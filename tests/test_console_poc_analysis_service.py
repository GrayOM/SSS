import unittest

from app.models.schemas import FileContent
from app.services.console_poc_analysis_service import (
    MockConsolePocAnalyzer,
    _extract_endpoint,
    _auth_bypass_severity,
    analyze_console_exploitability,
    select_console_relevant_files,
)


def f(path, content):
    return FileContent(path=path, extension='.js', size=len(content), priority=1, reason_code='INCLUDED', content_hash='h', content=content)


class ConsolePocAnalysisTests(unittest.TestCase):
    def test_auth_bypass_severity_navigate_only_is_low(self):
        self.assertEqual(_auth_bypass_severity("if (role==='ADMIN'){navigate('/admin')}"), 'low')

    def test_auth_bypass_severity_requireauth_is_high(self):
        self.assertEqual(_auth_bypass_severity("requireAuth(user); navigate('/admin')"), 'high')

    def test_auth_bypass_severity_fetch_or_axios_is_high(self):
        self.assertEqual(_auth_bypass_severity("navigate('/admin'); fetch('/api/me')"), 'high')
        self.assertEqual(_auth_bypass_severity("navigate('/admin'); axios.post('/api/me')"), 'high')
    def test_select_relevant_files_case_insensitive_content(self):
        selected = select_console_relevant_files([f('src/a.js', 'const Role = "ADMIN"; const x = LocalStorage.getItem("u")')])
        self.assertEqual(len(selected), 1)

    def test_requireauth_without_storage_generates_no_poc_code(self):
        files = [f('src/AdminMypage.js', "if(Role==='ADMIN'){Navigate('/admin')} requireAuth(user); import { requireAuth } from '../utils/sessionUtils';")]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        auth = [x for x in result.findings if x.vulnerability_type == 'Client-side Authorization Bypass'][0]
        self.assertIsNone(auth.console_poc.code)
        self.assertIn('requireAuth/checkSession 구현 파일 확인이 필요합니다.', auth.verification_notes)
        self.assertIn('sessionStorage/localStorage 조작 PoC는 현재 코드 근거로 검증되지 않았습니다.', auth.verification_notes)
        self.assertEqual(auth.confidence, 'low')
        self.assertIn('추가 확인 필요', auth.summary)

    def test_requireauth_userinfo_admin_without_dependency_file_has_no_poc_code(self):
        files = [f('src/AdminPage.js', "const userInfo = requireAuth(); if (userInfo.userType === 'ADMIN') { navigate('/admin') } import { requireAuth } from '../utils/sessionUtils';")]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        auth = [x for x in result.findings if x.vulnerability_type == 'Client-side Authorization Bypass'][0]
        self.assertIsNone(auth.console_poc.code)
        self.assertIn('sessionStorage/localStorage 조작 PoC는 현재 코드 근거로 검증되지 않았습니다.', auth.verification_notes)
        self.assertIn("userInfo.userType === 'ADMIN'", auth.evidence[0].snippet)

    def test_storage_evidence_generates_poc_code(self):
        files = [f('src/AdminMypage.js', "const user = JSON.parse(sessionStorage.getItem('user')); if (user?.userType === 'ADMIN') { navigate('/admin') }")]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        auth = [x for x in result.findings if x.vulnerability_type == 'Client-side Authorization Bypass'][0]
        self.assertIsNotNone(auth.console_poc.code)
        self.assertIn("sessionStorage.getItem('user')", auth.evidence[0].snippet)

    def test_header_like_routing_only_not_high_confidence(self):
        files = [f('src/Header.js', "if (userType==='ADMIN'){navigate('/admin-mypage')}")]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        auth = [x for x in result.findings if x.vulnerability_type == 'Client-side Authorization Bypass'][0]
        self.assertEqual(auth.severity, 'low')
        self.assertNotEqual(auth.confidence, 'high')

    def test_validation_bypass_has_endpoint_parameter_data_flow(self):
        files = [f('src/pay.js', "const payload={amount:100,status:'P'}; axios.post('/api/order', payload)")]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        finding = [x for x in result.findings if x.vulnerability_type == 'Client-side Validation Bypass'][0]
        flow = finding.evidence[0].data_flow
        self.assertTrue(any(x.startswith('parameter: amount') for x in flow))
        self.assertTrue(any(x.startswith('endpoint: /api/order') for x in flow))

    def test_extract_endpoint_supports_template_literal(self):
        ep = _extract_endpoint("axios.post(`${apiBase}/api/user/${sessionData.userId}/wallet/charge`, payload)")
        self.assertEqual(ep, '/api/user/{sessionData.userId}/wallet/charge')

    def test_validation_finds_template_literal_endpoint_in_data_flow(self):
        files = [f('src/wallet.js', "const payload={amount,userId}; axios.post(`${apiBase}/api/user/${sessionData.userId}/wallet/charge`, payload)")]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        finding = [x for x in result.findings if x.vulnerability_type == 'Client-side Validation Bypass'][0]
        self.assertIn('endpoint: /api/user/{sessionData.userId}/wallet/charge', finding.evidence[0].data_flow)

    def test_validation_endpoints_are_not_deduped_together(self):
        content = (
            "axios.post(`${apiBase}/api/auction/${item.id}/bid`, payload);"
            "fetch(`${apiBase}/api/order/${orderId}/complete-payment`, {method:'POST'});"
            "const amount=1; const orderId='x';"
        )
        files = [f('src/pay.js', content)]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        findings = [x for x in result.findings if x.vulnerability_type == 'Client-side Validation Bypass']
        endpoints = sorted([
            next((flow.replace('endpoint: ', '') for flow in finding.evidence[0].data_flow if flow.startswith('endpoint: ')), '')
            for finding in findings
        ])
        self.assertIn('/api/auction/{item.id}/bid', endpoints)
        self.assertIn('/api/order/{orderId}/complete-payment', endpoints)
        self.assertEqual(len(findings), 2)

    def test_dedup_merges_affected_files(self):
        files = [
            f('src/a.js', "const u=sessionStorage.getItem('user'); if(role==='ADMIN'){navigate('/admin')}"),
            f('src/b.js', "const u=sessionStorage.getItem('user'); if(role==='ADMIN'){navigate('/admin')}"),
        ]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        auth = [x for x in result.findings if x.vulnerability_type == 'Client-side Authorization Bypass'][0]
        self.assertGreaterEqual(len(auth.affected_files), 2)


if __name__ == '__main__':
    unittest.main()
