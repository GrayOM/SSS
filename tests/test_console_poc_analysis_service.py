import unittest

from app.models.schemas import FileContent
from app.services.console_poc_analysis_service import (
    MockConsolePocAnalyzer,
    _is_allowed_guarded_poc_code,
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
        finding = [x for x in result.findings if x.vulnerability_type in {'Client-side Validation Bypass', 'State/Status Manipulation Candidate', 'Payment/Point Manipulation Candidate'}][0]
        flow = finding.evidence[0].data_flow
        self.assertTrue(any(x.startswith('parameter: amount') for x in flow))
        self.assertTrue(any(x.startswith('endpoint: /api/order') for x in flow))

    def test_extract_endpoint_supports_template_literal(self):
        ep = _extract_endpoint("axios.post(`${apiBase}/api/user/${sessionData.userId}/wallet/charge`, payload)")
        self.assertEqual(ep, '/api/user/{sessionData.userId}/wallet/charge')

    def test_validation_finds_template_literal_endpoint_in_data_flow(self):
        files = [f('src/wallet.js', "const payload={amount,userId}; axios.post(`${apiBase}/api/user/${sessionData.userId}/wallet/charge`, payload)")]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        finding = [x for x in result.findings if x.vulnerability_type == 'Payment/Point Manipulation Candidate'][0]
        self.assertIn('endpoint: /api/user/{sessionData.userId}/wallet/charge', finding.evidence[0].data_flow)
        self.assertIn('axios.post', finding.evidence[0].snippet)
        self.assertNotIn('import React', finding.evidence[0].snippet)

    def test_validation_endpoints_are_not_deduped_together(self):
        content = (
            "axios.post(`${apiBase}/api/auction/${item.id}/bid`, payload);"
            "fetch(`${apiBase}/api/order/${orderId}/complete-payment`, {method:'POST'});"
            "const amount=1; const orderId='x';"
        )
        files = [f('src/pay.js', content)]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        findings = [
            x for x in result.findings if x.vulnerability_type in {
                'Client-side Validation Bypass',
                'Payment/Point Manipulation Candidate',
                'Generic API Review Candidate',
                'State/Status Manipulation Candidate',
            }
        ]
        endpoints = sorted([
            next((flow.replace('endpoint: ', '') for flow in finding.evidence[0].data_flow if flow.startswith('endpoint: ')), '')
            for finding in findings
        ])
        self.assertIn('/api/auction/{item.id}/bid', endpoints)
        self.assertIn('/api/order/{orderId}/complete-payment', endpoints)
        self.assertEqual(len(findings), 2)

    def test_different_payment_endpoints_not_deduped(self):
        files = [f('src/pay.js', "axios.post('/api/a/charge', { amount }); axios.post('/api/b/charge', { amount });")]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        findings = [x for x in result.findings if x.vulnerability_type == 'Payment/Point Manipulation Candidate']
        self.assertEqual(len(findings), 2)

    def test_different_endpoint_ids_are_unique(self):
        files = [f('src/pay.js', "axios.post('/api/a/charge', { amount }); axios.post('/api/b/charge', { amount });")]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        findings = [x for x in result.findings if x.vulnerability_type == 'Payment/Point Manipulation Candidate']
        self.assertNotEqual(findings[0].id, findings[1].id)

    def test_get_endpoint_allows_safe_console_poc(self):
        files = [f('src/get.js', "fetch('/api/user/session')")]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        finding = [x for x in result.findings if x.vulnerability_type == 'Generic API Review Candidate'][0]
        self.assertEqual(finding.console_poc.poc_type, 'browser_console')
        self.assertIn("method: 'GET'", finding.console_poc.code or '')
        self.assertIn("credentials: 'include'", finding.console_poc.code or '')

    def test_unknown_endpoint_is_low_with_verification_note(self):
        files = [f('src/x.js', "const endpoint = API_ENDPOINTS.CHARGE_POINT; apiClient.post(endpoint, payload); const amount=1;")]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        finding = [x for x in result.findings if x.vulnerability_type in {'Client-side Validation Bypass', 'Payment/Point Manipulation Candidate'}][0]
        self.assertEqual(finding.confidence, 'low')
        self.assertIn('endpoint variable requires manual review', finding.verification_notes)

    def test_no_api_candidate_no_validation_finding(self):
        files = [f('src/plain.js', "const x = 1; const y = x + 2;")]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        types = [x.vulnerability_type for x in result.findings]
        self.assertNotIn('Client-side Validation Bypass', types)
        self.assertNotIn('Generic API Review Candidate', types)

    def test_idor_candidate_classification(self):
        files = [f('src/order.js', "fetch('/api/order/by-product/${productId}/user/${userId}')")]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        finding = [x for x in result.findings if x.vulnerability_type == 'IDOR / Unauthorized Data Access Candidate'][0]
        self.assertIn('식별자 기반 조회 요청의 접근 제어 확인 필요', finding.title)

    def test_account_recovery_candidate_classification(self):
        files = [f('src/reset.js', "axios.post('/api/user/reset-password', { email, verificationCode })")]
        findings = MockConsolePocAnalyzer().analyze(files)
        finding = [x for x in findings if x.vulnerability_type == 'Account Recovery Flow Abuse Candidate'][0]
        self.assertIsNotNone(finding.console_poc.code)
        self.assertIn('CONFIRM_AUTHORIZED_TEST = false', finding.console_poc.code or '')

    def test_post_request_generates_guarded_poc(self):
        files = [f('src/post.js', "axios.post('/api/pay', { amount, orderId, userId })")]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        finding = [x for x in result.findings if x.vulnerability_type == 'Payment/Point Manipulation Candidate'][0]
        self.assertIsNotNone(finding.console_poc.code)
        self.assertEqual(finding.console_poc.poc_type, 'browser_console')
        self.assertIn('CONFIRM_AUTHORIZED_TEST = false', finding.console_poc.code or '')
        self.assertIn('fetch(endpoint', finding.console_poc.code or '')
        self.assertIn("'orderId': 'TEST_ORDER_ID'", finding.console_poc.code or '')
        self.assertIn("'userId': 'TEST_USER_ID'", finding.console_poc.code or '')
        self.assertIn("'amount': 1", finding.console_poc.code or '')
        self.assertIn('Guarded PoC: CONFIRM_AUTHORIZED_TEST 값을 true로 변경해야 실행됩니다.', finding.verification_notes)

    def test_get_endpoint_has_executable_readonly_poc(self):
        files = [f('src/get2.js', "fetch('/api/user/session')")]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        finding = [x for x in result.findings if x.vulnerability_type == 'Generic API Review Candidate'][0]
        self.assertIsNotNone(finding.console_poc.code)
        self.assertIn("method: 'GET'", finding.console_poc.code or '')
        self.assertIn("credentials: 'include'", finding.console_poc.code or '')

    def test_complete_payment_and_charge_are_guarded_not_blocked(self):
        files = [
            f('src/pay1.js', "axios.post('/api/order/{orderId}/complete-payment', { orderId, totalAmount, usePoints })"),
            f('src/pay2.js', "axios.post('/api/user/{sessionData.userId}/wallet/charge', { amount, userId })"),
        ]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        pocs = [x.console_poc.code or '' for x in result.findings if 'Manipulation Candidate' in x.vulnerability_type]
        self.assertTrue(any('CONFIRM_AUTHORIZED_TEST = false' in c for c in pocs))

    def test_delete_endpoint_manual_check_with_reason(self):
        files = [f('src/del.js', "axios.delete('/api/admin/delete-user/{userId}')")]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        finding = [x for x in result.findings if x.vulnerability_type in {'State/Status Manipulation Candidate', 'Client-side Validation Bypass', 'Generic API Review Candidate'}][0]
        self.assertIsNone(finding.console_poc.code)
        self.assertTrue(any('비가역/고위험 요청은 실행형 Console PoC를 생성하지 않았습니다.' in n for n in finding.verification_notes))

    def test_guarded_post_code_allowed_by_filter(self):
        code = "(async()=>{const CONFIRM_AUTHORIZED_TEST = false; if (!CONFIRM_AUTHORIZED_TEST) { throw new Error('x'); } const res = await fetch('/api/x',{method:'POST'});})();"
        self.assertTrue(_is_allowed_guarded_poc_code(code))

    def test_post_without_guard_rejected_by_filter(self):
        code = "fetch('/api/x',{method:'POST'})"
        self.assertFalse(_is_allowed_guarded_poc_code(code))

    def test_delete_fetch_rejected_by_filter(self):
        code = "fetch('/api/x',{method:'DELETE'})"
        self.assertFalse(_is_allowed_guarded_poc_code(code))

    def test_guarded_complete_payment_post_allowed(self):
        code = """(async () => {
  const CONFIRM_AUTHORIZED_TEST = false;
  if (!CONFIRM_AUTHORIZED_TEST) { throw new Error('x'); }
  await fetch('/api/order/TEST_ORDER_ID/complete-payment', { method: 'POST' });
})();"""
        self.assertTrue(_is_allowed_guarded_poc_code(code))

    def test_guarded_pay_endpoint_post_allowed(self):
        code = """(async () => {
  const CONFIRM_AUTHORIZED_TEST = false;
  if (!CONFIRM_AUTHORIZED_TEST) { throw new Error('x'); }
  await fetch('/api/pay', { method: 'POST' });
})();"""
        self.assertTrue(_is_allowed_guarded_poc_code(code))

    def test_guarded_payment_method_parameter_allowed(self):
        code = """(async () => {
  const CONFIRM_AUTHORIZED_TEST = false;
  if (!CONFIRM_AUTHORIZED_TEST) { throw new Error('x'); }
  const payload = { paymentMethod: 'POINTS' };
  await fetch('/api/order/pay', { method: 'POST', body: JSON.stringify(payload) });
})();"""
        self.assertTrue(_is_allowed_guarded_poc_code(code))

    def test_refund_endpoint_rejected(self):
        code = """(async () => {
  const CONFIRM_AUTHORIZED_TEST = false;
  if (!CONFIRM_AUTHORIZED_TEST) { throw new Error('x'); }
  await fetch('/api/order/refund', { method: 'POST' });
})();"""
        self.assertFalse(_is_allowed_guarded_poc_code(code))

    def test_transfer_endpoint_rejected(self):
        code = """(async () => {
  const CONFIRM_AUTHORIZED_TEST = false;
  if (!CONFIRM_AUTHORIZED_TEST) { throw new Error('x'); }
  await fetch('/api/wallet/transfer', { method: 'POST' });
})();"""
        self.assertFalse(_is_allowed_guarded_poc_code(code))

    def test_guard_variable_without_if_guard_rejected(self):
        code = """(async () => {
  const CONFIRM_AUTHORIZED_TEST = false;
  await fetch('/api/pay', { method: 'POST' });
})();"""
        self.assertFalse(_is_allowed_guarded_poc_code(code))

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
