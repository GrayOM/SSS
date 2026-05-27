import unittest

from app.models.schemas import FileContent
from app.services.console_poc_analysis_service import (
    GeminiConsolePocAnalyzer,
    MockConsolePocAnalyzer,
    _build_network_hook_mutation_poc,
    _is_allowed_guarded_poc_code,
    _extract_endpoint,
    _auth_bypass_severity,
    analyze_console_exploitability,
    select_console_relevant_files,
    get_console_poc_analyzer,
)


def f(path, content):
    return FileContent(path=path, extension='.js', size=len(content), priority=1, reason_code='INCLUDED', content_hash='h', content=content)


class ConsolePocAnalysisTests(unittest.TestCase):

    def test_build_artifact_dom_xss_not_generated(self):
        files = [f('src/app-bd3d900226fb938894f0.js', 'self.webpackChunkgatsby=[]; el.innerHTML=location.hash;')]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        self.assertFalse(any(x.vulnerability_type == 'DOM XSS' for x in result.findings))

    def test_build_artifact_api_candidate_not_generated(self):
        files = [f('src/framework-481beeb6bc5ccc2a4757.js', "fetch('/api/user/session')")]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        self.assertFalse(any(x.vulnerability_type == 'Generic API Review Candidate' for x in result.findings))

    def test_application_js_api_candidate_kept(self):
        files = [f('src/application.js', "fetch('/api/user/session')")]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        self.assertTrue(any(x.vulnerability_type == 'Generic API Review Candidate' for x in result.findings))
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
        self.assertIn('fetch hook installed', auth.console_poc.code or '')
        self.assertIn("window.fetch = async function(input, init = {}) {", auth.console_poc.code or '')
        self.assertIn('return originalFetch.call(this, input, init);', auth.console_poc.code or '')
        self.assertNotIn('...args', auth.console_poc.code or '')
        self.assertNotIn('.args', auth.console_poc.code or '')
        self.assertNotIn('originalFetch(...args)', auth.console_poc.code or '')
        self.assertNotIn('originalFetch(.args)', auth.console_poc.code or '')
        self.assertIn('requireAuth/checkSession 구현 파일 확인이 필요합니다.', auth.verification_notes)
        self.assertIn('sessionStorage/localStorage 조작 PoC는 현재 코드 근거로 검증되지 않았습니다.', auth.verification_notes)
        self.assertEqual(auth.confidence, 'low')
        self.assertIn('추가 확인 필요', auth.summary)

    def test_auth_fetch_hook_regression_no_spread_args(self):
        files = [f('src/AuthPage.js', "if (userInfo.userType !== 'ADMIN') { navigate('/'); } requireAuth(user);")]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        auth = [x for x in result.findings if x.vulnerability_type == 'Client-side Authorization Bypass'][0]
        code = auth.console_poc.code or ''
        self.assertNotIn('.args', code)
        self.assertNotIn('...args', code)
        self.assertIn('originalFetch.call(this, input, init)', code)

    def test_requireauth_userinfo_admin_without_dependency_file_has_no_poc_code(self):
        files = [f('src/AdminPage.js', "const userInfo = requireAuth(); if (userInfo.userType === 'ADMIN') { navigate('/admin') } import { requireAuth } from '../utils/sessionUtils';")]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        auth = [x for x in result.findings if x.vulnerability_type == 'Client-side Authorization Bypass'][0]
        self.assertIn('fetch hook installed', auth.console_poc.code or '')
        self.assertIn('sessionStorage/localStorage 조작 PoC는 현재 코드 근거로 검증되지 않았습니다.', auth.verification_notes)
        self.assertIn("userInfo.userType === 'ADMIN'", auth.evidence[0].snippet)

    def test_auth_evidence_excludes_requireauth_import_line(self):
        files = [f('src/AdminPage.js', "import { requireAuth } from '../utils/sessionUtils';\nconst userInfo = requireAuth();\nif (userInfo.userType === 'ADMIN') { navigate('/admin'); }")]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        auth = [x for x in result.findings if x.vulnerability_type == 'Client-side Authorization Bypass'][0]
        self.assertNotIn("import { requireAuth }", auth.evidence[0].snippet)
        self.assertIn("userInfo.userType === 'ADMIN'", auth.evidence[0].snippet)

    def test_auth_evidence_keeps_requireauth_call_and_admin_branch_together(self):
        files = [f('src/AdminPage.js', "const userInfo = requireAuth();\nconst x = 1;\nif (userInfo.userType === 'ADMIN') {\n  navigate('/admin');\n}")]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        auth = [x for x in result.findings if x.vulnerability_type == 'Client-side Authorization Bypass'][0]
        self.assertIn("const userInfo = requireAuth();", auth.evidence[0].snippet)
        self.assertIn("if (userInfo.userType === 'ADMIN')", auth.evidence[0].snippet)

    def test_auth_evidence_excludes_checkauthstatus_import_line(self):
        files = [f('src/Header.js', "import { checkAuthStatus } from '../utils/auth';\nconst role = userInfo.role;\nif (role === 'NAFAL') { navigate('/admin'); }\ncheckAuthStatus();")]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        auth = [x for x in result.findings if x.vulnerability_type == 'Client-side Authorization Bypass'][0]
        self.assertNotIn("import { checkAuthStatus }", auth.evidence[0].snippet)
        self.assertIn("if (role === 'NAFAL')", auth.evidence[0].snippet)

    def test_auth_evidence_skips_role_badge_presentation_code(self):
        files = [f('src/Header.js', "function getRoleBadgeColor(role) {\n  switch (role) {\n    case 'ADMIN': return 'var(--red)';\n    case 'NAFAL': return 'var(--blue)';\n    default: return 'var(--gray)';\n  }\n}\nif (userInfo.userType !== 'ADMIN') { navigate('/'); }")]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        auth = [x for x in result.findings if x.vulnerability_type == 'Client-side Authorization Bypass'][0]
        self.assertNotIn('getRoleBadgeColor', auth.evidence[0].snippet)
        self.assertIn("userInfo.userType !== 'ADMIN'", auth.evidence[0].snippet)

    def test_auth_evidence_skips_notification_display_code(self):
        files = [f('src/Header.js', "function shouldShowNotification(notification, userInfo) {\n  const notificationRole = notification.role;\n  return notificationRole === userInfo.role;\n}\nif (userInfo.userType !== 'ADMIN') { navigate('/'); }")]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        auth = [x for x in result.findings if x.vulnerability_type == 'Client-side Authorization Bypass'][0]
        self.assertNotIn('shouldShowNotification', auth.evidence[0].snippet)
        self.assertIn("userInfo.userType !== 'ADMIN'", auth.evidence[0].snippet)

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
        self.assertIsNotNone(finding.verification_playbook)
        self.assertIn('API 호출 직전', finding.verification_playbook.breakpoints[0].reason)
        self.assertIn('amount', finding.verification_playbook.breakpoints[0].watch_variables)

    def test_dom_xss_requires_source_sink_flow(self):
        files = [f('src/x.js', "const testElement = document.createElement('div'); testElement.innerHTML = '';")]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        self.assertFalse(any(x.vulnerability_type == 'DOM XSS' for x in result.findings))

    def test_dom_xss_static_innerhtml_not_reported(self):
        files = [f('src/x.js', 'el.innerHTML = "<span>static</span>";')]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        self.assertFalse(any(x.vulnerability_type == 'DOM XSS' for x in result.findings))

    def test_get_session_no_global_parameter_fallback(self):
        files = [f('src/mix.js', "const amount=1; const orderId='x'; fetch('/api/user/session')")]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        finding = [x for x in result.findings if x.vulnerability_type == 'Generic API Review Candidate'][0]
        flow = finding.evidence[0].data_flow
        self.assertFalse(any(p.startswith('parameter: amount') for p in flow))
        self.assertFalse(any(p.startswith('parameter: orderId') for p in flow))

    def test_generic_ajax_wrapper_not_promoted(self):
        files = [f('src/ajax.js', "$.ajax({ url: url, type: 'POST', data: data, success: ()=>{} })")]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        self.assertFalse(any(x.vulnerability_type in {'Client-side Validation Bypass', 'Payment/Point Manipulation Candidate'} for x in result.findings))

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
        self.assertIn('[SSS PoC] 설치 완료', finding.console_poc.code or '')

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

    def test_generic_get_auction_is_not_promoted(self):
        files = [f('src/a.js', "fetch('/api/auction/product/1')")]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        self.assertFalse(any(x.vulnerability_type == 'Generic API Review Candidate' for x in result.findings))

    def test_idor_candidate_classification(self):
        files = [f('src/order.js', "fetch('/api/order/by-product/${productId}/user/${userId}')")]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        finding = [x for x in result.findings if x.vulnerability_type == 'IDOR / Unauthorized Data Access Candidate'][0]
        self.assertIn('식별자 기반 조회 요청의 접근 제어 확인 필요', finding.title)

    def test_user_session_get_is_kept(self):
        files = [f('src/s.js', "fetch('/api/user/session')")]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        self.assertTrue(any(x.vulnerability_type == 'Generic API Review Candidate' for x in result.findings))

    def test_api_base_verify_code_does_not_use_test_value_endpoint(self):
        files = [f('src/v.js', "axios.post('{API_BASE}/verify-code', { code })")]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        findings = [x for x in result.findings if 'Candidate' in x.vulnerability_type]
        if findings:
            finding = findings[0]
            self.assertNotIn('TEST_VALUE/verify-code', finding.console_poc.code or '')
            self.assertIn('{API_BASE}/verify-code', finding.console_poc.code or '')
            self.assertTrue(any('API_BASE 값을 실제 대상 URL로 변경해야 합니다.' in n for n in finding.verification_notes) or finding.console_poc.code is None)

    def test_api_base_get_endpoint_uses_placeholder_base(self):
        files = [f('src/vget.js', "fetch('{API_BASE}/user/session')")]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        finding = [x for x in result.findings if x.vulnerability_type == 'Generic API Review Candidate'][0]
        self.assertIn('{API_BASE}/user/session', finding.console_poc.code or '')

    def test_api_base_path_variable_is_replaced_in_poc(self):
        files = [f('src/vpath.js', "axios.post('{API_BASE}/api/user/{userId}/wallet', { amount })")]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        finding = [x for x in result.findings if 'Candidate' in x.vulnerability_type][0]
        self.assertNotIn('TEST_VALUE/wallet', finding.console_poc.code or '')
        self.assertIn('{API_BASE}/api/user/{userId}/wallet', finding.console_poc.code or '')

    def test_auth_missing_dependency_uses_fetch_hook_poc(self):
        files = [f('src/AdminMypage.js', "if(Role==='ADMIN'){Navigate('/admin')} requireAuth(user); import { requireAuth } from '../utils/sessionUtils';")]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        auth = [x for x in result.findings if x.vulnerability_type == 'Client-side Authorization Bypass'][0]
        self.assertIn('fetch hook installed', auth.console_poc.code or '')



    def test_gemini_analyzer_filters_build_artifact_files_from_prompt(self):
        class FakeGeminiClient:
            model = 'fake-gemini'

            def __init__(self):
                self.prompt = None

            def analyze(self, prompt: str) -> str:
                self.prompt = prompt
                return '{"findings": []}'

        files = [
            f('src/app-bd3d900226fb938894f0.js', "self.webpackChunkgatsby=[]; fetch('/api/user/session')"),
            f('src/application.js', "fetch('/api/user/session')"),
        ]
        fake_client = FakeGeminiClient()
        analyzer = GeminiConsolePocAnalyzer(fake_client)
        analyzer.analyze(files)

        self.assertIsNotNone(fake_client.prompt)
        self.assertNotIn('app-bd3d900226fb938894f0.js', fake_client.prompt)
        self.assertNotIn('self.webpackChunkgatsby', fake_client.prompt)
        self.assertIn('application.js', fake_client.prompt)
        self.assertIn('/api/user/session', fake_client.prompt)
        self.assertEqual(analyzer.last_debug.backend, 'gemini')
        self.assertTrue(analyzer.last_debug.called)

    def test_gemini_filters_build_artifact_from_prompt_but_keeps_application_js(self):
        class FakeGeminiClient:
            def __init__(self):
                self.last_prompt = ''
            def analyze(self, prompt: str) -> str:
                self.last_prompt = prompt
                return '{"findings":[]}'
        client = FakeGeminiClient()
        analyzer = GeminiConsolePocAnalyzer(client)
        analyzer.analyze([
            f('src/app-bd3d900226fb938894f0.js', "self.webpackChunkgatsby=[]; fetch('/api/user/session')"),
            f('src/application.js', "fetch('/api/user/session')"),
        ])
        self.assertNotIn('app-bd3d900226fb938894f0.js', client.last_prompt)
        self.assertNotIn('self.webpackChunkgatsby', client.last_prompt)
        self.assertIn('application.js', client.last_prompt)
        self.assertIn('/api/user/session', client.last_prompt)
        self.assertEqual(analyzer.last_debug.backend, 'gemini')
        self.assertTrue(analyzer.last_debug.called)
        self.assertEqual(analyzer.last_debug.candidate_count, 1)



    def test_get_console_poc_analyzer_unsupported_backend_raises(self):
        from app.services import console_poc_analysis_service as svc
        original_backend = svc.settings.ANALYZER_BACKEND
        try:
            svc.settings.ANALYZER_BACKEND = 'openai'
            with self.assertRaises(ValueError) as cm:
                get_console_poc_analyzer()
            self.assertIn('Unsupported readable analysis backend', str(cm.exception))
        finally:
            svc.settings.ANALYZER_BACKEND = original_backend
    def test_gemini_missing_id_is_auto_generated(self):
        class FakeGeminiClient:
            def analyze(self, prompt: str) -> str:
                return """{"findings":[{"title":"t","vulnerability_type":"Generic API Review Candidate","severity":"medium","confidence":"medium","affected_files":["src/a.js"],"summary":"s","evidence":[{"source_path":"src/a.js","start_line":1,"end_line":1,"snippet":"fetch('/api/user/session')","reason":"r","data_flow":["source -> state/storage -> sink"]}],"console_poc":{"poc_type":"manual_check","description":"d","preconditions":[],"steps":[],"code":null,"expected_result":"e","safety":"safe"},"attack_scenario":["x"],"impact":"i","root_cause":"c","remediation":"m","verification_notes":[]}]}"""
        analyzer = GeminiConsolePocAnalyzer(FakeGeminiClient())
        findings = analyzer.analyze([f('src/a.js', "fetch('/api/user/session')")])
        self.assertEqual(len(findings), 1)
        self.assertTrue(findings[0].id)
        self.assertEqual(analyzer.last_debug.backend, 'gemini')
        self.assertEqual(analyzer.last_debug.scope, 'readable_analysis')
        self.assertTrue(analyzer.last_debug.called)
        self.assertEqual(analyzer.last_debug.raw_item_count, 1)
        self.assertEqual(analyzer.last_debug.accepted_item_count, 1)
        self.assertEqual(analyzer.last_debug.dropped_item_count, 0)

    def test_gemini_dangerous_poc_code_removed_but_id_kept(self):
        class FakeGeminiClient:
            def analyze(self, prompt: str) -> str:
                return """{"findings":[{"title":"t","vulnerability_type":"Payment/Point Manipulation Candidate","severity":"high","confidence":"medium","affected_files":["src/a.js"],"summary":"s","evidence":[{"source_path":"src/a.js","start_line":1,"end_line":1,"snippet":"axios.post('/api/pay')","reason":"r","data_flow":["source -> state/storage -> sink"]}],"console_poc":{"poc_type":"browser_console","description":"d","preconditions":[],"steps":[],"code":"fetch('/api/x',{method:'DELETE'})","expected_result":"e","safety":"safe"},"attack_scenario":["x"],"impact":"i","root_cause":"c","remediation":"m","verification_notes":[]}]}"""
        analyzer = GeminiConsolePocAnalyzer(FakeGeminiClient())
        findings = analyzer.analyze([f('src/a.js', "axios.post('/api/pay',{amount:1})")])
        self.assertEqual(len(findings), 1)
        self.assertTrue(findings[0].id)
        self.assertIsNone(findings[0].console_poc.code)
        self.assertEqual(analyzer.last_debug.accepted_item_count, 1)

    def test_gemini_malformed_item_does_not_break_all(self):
        class FakeGeminiClient:
            def analyze(self, prompt: str) -> str:
                return """{"findings":[{"title":"bad","vulnerability_type":"Generic API Review Candidate","severity":"medium","confidence":"medium","affected_files":["src/a.js"],"summary":"s","evidence":[],"console_poc":{"poc_type":"manual_check","description":"d","preconditions":[],"steps":[],"code":null,"expected_result":"e","safety":"safe"},"attack_scenario":["x"],"impact":"i","root_cause":"c","remediation":"m","verification_notes":[]},{"title":"ok","vulnerability_type":"Generic API Review Candidate","severity":"medium","confidence":"medium","affected_files":["src/a.js"],"summary":"s","evidence":[{"source_path":"src/a.js","start_line":1,"end_line":1,"snippet":"fetch('/api/user/session')","reason":"r","data_flow":["source -> state/storage -> sink"]}],"console_poc":{"poc_type":"manual_check","description":"d","preconditions":[],"steps":[],"code":null,"expected_result":"e","safety":"safe"},"attack_scenario":["x"],"impact":"i","root_cause":"c","remediation":"m","verification_notes":[]}]}"""
        analyzer = GeminiConsolePocAnalyzer(FakeGeminiClient())
        findings = analyzer.analyze([f('src/a.js', "fetch('/api/user/session')")])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].title, 'ok')
        self.assertEqual(analyzer.last_debug.accepted_item_count, 1)
        self.assertEqual(analyzer.last_debug.dropped_item_count, 1)
        self.assertIn(analyzer.last_debug.drop_reasons[0].stage, {'shape', 'validation'})

    def test_gemini_invalid_json_records_parse_error(self):
        class FakeGeminiClient:
            def analyze(self, prompt: str) -> str:
                return "not-json"
        analyzer = GeminiConsolePocAnalyzer(FakeGeminiClient())
        findings = analyzer.analyze([f('src/a.js', "fetch('/api/user/session')")])
        self.assertEqual(findings, [])
        self.assertTrue(analyzer.last_debug.called)
        self.assertTrue(any('parse failed' in e for e in analyzer.last_debug.errors))

    def test_account_recovery_candidate_classification(self):
        files = [f('src/reset.js', "axios.post('/api/user/reset-password', { email, verificationCode })")]
        findings = MockConsolePocAnalyzer().analyze(files)
        finding = [x for x in findings if x.vulnerability_type == 'Account Recovery Flow Abuse Candidate'][0]
        self.assertIsNotNone(finding.console_poc.code)
        self.assertIn('window.SSS_POC.armMutation()', finding.console_poc.code or '')
        self.assertIsNotNone(finding.verification_playbook)

    def test_disabled_button_only_generates_playbook_console_code(self):
        files = [f('src/pay.js', "<button disabled={amount <= 0} onClick={handlePay}>Pay</button>")]
        findings = MockConsolePocAnalyzer().analyze(files)
        self.assertEqual(len([x for x in findings if x.verification_playbook and x.verification_playbook.strategy == 'disabled_button_bypass']), 0)

    def test_disabled_loading_only_does_not_create_disabled_finding(self):
        files = [f('src/x.js', "<button disabled={loading}>Pay</button>")]
        findings = MockConsolePocAnalyzer().analyze(files)
        self.assertFalse(any(x.verification_playbook and x.verification_playbook.strategy == 'disabled_button_bypass' for x in findings))

    def test_disabled_with_handler_and_api_creates_playbook(self):
        files = [f('src/pay.js', "const handlePay=()=>{axios.post('/api/pay',{ amount })}; <button disabled={amount <= 0} onClick={handlePay}>Pay</button>")]
        findings = MockConsolePocAnalyzer().analyze(files)
        self.assertTrue(any(x.verification_playbook and x.verification_playbook.strategy == 'disabled_button_bypass' for x in findings))

    def test_auth_guard_playbook_contains_role_watch_variables(self):
        files = [f('src/auth.js', "if (userInfo.userType !== 'ADMIN') { navigate('/'); }")]
        findings = MockConsolePocAnalyzer().analyze(files)
        auth = [x for x in findings if x.vulnerability_type == 'Client-side Authorization Bypass'][0]
        self.assertIsNotNone(auth.verification_playbook)
        self.assertIn('userInfo', auth.verification_playbook.breakpoints[0].watch_variables)
        self.assertIn('userType', auth.verification_playbook.breakpoints[0].watch_variables)

    def test_validation_return_breakpoint_is_included(self):
        files = [f('src/verify.js', "function handleVerify(){ if (!code) return; axios.post('/verify-code', { code }); }")]
        findings = MockConsolePocAnalyzer().analyze(files)
        rec = [x for x in findings if x.vulnerability_type == 'Account Recovery Flow Abuse Candidate'][0]
        reasons = [b.reason for b in rec.verification_playbook.breakpoints]
        self.assertIn('클라이언트 검증 실패 분기 확인', reasons)
        self.assertIn('API 호출 직전 payload 변조 확인', reasons)
        all_watch = {w for bp in rec.verification_playbook.breakpoints for w in bp.watch_variables}
        self.assertIn('code', all_watch)

    def test_fetch_hook_endpoint_is_escaped(self):
        code = _build_network_hook_mutation_poc('/api/o"rder')
        self.assertIn('const TARGET_ENDPOINT = "/api/o\\"rder";', code)
        self.assertIn('XMLHttpRequest.prototype.open', code)
        self.assertIn('axios.interceptors.request.use', code)

    def test_xhr_hook_does_not_mutate_without_arm(self):
        code = _build_network_hook_mutation_poc('/api/pay')
        self.assertIn('if (SSS_POC_STATE.mutationArmed && !BLOCKED_REPLAY && parsed)', code)

    def test_xhr_hook_captures_method_url_body(self):
        code = _build_network_hook_mutation_poc('/api/pay')
        self.assertIn('__poc_method', code)
        self.assertIn('__poc_url', code)
        self.assertIn("transport: 'xhr'", code)
        self.assertIn('captured.push({', code)

    def test_unrelated_validation_line_not_included(self):
        pad = "\n".join([f"const x{i}=1;" for i in range(300)])
        content = f"{pad}\nfunction handlePay(){{ axios.post('/api/pay', {{ amount }}); }}\n" + "\n".join([f"const y{i}=2;" for i in range(450)]) + "\nif (!code) return;\n"
        files = [f('src/item.js', content)]
        findings = MockConsolePocAnalyzer().analyze(files)
        pay = [x for x in findings if x.vulnerability_type == 'Payment/Point Manipulation Candidate'][0]
        self.assertFalse(any(bp.reason == '클라이언트 검증 실패 분기 확인' and bp.start_line > 700 for bp in (pay.verification_playbook.breakpoints if pay.verification_playbook else [])))

    def test_verify_code_watch_variables_are_narrow(self):
        files = [f('src/verify.js', "function handleVerify(){ if (!code) return; axios.post('/verify-code', { code }); }")]
        findings = MockConsolePocAnalyzer().analyze(files)
        rec = [x for x in findings if x.vulnerability_type == 'Account Recovery Flow Abuse Candidate'][0]
        all_watch = sorted({w for bp in rec.verification_playbook.breakpoints for w in bp.watch_variables})
        self.assertIn('payload', all_watch)
        self.assertIn('code', all_watch)
        self.assertNotIn('amount', all_watch)

    def test_disabled_findings_are_not_deduped_across_files(self):
        files = [
            f('src/fileA.js', "const handlePay=()=>{axios.post('/api/a',{ amount })}; <button disabled={amount <= 0} onClick={handlePay}>Pay</button>"),
            f('src/fileB.js', "const handlePay=()=>{axios.post('/api/b',{ amount })}; <button disabled={amount <= 0} onClick={handlePay}>Pay</button>"),
        ]
        findings = MockConsolePocAnalyzer().analyze(files)
        disabled = [x for x in findings if x.verification_playbook and x.verification_playbook.strategy == 'disabled_button_bypass']
        self.assertEqual(len(disabled), 2)
        self.assertTrue(all(len(x.affected_files) == 1 for x in disabled))
        self.assertEqual(sorted([x.affected_files[0] for x in disabled]), ['src/fileA.js', 'src/fileB.js'])

    def test_location_href_without_source_sink_flow_not_reported(self):
        files = [f('src/safe.js', 'const x = window.location.href; el.innerHTML = safeValue;')]
        findings = MockConsolePocAnalyzer().analyze(files)
        self.assertFalse(any(x.vulnerability_type == 'DOM XSS' for x in findings))

    def test_location_hash_still_reports_dom_xss(self):
        files = [f('src/xss.js', 'const x = location.hash; el.innerHTML = x;')]
        findings = MockConsolePocAnalyzer().analyze(files)
        self.assertTrue(any(x.vulnerability_type == 'DOM XSS' for x in findings))

    def test_post_request_generates_guarded_poc(self):
        files = [f('src/post.js', "axios.post('/api/pay', { amount, orderId, userId })")]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        finding = [x for x in result.findings if x.vulnerability_type == 'Payment/Point Manipulation Candidate'][0]
        self.assertIsNotNone(finding.console_poc.code)
        self.assertEqual(finding.console_poc.poc_type, 'browser_console')
        self.assertIn('[SSS PoC] 설치 완료', finding.console_poc.code or '')
        self.assertIn('window.SSS_POC.armMutation()', finding.console_poc.code or '')
        self.assertIn('list() {', finding.console_poc.code or '')
        self.assertIn('window.fetch = async function', finding.console_poc.code or '')

    def test_get_endpoint_has_executable_readonly_poc(self):
        files = [f('src/get2.js', "fetch('/api/user/session')")]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        finding = [x for x in result.findings if x.vulnerability_type == 'Generic API Review Candidate'][0]
        self.assertIsNotNone(finding.console_poc.code)
        self.assertIn('[SSS PoC] 설치 완료', finding.console_poc.code or '')
        self.assertIn('API JSON이 아니라 HTML이 반환되었습니다', finding.console_poc.code or '')

    def test_complete_payment_and_charge_are_guarded_not_blocked(self):
        files = [
            f('src/pay1.js', "axios.post('/api/order/{orderId}/complete-payment', { orderId, totalAmount, usePoints })"),
            f('src/pay2.js', "axios.post('/api/user/{sessionData.userId}/wallet/charge', { amount, userId })"),
        ]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        pocs = [x.console_poc.code or '' for x in result.findings if 'Manipulation Candidate' in x.vulnerability_type]
        self.assertTrue(any('window.SSS_POC.armMutation()' in c for c in pocs))

    def test_delete_endpoint_manual_check_with_reason(self):
        files = [f('src/del.js', "axios.delete('/api/admin/delete-user/{userId}')")]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        finding = [x for x in result.findings if x.vulnerability_type in {'State/Status Manipulation Candidate', 'Client-side Validation Bypass', 'Generic API Review Candidate'}][0]
        self.assertIsNotNone(finding.console_poc.code)
        self.assertIn('replay blocked: high-risk endpoint', finding.console_poc.code or '')
        self.assertTrue(any('observe mode만 제공됩니다' in n for n in finding.verification_notes))

    def test_post_poc_steps_use_arm_mutation_not_confirm_flag(self):
        files = [f('src/post2.js', "axios.post('/api/pay', { amount })")]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        finding = [x for x in result.findings if x.vulnerability_type in {'Payment/Point Manipulation Candidate', 'Client-side Validation Bypass'}][0]
        pre = ' '.join(finding.console_poc.preconditions)
        steps = ' '.join(finding.console_poc.steps)
        notes = ' '.join(finding.verification_notes)
        self.assertNotIn('CONFIRM_AUTHORIZED_TEST', pre + steps + notes)
        self.assertIn('window.SSS_POC.armMutation()', pre + steps + notes)

    def test_axios_capture_has_transport_marker(self):
        code = _build_network_hook_mutation_poc('/api/pay')
        self.assertIn("transport: 'axios'", code)
        self.assertIn('axios replay unavailable', code)

    def test_sss_poc_hook_code_allowed_by_filter(self):
        code = _build_network_hook_mutation_poc('/api/pay')
        self.assertTrue(_is_allowed_guarded_poc_code(code))

    def test_high_risk_observer_hook_allowed_by_filter(self):
        code = _build_network_hook_mutation_poc('/api/admin/delete-user/{userId}')
        self.assertTrue(_is_allowed_guarded_poc_code(code))

    def test_direct_delete_still_rejected(self):
        self.assertFalse(_is_allowed_guarded_poc_code("fetch('/api/user/1', { method: 'DELETE' })"))

    def test_direct_axios_delete_still_rejected(self):
        self.assertFalse(_is_allowed_guarded_poc_code("axios.delete('/api/user/1')"))

    def test_unknown_endpoint_goes_review_not_playbook(self):
        files = [f('src/a.js', "const endpoint = API_ENDPOINTS.X; const amount = 1; apiClient.post(endpoint, { amount });")]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        self.assertEqual(len(result.verification_playbooks), 0)
        self.assertTrue(len(result.review_candidates) >= 1)
        self.assertTrue(any('endpoint가 UNKNOWN이라 자동 PoC를 생성하지 않았습니다.' in ' '.join(x.verification_notes) for x in result.review_candidates))

    def test_disabled_loading_is_review_candidate_not_playbook(self):
        files = [f('src/a.js', "<button disabled={loading}>Pay</button>")]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        self.assertEqual(len(result.verification_playbooks), 0)

    def test_page_and_action_hints_in_playbook(self):
        files = [f('src/PaymentPage.js', "function handlePayment(){axios.post('/api/order/123/complete-payment',{amount})}")]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        p = result.verification_playbooks[0]
        self.assertEqual(p.page_hint, '결제/주문 화면')
        self.assertEqual(p.user_action_hint, '결제 버튼 클릭')
        self.assertEqual(p.function_name, 'handlePayment')
        self.assertIn('검증 화면', p.console_code or '')
        self.assertIn('사용자 동작', p.console_code or '')
        self.assertIn('대상 API', p.console_code or '')
        finding = [x for x in result.findings if x.vulnerability_type in {'Payment/Point Manipulation Candidate', 'Client-side Validation Bypass'}][0]
        steps = ' '.join(finding.console_poc.steps if finding.console_poc else [])
        self.assertIn('결제/주문 화면', steps)
        self.assertIn('결제 버튼 클릭', steps)

    def test_playbook_contains_proof_and_criteria(self):
        files = [f('src/FindPassword.js', "function handleVerify(){axios.post('/verify-code',{code})}")]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        p = result.verification_playbooks[0]
        self.assertEqual(p.page_hint, '계정 복구/인증 화면')
        self.assertEqual(p.user_action_hint, '인증번호 확인 버튼 클릭')
        self.assertTrue(len(p.proof_steps) > 0)
        self.assertTrue(len(p.success_criteria) > 0)
        self.assertTrue(len(p.failure_criteria) > 0)
        self.assertTrue(len(p.evidence_to_capture) > 0)

    def test_disabled_console_code_no_auto_click_and_has_api(self):
        files = [f('src/pay.js', "const handlePay=()=>{axios.post('/api/pay',{ amount })}; <button disabled={amount <= 0} onClick={handlePay}>Pay</button>")]
        findings = MockConsolePocAnalyzer().analyze(files)
        disabled = [x for x in findings if x.verification_playbook and x.verification_playbook.strategy == 'disabled_button_bypass'][0]
        code = disabled.verification_playbook.console_code or ''
        self.assertNotIn('const target = candidates[0]', code)
        self.assertIn('window.SSS_DISABLED = {', code)
        self.assertIn('list()', code)
        self.assertIn('enable(index)', code)
        self.assertIn('click(index)', code)

    def test_load_dashboard_get_goes_review_candidate(self):
        files = [f('src/AdminMypage.js', "function fetchSession(){fetch('/api/user/session')}")]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        self.assertEqual(len(result.verification_playbooks), 0)
        self.assertTrue(len(result.review_candidates) >= 1)

    def test_generic_api_review_candidate_not_promoted_to_playbook(self):
        files = [f('src/x.js', "fetch('/api/user/session')")]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        self.assertFalse(any(p.risk_type == 'Generic API Review Candidate' for p in result.verification_playbooks))
        self.assertTrue(any('일반 API 후보라 자동 검증 Playbook에서 제외하고 수동 검토 후보로 분류했습니다.' in ' '.join(x.verification_notes) for x in result.review_candidates))

    def test_session_endpoint_with_query_goes_review(self):
        files = [f('src/s.js', "fetch('/api/user/session?refresh=true')")]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        self.assertEqual(len(result.verification_playbooks), 0)
        self.assertTrue(len(result.review_candidates) >= 1)

    def test_compressed_library_like_evidence_goes_review(self):
        snippet = "function M(){const constants='x'; return wa; /* gzip deflate */}"
        files = [f('src/verification.js', snippet + " axios.post('/api/pay',{amount})")]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        self.assertEqual(len(result.verification_playbooks), 0)
        self.assertTrue(any('압축/라이브러리성 코드' in ' '.join(x.verification_notes) for x in result.review_candidates))

    def test_generic_action_hint_adds_manual_verification_note(self):
        files = [f('src/unknown.js', "function doRequest(){axios.post('/api/pay',{amount})}")]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        finding = [x for x in result.findings if x.vulnerability_type in {'Payment/Point Manipulation Candidate', 'Client-side Validation Bypass'}][0]
        self.assertTrue(any('수동 확인 필요' in n for n in finding.verification_notes))

    def test_same_endpoint_different_function_creates_separate_playbooks(self):
        files = [
            f('src/PaymentPage.js', "function handlePay(){axios.post('/api/pay',{amount})}"),
            f('src/PaymentPageRetry.js', "function handleRetryPayment(){axios.post('/api/pay',{amount})}"),
        ]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        self.assertGreaterEqual(len(result.verification_playbooks), 2)
        fnames = sorted([x.function_name for x in result.verification_playbooks if x.function_name])
        self.assertIn('handlePay', fnames)
        self.assertIn('handleRetryPayment', fnames)

    def test_playbooks_are_capped_to_seven(self):
        src = "\n".join([f"function handlePay{i}(){{axios.post('/api/pay/{i}',{{amount}})}}" for i in range(12)])
        files = [f('src/PaymentPage.js', src)]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        self.assertLessEqual(len(result.verification_playbooks), 7)

    def test_auction_page_bid_has_page_and_action_hint(self):
        files = [f('src/AuctionPage.js', "function handleBid(){axios.post('/api/auction/1/bid',{amount})}")]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        self.assertTrue(len(result.verification_playbooks) >= 1)
        p = result.verification_playbooks[0]
        self.assertEqual(p.page_hint, '경매/입찰 화면')
        self.assertEqual(p.user_action_hint, '입찰 버튼 클릭')


    def test_findpassword_send_verification_promoted_with_action_hint(self):
        files = [f('src/FindPassword.js', "function sendVerificationCode(){axios.post('{API_BASE}/send-verification',{email})}")]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        self.assertTrue(any(p.endpoint == '{API_BASE}/send-verification' for p in result.verification_playbooks))
        pbook = [p for p in result.verification_playbooks if p.endpoint == '{API_BASE}/send-verification'][0]
        self.assertEqual(pbook.user_action_hint, '인증번호 발송 버튼 클릭')
        finding = [x for x in result.findings if x.vulnerability_type == 'Account Recovery Flow Abuse Candidate'][0]
        self.assertTrue(any('API_BASE 값을 실제 대상 URL로 변경해야 합니다.' in n for n in finding.verification_notes))

    def test_findpassword_verify_code_promoted_with_action_hint(self):
        files = [f('src/FindPassword.js', "function verifyCode(){axios.post('{API_BASE}/verify-code',{code})}")]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        pbook = [p for p in result.verification_playbooks if p.endpoint == '{API_BASE}/verify-code'][0]
        self.assertEqual(pbook.user_action_hint, '인증번호 확인 버튼 클릭')

    def test_findpassword_reset_password_promoted_with_action_hint(self):
        files = [f('src/FindPassword.js', "function resetPassword(){axios.put('{API_BASE}/reset-password',{password})}")]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        pbook = [p for p in result.verification_playbooks if p.endpoint == '{API_BASE}/reset-password'][0]
        self.assertEqual(pbook.user_action_hint, '비밀번호 재설정 버튼 클릭')

    def test_purchase_stripe_and_iamport_action_hints(self):
        stripe_files = [f('src/PurchasePage.js', "function handleStripeCheckout(){axios.post('/api/stripe/create-checkout-session',{amount})}")]
        stripe_result = analyze_console_exploitability(stripe_files, analyzer=MockConsolePocAnalyzer())
        stripe = [p for p in stripe_result.verification_playbooks if p.endpoint == '/api/stripe/create-checkout-session'][0]

        iamport_files = [f('src/PurchasePage.js', "function requestIamportPay(){axios.post('/api/iamport/prepare',{amount})}")]
        iamport_result = analyze_console_exploitability(iamport_files, analyzer=MockConsolePocAnalyzer())
        iamport = [p for p in iamport_result.verification_playbooks if p.endpoint == '/api/iamport/prepare'][0]

        self.assertEqual(stripe.user_action_hint, '결제 버튼 클릭')
        self.assertEqual(iamport.user_action_hint, '결제 승인/검증 버튼 클릭')

    def test_steps_do_not_repeat_screen_word(self):
        files = [f('src/PaymentPage.js', "function handlePayment(){axios.post('/api/order/1/complete-payment',{amount})}")]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        finding = [x for x in result.findings if x.console_poc and x.console_poc.code and x.vulnerability_type == 'Payment/Point Manipulation Candidate'][0]
        self.assertFalse(any('화면 화면으로 이동' in step for step in finding.console_poc.steps))

    def test_verify_identity_classification_for_non_findpassword(self):
        files = [f('src/ItemDetailPage.js', "function handleVerifyCode(){axios.post('/api/user/verify-identity',{code})}")]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        finding = [x for x in result.findings if '/api/user/verify-identity' in (x.console_poc.code or '')][0]
        self.assertEqual(finding.vulnerability_type, 'Identity Verification / Action Authorization Bypass Candidate')

    def test_generic_get_recommend_note_not_session_note(self):
        files = [f('src/nls.js', "function getRecommendSearch(){fetch('/header/recommend_search.do')}")]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        self.assertEqual(len(result.verification_playbooks), 0)
        self.assertTrue(len(result.review_candidates) >= 1)
        notes = ' '.join(result.review_candidates[0].verification_notes)
        self.assertIn('자동 조회/추천검색성 API로 판단되어 Playbook에서 제외했습니다.', notes)
        self.assertNotIn('자동 세션/초기화 요청으로 판단되어 Playbook에서 제외했습니다.', notes)

    def test_react_generic_submit_order_infers_payment_hints(self):
        files = [f('src/OrderFlow.jsx', "function submitOrder(){axios.post('/api/orders/123/pay',{amount})}\n<button onClick={submitOrder}>Pay now</button>")]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        p = [x for x in result.verification_playbooks if x.endpoint == '/api/orders/123/pay'][0]
        self.assertEqual(p.page_hint, '결제/주문 화면')
        self.assertEqual(p.user_action_hint, '결제 버튼 클릭')

    def test_vue_generic_place_bid_infers_auction_hints(self):
        files = [f('src/BidWidget.vue', "@click=\"placeBid\"\nfunction placeBid(){axios.post('/api/auction/1/bid',{amount})}")]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        p = [x for x in result.verification_playbooks if x.endpoint == '/api/auction/1/bid'][0]
        self.assertEqual(p.page_hint, '경매/입찰 화면')
        self.assertEqual(p.user_action_hint, '입찰 버튼 클릭')

    def test_vanilla_charge_infers_wallet_hint(self):
        files = [f('src/Wallet.js', "document.querySelector('#charge').addEventListener('click', chargeWallet)\nfunction chargeWallet(){fetch('/api/wallet/charge',{method:'POST',body:JSON.stringify({amount})})}")]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        p = [x for x in result.verification_playbooks if x.endpoint == '/api/wallet/charge'][0]
        self.assertEqual(p.page_hint, '지갑/포인트 화면')

    def test_result_contains_project_understanding(self):
        files = [f('src/App.jsx', "<Route path='/payment' element={<PaymentPage />} />"), f('src/PaymentPage.jsx', "function submitOrder(){axios.post('/api/orders/123/pay',{amount})}")]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        self.assertIsNotNone(result.project_understanding)
        pu = result.project_understanding
        self.assertTrue(any(r.path == '/payment' for r in pu.routes))
        self.assertTrue(any(a.endpoint == '/api/orders/123/pay' for a in pu.api_inventory))

    def test_payment_with_ui_event_promotes_playbook_and_score_notes(self):
        files = [f('src/OrderFlow.jsx', "function submitOrder(){axios.post('/api/orders/123/pay',{amount})}\n<button onClick={submitOrder}>Pay now</button>")]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        self.assertTrue(any(p.endpoint == '/api/orders/123/pay' for p in result.verification_playbooks))
        rel = [x for x in result.findings if x.vulnerability_type in {'Payment/Point Manipulation Candidate', 'Client-side Validation Bypass'}][0]
        notes = ' '.join(rel.verification_notes)
        self.assertIn('playbook_score=', notes)
        self.assertTrue(('ui_event_connected' in notes) or ('endpoint_category=payment' in notes))

    def test_payment_endpoint_without_ui_event_stays_review(self):
        files = [f('src/service.js', "axios.post('/api/orders/123/pay',{amount})")]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        self.assertFalse(any(p.endpoint == '/api/orders/123/pay' for p in result.verification_playbooks))
        self.assertTrue(any('playbook_score=' in ' '.join(x.verification_notes) for x in result.review_candidates))

    def test_multiline_jsx_button_text_is_connected(self):
        files = [f('src/Pay.jsx', "<button\n  disabled={loading}\n  onClick={submitOrder}\n>\n  Pay now\n</button>\nfunction submitOrder(){axios.post('/api/orders/123/pay',{amount})}")]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        pu = result.project_understanding
        ev = [x for x in pu.ui_events if x.handler_name == 'submitOrder'][0]
        self.assertEqual(ev.element_text, 'Pay now')

    def test_jquery_send_sms_post_promotes_playbook(self):
        files = [f('templates/mypage.html', "<button id=\"sendSms\">인증번호 발송</button>\n<script>$('#sendSms').on('click', function(){ $.ajax({ url:'/user/chkMobiSendAjax', type:'POST', data:{ phoneNo } }); });</script>")]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        self.assertTrue(any(p.endpoint == '/user/chkMobiSendAjax' for p in result.verification_playbooks))
        p = [x for x in result.verification_playbooks if x.endpoint == '/user/chkMobiSendAjax'][0]
        self.assertEqual(p.user_action_hint, '인증번호 발송 버튼 클릭')
        self.assertNotEqual(p.page_hint, '해당 기능 화면')
        notes = ' '.join([n for x in result.findings for n in x.verification_notes])
        self.assertIn('playbook_score=', notes)
        self.assertTrue(('ui_event_connected' in notes) or ('endpoint_category=' in notes))

    def test_jquery_recommend_search_get_stays_review(self):
        files = [f('templates/nls.html', "<button id='reco'>추천검색</button><script>$('#reco').on('click', function(){ $.ajax({ url:'/header/recommend_search.do', type:'GET' }); });</script>")]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        self.assertEqual(len(result.verification_playbooks), 0)
        notes = ' '.join(result.review_candidates[0].verification_notes)
        self.assertIn('조회/추천검색성 API', notes)

    def test_mypage_get_review_candidate(self):
        files = [f('templates/mypage.html', "function loadMyPage(){fetch('/myPage/myPageNewAjax')}")]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        self.assertFalse(any(p.endpoint == '/myPage/myPageNewAjax' for p in result.verification_playbooks))

    def test_guarded_post_code_allowed_by_filter(self):
        code = "(async()=>{const CONFIRM_AUTHORIZED_TEST = false; if (!CONFIRM_AUTHORIZED_TEST) { throw new Error('x'); } const res = await fetch('/api/x',{method:'POST'});})();"
        self.assertTrue(_is_allowed_guarded_poc_code(code))

    def test_axios_post_without_guard_rejected(self):
        code = "axios.post('/api/pay', { amount: 1 })"
        self.assertFalse(_is_allowed_guarded_poc_code(code))

    def test_axios_post_with_guard_allowed(self):
        code = """(async () => {
  const CONFIRM_AUTHORIZED_TEST = false;
  if (!CONFIRM_AUTHORIZED_TEST) { throw new Error('x'); }
  await axios.post('/api/pay', { amount: 1 });
})();"""
        self.assertTrue(_is_allowed_guarded_poc_code(code))

    def test_axios_delete_rejected(self):
        code = "axios.delete('/api/user/1')"
        self.assertFalse(_is_allowed_guarded_poc_code(code))

    def test_xhr_post_without_guard_rejected(self):
        code = "const x = new XMLHttpRequest(); x.open('POST','/api/pay'); x.send('x');"
        self.assertFalse(_is_allowed_guarded_poc_code(code))

    def test_xhr_post_with_guard_allowed(self):
        code = """(async () => {
  const CONFIRM_AUTHORIZED_TEST = false;
  if (!CONFIRM_AUTHORIZED_TEST) { throw new Error('x'); }
  const x = new XMLHttpRequest(); x.open('POST','/api/pay'); x.send('x');
})();"""
        self.assertTrue(_is_allowed_guarded_poc_code(code))

    def test_send_beacon_rejected(self):
        code = "navigator.sendBeacon('/api/pay', 'x')"
        self.assertFalse(_is_allowed_guarded_poc_code(code))

    def test_execute_query_not_blocked_by_exec_substring(self):
        code = """(async () => {
  const CONFIRM_AUTHORIZED_TEST = false;
  if (!CONFIRM_AUTHORIZED_TEST) { throw new Error('x'); }
  await fetch('/api/execute-query', { method: 'POST' });
})();"""
        self.assertTrue(_is_allowed_guarded_poc_code(code))

    def test_exec_function_call_rejected(self):
        self.assertFalse(_is_allowed_guarded_poc_code("exec('rm -rf /')"))

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
