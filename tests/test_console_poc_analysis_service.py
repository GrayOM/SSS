import unittest

from app.models.schemas import FileContent
from app.services.console_poc_analysis_service import (
    GeminiConsolePocAnalyzer,
    MockConsolePocAnalyzer,
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
            self.assertIn("const API_BASE = 'https://TARGET_BASE_URL';", finding.console_poc.code or '')
            self.assertIn('const endpoint = `${API_BASE}/verify-code`;', finding.console_poc.code or '')
            self.assertTrue(any('API_BASE 값을 실제 대상 URL로 변경해야 합니다.' in n for n in finding.verification_notes) or finding.console_poc.code is None)

    def test_api_base_get_endpoint_uses_placeholder_base(self):
        files = [f('src/vget.js', "fetch('{API_BASE}/user/session')")]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        finding = [x for x in result.findings if x.vulnerability_type == 'Generic API Review Candidate'][0]
        self.assertIn("const API_BASE = 'https://TARGET_BASE_URL';", finding.console_poc.code or '')
        self.assertIn('const endpoint = `${API_BASE}/user/session`;', finding.console_poc.code or '')

    def test_api_base_path_variable_is_replaced_in_poc(self):
        files = [f('src/vpath.js', "axios.post('{API_BASE}/api/user/{userId}/wallet', { amount })")]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        finding = [x for x in result.findings if 'Candidate' in x.vulnerability_type][0]
        self.assertNotIn('TEST_VALUE/wallet', finding.console_poc.code or '')
        self.assertIn("const API_BASE = 'https://TARGET_BASE_URL';", finding.console_poc.code or '')
        self.assertIn('const endpoint = `${API_BASE}/api/user/TEST_USER_ID/wallet`;', finding.console_poc.code or '')

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
        self.assertIn('CONFIRM_AUTHORIZED_TEST = false', finding.console_poc.code or '')
        self.assertIsNotNone(finding.verification_playbook)

    def test_disabled_button_only_generates_playbook_console_code(self):
        files = [f('src/pay.js', "<button disabled={amount <= 0} onClick={handlePay}>Pay</button>")]
        findings = MockConsolePocAnalyzer().analyze(files)
        finding = [x for x in findings if x.verification_playbook and x.verification_playbook.strategy == 'disabled_button_bypass'][0]
        self.assertIn('button[disabled]', finding.verification_playbook.console_code or '')

    def test_auth_guard_playbook_contains_role_watch_variables(self):
        files = [f('src/auth.js', "if (userInfo.userType !== 'ADMIN') { navigate('/'); }")]
        findings = MockConsolePocAnalyzer().analyze(files)
        auth = [x for x in findings if x.vulnerability_type == 'Client-side Authorization Bypass'][0]
        self.assertIsNotNone(auth.verification_playbook)
        self.assertIn('userInfo', auth.verification_playbook.breakpoints[0].watch_variables)
        self.assertIn('userType', auth.verification_playbook.breakpoints[0].watch_variables)

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
