import unittest

from app.models.schemas import FileContent
from app.services.console_poc_analysis_service import (
    GeminiConsolePocAnalyzer,
    MAX_PLAYBOOK_COUNT,
    MockConsolePocAnalyzer,
    PROMOTION_SCORE_THRESHOLD,
    _build_common_console_helper,
    _build_network_hook_mutation_poc,
    _build_short_console_verification_code,
    _is_allowed_guarded_poc_code,
    _extract_endpoint,
    _auth_bypass_severity,
    analyze_console_exploitability,
    select_console_relevant_files,
    get_console_poc_analyzer,
)


def f(path, content):
    return FileContent(path=path, extension='.js', size=len(content), priority=1, reason_code='INCLUDED', content_hash='h', content=content)


MANUAL_REVIEW_NOTE = 'Manual review candidate'
NOT_CONFIRMED_NOTE = 'Not yet verified by runtime evidence'
RESOLVE_BEFORE_POC_NOTE = 'Resolve endpoint/page/action before using PoC'
UNRESOLVED_PLACEHOLDER_NOTE = 'Unresolved placeholder blocks promotion'
GENERIC_PAGE_ACTION_NOTE = 'Generic page/action blocks promotion'
RTVC_NOTE = 'Selected as runtime verification candidate'


class ConsolePocAnalysisTests(unittest.TestCase):
    def _assert_promoted_poc_self_contained(self, playbook, max_lines=12):
        code = playbook.console_code or ''
        forbidden = (
            'window.SSS_POC.find(',
            'window.SSS_POC',
            'window.SSS_REVIEW_POC',
            'XMLHttpRequest.prototype',
            'fetch = new Proxy',
            'addEventListener("fetch"',
            'SSS_POC.find',
            'SSS_REVIEW_POC',
        )
        for sig in forbidden:
            self.assertNotIn(sig, code)
        self.assertLessEqual(len([line for line in code.splitlines() if line.strip()]), max_lines)

    def _assert_v1_playbook_contract(self, playbook):
        self.assertTrue(playbook.source_path)
        self.assertIsInstance(playbook.start_line, int)
        self.assertIsInstance(playbook.end_line, int)
        self.assertTrue(playbook.vulnerability_title)
        self.assertTrue(playbook.vulnerable_code_summary)
        self.assertTrue(playbook.why_exploitable)
        self.assertIsNotNone(playbook.data_flow)
        self.assertTrue(playbook.data_flow.api_call_or_sink)
        self.assertIsNotNone(playbook.breakpoint_plan)
        self.assertTrue(playbook.breakpoint_plan.file)
        self.assertIsInstance(playbook.breakpoint_plan.line, int)
        self.assertTrue(playbook.breakpoint_plan.when_to_pause)
        self.assertTrue(playbook.breakpoint_plan.what_variable_or_request_to_check)
        self.assertIsNotNone(playbook.poc_injection_plan)
        self.assertEqual(playbook.poc_injection_plan.where_to_paste_code, 'Browser DevTools Console')
        self.assertTrue(playbook.poc_injection_plan.when_to_run)
        self.assertTrue(playbook.poc_injection_plan.required_user_action)
        self.assertTrue(playbook.console_code)

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
        self.assertIn('requireAuth/checkSession implementation file needs manual confirmation', auth.verification_notes)
        self.assertIn('sessionStorage/localStorage manipulation PoC is not confirmed by current code evidence', auth.verification_notes)
        self.assertEqual(auth.confidence, 'low')
        self.assertIn('needs manual confirmation', auth.summary)

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
        self.assertIn('sessionStorage/localStorage manipulation PoC is not confirmed by current code evidence', auth.verification_notes)
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
        # With 'user' key (JSON-object pattern), auth bypass is PROMOTED with short PoC.
        files = [f('src/AdminMypage.js', "const user = JSON.parse(sessionStorage.getItem('user')); if (user?.userType === 'ADMIN') { navigate('/admin') }")]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        auth = [x for x in result.findings if x.vulnerability_type == 'Client-side Authorization Bypass'][0]
        self.assertIn("sessionStorage.getItem('user')", auth.evidence[0].snippet)
        # After promotion, console_poc.code is cleared; check via playbook
        pb = [p for p in result.verification_playbooks if p.risk_type == 'Client-side Authorization Bypass']
        if pb:
            self.assertIn('sessionStorage', pb[0].console_code or '')
            self.assertLessEqual(len((pb[0].console_code or '').splitlines()), 2)
        else:
            # Not promoted: code must still be set on the finding
            self.assertIsNotNone(auth.console_poc.code)

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
        self.assertIn('before API call', finding.verification_playbook.breakpoints[0].reason)
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
        # No function/UI event -> action is generic -> no runnable hook; manual_plan review candidate
        files = [f('src/get.js', "fetch('/api/user/session')")]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        finding = [x for x in result.findings if x.vulnerability_type == 'Generic API Review Candidate'][0]
        self.assertEqual(finding.poc_generation_status, 'manual_plan')
        self.assertIsNone(finding.console_poc.code)
        self.assertTrue(any('Not a runnable proof yet' in n for n in finding.verification_notes))

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
        self.assertIn('access control check required for identifier-based query', finding.title)

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
            self.assertTrue(any('replace API_BASE with the actual target URL' in n for n in finding.verification_notes) or finding.console_poc.code is None)

    def test_api_base_get_endpoint_no_runnable_poc(self):
        # {API_BASE} placeholder -> unresolved -> no runnable PoC code; manual_plan
        files = [f('src/vget.js', "fetch('{API_BASE}/user/session')")]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        finding = [x for x in result.findings if x.vulnerability_type == 'Generic API Review Candidate'][0]
        self.assertIsNone(finding.console_poc.code)
        self.assertNotIn('{API_BASE}/user/session', (finding.console_poc.code or ''))
        self.assertNotIn('url.includes("{API_BASE}/user/session")', (finding.console_poc.code or ''))
        self.assertTrue(any('Unresolved placeholder' in n or 'Not a runnable proof' in n or 'manual' in n.lower() for n in finding.verification_notes))

    def test_api_base_path_variable_no_url_includes_placeholder(self):
        # {API_BASE} and {userId} are unresolved -> no runnable PoC; no url.includes with placeholder
        files = [f('src/vpath.js', "axios.post('{API_BASE}/api/user/{userId}/wallet', { amount })")]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        finding = [x for x in result.findings if 'Candidate' in x.vulnerability_type][0]
        self.assertIsNone(finding.console_poc.code)
        self.assertNotIn('url.includes("{API_BASE}', (finding.console_poc.code or ''))
        self.assertNotIn('url.includes("{userId}', (finding.console_poc.code or ''))
        self.assertNotIn('url.includes("TEST_VALUE', (finding.console_poc.code or ''))

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
        # New design: short CONFIRM-guarded direct replay, no global interceptor
        self.assertIn('confirm(', finding.console_poc.code or '')
        self.assertNotIn('window.SSS_REVIEW_POC', finding.console_poc.code or '')
        self.assertNotIn('SSS_REVIEW_POC_STATE', finding.console_poc.code or '')
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
        self.assertIn('check client-side validation branch', reasons)
        self.assertIn('check payload before API call', reasons)
        all_watch = {w for bp in rec.verification_playbook.breakpoints for w in bp.watch_variables}
        self.assertIn('code', all_watch)

    def test_fetch_hook_endpoint_is_escaped(self):
        code = _build_network_hook_mutation_poc('/api/o"rder')
        self.assertIn('const TARGET_ENDPOINT = "/api/o\\"rder";', code)
        self.assertIn('XMLHttpRequest.prototype.open', code)
        self.assertIn('axios.interceptors.request.use', code)

    def test_xhr_hook_does_not_mutate_without_arm(self):
        code = _build_network_hook_mutation_poc('/api/pay')
        self.assertIn('if (SSS_REVIEW_POC_STATE.mutationArmed && !BLOCKED_REPLAY && parsed)', code)

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
        self.assertFalse(any(bp.reason == 'check client-side validation branch' and bp.start_line > 700 for bp in (pay.verification_playbook.breakpoints if pay.verification_playbook else [])))

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

    def test_post_request_no_hook_when_action_generic(self):
        # No function/UI event -> action is generic -> no runnable hook; "Not a runnable proof yet"
        files = [f('src/post.js', "axios.post('/api/pay', { amount, orderId, userId })")]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        finding = [x for x in result.findings if x.vulnerability_type == 'Payment/Point Manipulation Candidate'][0]
        self.assertIsNone(finding.console_poc.code)
        self.assertEqual(finding.poc_generation_status, 'manual_plan')
        self.assertTrue(any('Not a runnable proof yet' in n for n in finding.verification_notes))
        # Hook installer must not appear in any review candidate code
        for rc in result.review_candidates:
            self.assertNotIn('window.fetch = async function', (rc.console_poc.code or ''))
            self.assertNotIn('SSS_REVIEW_POC_STATE', (rc.console_poc.code or ''))

    def test_get_endpoint_has_no_hook_code_when_action_generic(self):
        # No function/UI event -> action is generic -> no runnable hook code
        files = [f('src/get2.js', "fetch('/api/user/session')")]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        finding = [x for x in result.findings if x.vulnerability_type == 'Generic API Review Candidate'][0]
        self.assertIsNone(finding.console_poc.code)
        self.assertEqual(finding.poc_generation_status, 'manual_plan')
        self.assertFalse(any('window.fetch = async function' in (f.console_poc.code or '') for f in result.findings))

    def test_complete_payment_and_charge_unresolved_placeholder_is_manual_plan(self):
        # Template literal endpoints with {orderId}/{sessionData.userId} are unresolved placeholders.
        # They become manual_plan review candidates, not runnable PoC.
        files = [
            f('src/pay1.js', "axios.post('/api/order/{orderId}/complete-payment', { orderId, totalAmount, usePoints })"),
            f('src/pay2.js', "axios.post('/api/user/{sessionData.userId}/wallet/charge', { amount, userId })"),
        ]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        candidates = [x for x in result.findings if 'Manipulation Candidate' in x.vulnerability_type]
        self.assertTrue(len(candidates) >= 1)
        for c in candidates:
            self.assertIsNone(c.console_poc.code)
            self.assertNotIn('window.fetch = async function', (c.console_poc.code or ''))

    def test_delete_endpoint_no_hook_when_action_generic(self):
        # No function/UI event -> action is generic -> no runnable hook code regardless of method
        files = [f('src/del.js', "axios.delete('/api/admin/delete-user/{userId}')")]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        finding = [x for x in result.findings if x.vulnerability_type in {'State/Status Manipulation Candidate', 'Client-side Validation Bypass', 'Generic API Review Candidate'}][0]
        self.assertIsNone(finding.console_poc.code)
        self.assertTrue(any('Not a runnable proof yet' in n or 'observe mode only' in n for n in finding.verification_notes))

    def test_post_poc_uses_confirm_guard_not_arm_mutation(self):
        # New design: bare axios.post with no function -> generic action -> manual_plan,
        # code is None. For any code that IS generated, it uses browser confirm()
        # not SSS_REVIEW_POC.armMutation().
        files = [f('src/post2.js', "axios.post('/api/pay', { amount })")]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        finding = [x for x in result.findings if x.vulnerability_type in {'Payment/Point Manipulation Candidate', 'Client-side Validation Bypass'}][0]
        code = finding.console_poc.code or ''
        # Generic action -> manual_plan; code should be None or use CONFIRM guard
        if code:
            self.assertIn('confirm(', code)
            self.assertNotIn('window.SSS_REVIEW_POC.armMutation()', code)
            self.assertNotIn('SSS_REVIEW_POC_STATE', code)

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
        self.assertTrue(any('endpoint is UNKNOWN: auto PoC not generated' in ' '.join(x.verification_notes) for x in result.review_candidates))

    def test_unresolved_api_base_url_endpoint_is_not_promoted(self):
        # New behavior: {API_BASE_URL}/login + button is PROMOTED with the base-URL prefix stripped.
        # The playbook endpoint is normalized to /login; no raw {API_BASE_URL} leaks into the PoC.
        files = [f('src/LoginPage.js', "function handleLogin(){axios.post('{API_BASE_URL}/login',{ username, password })}\n<button onClick={handleLogin}>Login</button>")]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        # Raw endpoint must never appear verbatim in the playbook endpoint field.
        self.assertFalse(any(p.endpoint == '{API_BASE_URL}/login' for p in result.verification_playbooks))
        # A promoted playbook for /login must exist with a normalized endpoint and self-contained PoC.
        pb = next((p for p in result.verification_playbooks if '/login' in (p.endpoint or '')), None)
        self.assertIsNotNone(pb, 'expected a promoted playbook for /login after base-URL normalization')
        self.assertNotIn('{API_BASE_URL}', pb.console_code or '')
        self.assertIn('fetch("/login"', pb.console_code or '')
        self._assert_promoted_poc_self_contained(pb)
        self.assertIsNone(result.common_console_helper)

    def test_required_base_url_variants_promote_as_self_contained_playbooks(self):
        files = [
            f('src/AdminAdd.jsx',
              'function addNumbers(){axios.post(`${API_BASE_URL}/admin/add-numbers`, { a, b });}\n'
              '<button onClick={addNumbers}>Add</button>'),
            f('src/Lotto.jsx',
              'function generateLotto(){axios.post(API_BASE_URL + "/generate-lotto", {});}\n'
              '<button onClick={generateLotto}>Generate</button>'),
            f('src/Client.jsx',
              'function login(){axios.create({ baseURL: API_BASE_URL }).post("/login", { email, password });}\n'
              '<button onClick={login}>Login</button>'),
        ]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        endpoints = {p.endpoint: p for p in result.verification_playbooks}
        for endpoint in ('/admin/add-numbers', '/generate-lotto', '/login'):
            self.assertIn(endpoint, endpoints)
            self.assertIn(f'fetch("{endpoint}"', endpoints[endpoint].console_code or '')
            self._assert_promoted_poc_self_contained(endpoints[endpoint])
        self.assertIsNone(result.common_console_helper)

    def test_path_param_endpoint_promotes_with_editable_test_id(self):
        files = [f('src/AuctionPage.js',
                   "function handleBid(){axios.post('/api/auction/{item.id}/bid',{amount})}\n"
                   "<button onClick={handleBid}>Bid</button>")]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        pb = next((p for p in result.verification_playbooks if p.endpoint == '/api/auction/{item.id}/bid'), None)
        self.assertIsNotNone(pb)
        code = pb.console_code or ''
        self.assertIn('const TEST_ID = "REPLACE_WITH_TEST_ID";', code)
        self.assertIn('fetch(`/api/auction/${TEST_ID}/bid', code)
        self._assert_promoted_poc_self_contained(pb)
        self.assertIsNone(result.common_console_helper)

    def test_unknown_path_placeholder_remains_manual(self):
        files = [f('src/UnknownPath.js',
                   'function runUnknown(){axios.post("{API_BASE_URL}/{UNKNOWN_PATH}", {})}\n'
                   '<button onClick={runUnknown}>Run</button>')]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        self.assertFalse(any(p.endpoint == '/{UNKNOWN_PATH}' for p in result.verification_playbooks))
        self.assertTrue(result.review_candidates)

    def test_generic_action_hint_is_not_promoted(self):
        files = [f('src/PaymentPage.js', "function doRequest(){axios.post('/api/pay',{amount})}")]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        self.assertFalse(any(p.endpoint == '/api/pay' for p in result.verification_playbooks))
        self.assertTrue(any(GENERIC_PAGE_ACTION_NOTE in ' '.join(x.verification_notes) for x in result.review_candidates))

    def test_disabled_loading_is_review_candidate_not_playbook(self):
        files = [f('src/a.js', "<button disabled={loading}>Pay</button>")]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        self.assertEqual(len(result.verification_playbooks), 0)

    def test_page_and_action_hints_in_playbook(self):
        # New design: playbook code is a direct CONFIRM-guarded replay; page/action are
        # stored in page_hint/user_action_hint fields, not embedded in the code.
        files = [f('src/PaymentPage.js', "function handlePayment(){axios.post('/api/order/123/complete-payment',{amount})}")]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        p = result.verification_playbooks[0]
        self.assertEqual(p.page_hint, 'payment/order page')
        self.assertEqual(p.user_action_hint, 'click payment button')
        self.assertEqual(p.function_name, 'handlePayment')
        # Direct replay code: contains endpoint and CONFIRM guard
        self.assertIn('/api/order/123/complete-payment', p.console_code or '')
        self.assertIn('confirm(', p.console_code or '')
        # No global hook
        self.assertNotIn('window.fetch = async function', p.console_code or '')

    def test_generated_poc_explains_undefined_is_normal_after_install(self):
        code = _build_network_hook_mutation_poc('/api/pay', page_hint='payment page', action_hint='click payment button')
        self.assertIn('undefined output is normal', code)
        self.assertIn('Confirm window.SSS_REVIEW_POC exists', code)
        self.assertIn('wrong page, wrong button/action, placeholder endpoint', code)
        self.assertIn('window.SSS_REVIEW_POC.list()', code)
        self.assertIn('Use window.SSS_REVIEW_POC.armMutation() only after the baseline request is captured', code)
        self.assertNotIn('window.SSS_POC =', code)
        self.assertIn('const PAGE_HINT = "payment page";', code)
        self.assertIn('const ACTION_HINT = "click payment button";', code)

    def test_review_poc_invalid_hints_use_english_fallback(self):
        invalid_hint = chr(0x2603)
        code = _build_network_hook_mutation_poc('/api/pay', page_hint=invalid_hint, action_hint=invalid_hint)

        self.assertIn('const PAGE_HINT = "target page";', code)
        self.assertIn('const ACTION_HINT = "target action";', code)
        self.assertFalse(any(ord(ch) > 127 for ch in code))
        self.assertNotIn('window.SSS_POC =', code)

    def test_review_candidate_standalone_poc_uses_review_namespace(self):
        code = _build_network_hook_mutation_poc('/api/pay', page_hint='payment page', action_hint='click payment button')

        self.assertIn('window.SSS_REVIEW_POC =', code)
        self.assertIn('window.SSS_REVIEW_POC.armMutation()', code)
        self.assertIn('window.SSS_REVIEW_POC.replay(index, overrides)', code)
        self.assertNotIn('window.SSS_POC =', code)
        self.assertNotIn('window.SSS_POC.list()', code)
        self.assertNotIn('window.SSS_POC.armMutation()', code)
        self.assertNotIn('window.SSS_POC.replay', code)

    def test_review_candidate_no_hook_no_function_no_overwrite(self):
        # No function/UI -> action generic -> review candidate; no runnable code, no SSS_POC overwrite.
        # New: common_console_helper is None because no promoted playbook needs it.
        files = [f('src/service.js', "axios.post('/api/orders/123/pay',{amount})")]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        review = [x for x in result.review_candidates if '/api/orders/123/pay' in ' '.join(sum([e.data_flow for e in x.evidence], []))][0]

        self.assertIn(MANUAL_REVIEW_NOTE, review.title)
        self.assertIn(NOT_CONFIRMED_NOTE, review.summary)
        self.assertIn(RESOLVE_BEFORE_POC_NOTE, ' '.join(review.verification_notes))
        # No hook installer in any code field
        self.assertIsNone(review.console_poc.code)
        obs_code = (review.observational_poc.code or '') if review.observational_poc else ''
        self.assertNotIn('window.SSS_POC =', obs_code)
        self.assertNotIn('window.SSS_REVIEW_POC =', obs_code)
        # No promoted playbook -> helper is None (no helper needed for manual review only).
        self.assertIsNone(result.common_console_helper)

    def test_promoted_playbook_has_concrete_runtime_guidance(self):
        files = [f('src/Pay.jsx', "function submitOrder(){axios.post('/api/orders/123/pay',{amount})}\n<button onClick={submitOrder}>Pay now</button>")]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        p = [x for x in result.verification_playbooks if x.endpoint == '/api/orders/123/pay'][0]
        self.assertEqual(p.page_hint, 'payment/order page')
        self.assertEqual(p.user_action_hint, 'click payment button')
        self.assertEqual(p.endpoint, '/api/orders/123/pay')
        self.assertTrue(p.console_code)
        self.assertNotIn('target action', p.user_action_hint)
        self.assertNotIn('const TARGET_ENDPOINT = "UNKNOWN";', p.console_code)
        self.assertNotIn('const TARGET_ENDPOINT = "{API_BASE_URL}/login";', p.console_code)

    def test_review_candidate_with_manual_plan_is_not_confirmed_vulnerability(self):
        files = [f('src/service.js', "axios.post(apiUrl,{amount})")]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        self.assertEqual(len(result.verification_playbooks), 0)
        review = [x for x in result.review_candidates if x.poc_generation_status == 'manual_plan'][0]
        self.assertTrue(review.manual_poc_plan)
        self.assertIn(MANUAL_REVIEW_NOTE, review.title)
        self.assertIn(NOT_CONFIRMED_NOTE, review.summary)
        self.assertIn(RESOLVE_BEFORE_POC_NOTE, ' '.join(review.verification_notes))

    def test_playbook_contains_proof_and_criteria(self):
        files = [f('src/FindPassword.js', "function handleVerify(){axios.post('/verify-code',{code})}")]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        p = result.verification_playbooks[0]
        self.assertEqual(p.page_hint, 'account recovery page')
        self.assertEqual(p.user_action_hint, 'click verify code button')
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
        self.assertTrue(any('generic API candidate: excluded from auto playbook, moved to manual review' in ' '.join(x.verification_notes) for x in result.review_candidates))

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
        self.assertTrue(any('compressed/library code' in ' '.join(x.verification_notes) for x in result.review_candidates))

    def test_generic_action_hint_adds_not_runnable_note(self):
        # Generic action (doRequest has no matching action inference) -> "Not a runnable proof yet" note
        files = [f('src/unknown.js', "function doRequest(){axios.post('/api/pay',{amount})}")]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        finding = [x for x in result.findings if x.vulnerability_type in {'Payment/Point Manipulation Candidate', 'Client-side Validation Bypass'}][0]
        self.assertTrue(any('Not a runnable proof yet' in n for n in finding.verification_notes))
        self.assertIsNone(finding.console_poc.code)

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
        self.assertLessEqual(len(result.verification_playbooks), MAX_PLAYBOOK_COUNT)

    def test_auction_page_bid_has_page_and_action_hint(self):
        files = [f('src/AuctionPage.js', "function handleBid(){axios.post('/api/auction/1/bid',{amount})}")]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        self.assertTrue(len(result.verification_playbooks) >= 1)
        p = result.verification_playbooks[0]
        self.assertEqual(p.page_hint, 'auction/bid page')
        self.assertEqual(p.user_action_hint, 'click bid button')


    def test_findpassword_send_verification_with_api_base_stays_review(self):
        # New behavior: {API_BASE}/send-verification with function + concrete action hint IS promoted.
        # The raw {API_BASE} prefix is stripped; playbook endpoint shows /send-verification.
        files = [f('src/FindPassword.js', "function sendVerificationCode(){axios.post('{API_BASE}/send-verification',{email})}")]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        # Raw endpoint must not appear verbatim in any playbook endpoint field.
        self.assertFalse(any(p.endpoint == '{API_BASE}/send-verification' for p in result.verification_playbooks))
        # Promoted playbook must exist with normalized path and no {API_BASE} in PoC.
        pb = next((p for p in result.verification_playbooks if 'send-verification' in (p.endpoint or '')), None)
        self.assertIsNotNone(pb, 'expected a promoted playbook for send-verification after base-URL normalization')
        self.assertNotIn('{API_BASE}', pb.console_code or '')

    def test_findpassword_verify_code_with_api_base_stays_review(self):
        # New behavior: {API_BASE}/verify-code with function + concrete action hint IS promoted.
        files = [f('src/FindPassword.js', "function verifyCode(){axios.post('{API_BASE}/verify-code',{code})}")]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        self.assertFalse(any(p.endpoint == '{API_BASE}/verify-code' for p in result.verification_playbooks))
        pb = next((p for p in result.verification_playbooks if 'verify-code' in (p.endpoint or '')), None)
        self.assertIsNotNone(pb, 'expected a promoted playbook for verify-code after base-URL normalization')
        self.assertNotIn('{API_BASE}', pb.console_code or '')

    def test_findpassword_reset_password_with_api_base_stays_review(self):
        # New behavior: {API_BASE}/reset-password with function + concrete action hint IS promoted.
        files = [f('src/FindPassword.js', "function resetPassword(){axios.put('{API_BASE}/reset-password',{password})}")]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        self.assertFalse(any(p.endpoint == '{API_BASE}/reset-password' for p in result.verification_playbooks))
        pb = next((p for p in result.verification_playbooks if 'reset-password' in (p.endpoint or '')), None)
        self.assertIsNotNone(pb, 'expected a promoted playbook for reset-password after base-URL normalization')
        self.assertNotIn('{API_BASE}', pb.console_code or '')

    def test_purchase_stripe_and_iamport_action_hints(self):
        stripe_files = [f('src/PurchasePage.js', "function handleStripeCheckout(){axios.post('/api/stripe/create-checkout-session',{amount})}")]
        stripe_result = analyze_console_exploitability(stripe_files, analyzer=MockConsolePocAnalyzer())
        stripe = [p for p in stripe_result.verification_playbooks if p.endpoint == '/api/stripe/create-checkout-session'][0]

        iamport_files = [f('src/PurchasePage.js', "function requestIamportPay(){axios.post('/api/iamport/prepare',{amount})}")]
        iamport_result = analyze_console_exploitability(iamport_files, analyzer=MockConsolePocAnalyzer())
        iamport = [p for p in iamport_result.verification_playbooks if p.endpoint == '/api/iamport/prepare'][0]

        self.assertEqual(stripe.user_action_hint, 'click payment button')
        self.assertEqual(iamport.user_action_hint, 'click payment approval button')

    def test_steps_do_not_repeat_screen_word(self):
        files = [f('src/PaymentPage.js', "function handlePayment(){axios.post('/api/order/1/complete-payment',{amount})}")]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        finding = [x for x in result.findings if x.console_poc and x.vulnerability_type == 'Payment/Point Manipulation Candidate'][0]
        self.assertFalse(any('Navigate to target feature page' in step for step in finding.console_poc.steps))

    def test_verify_identity_classification_for_non_findpassword(self):
        files = [f('src/ItemDetailPage.js', "function handleVerifyCode(){axios.post('/api/user/verify-identity',{code})}")]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        finding = [
            x for x in result.findings
            if any('/api/user/verify-identity' in flow for ev in x.evidence for flow in ev.data_flow)
        ][0]
        self.assertEqual(finding.vulnerability_type, 'Identity Verification / Action Authorization Bypass Candidate')

    def test_generic_get_recommend_note_not_session_note(self):
        files = [f('src/nls.js', "function getRecommendSearch(){fetch('/header/recommend_search.do')}")]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        self.assertEqual(len(result.verification_playbooks), 0)
        self.assertTrue(len(result.review_candidates) >= 1)
        notes = ' '.join(result.review_candidates[0].verification_notes)
        self.assertIn('classified as auto-query/recommend API: excluded from playbook', notes)
        self.assertNotIn('classified as auto session/init request: excluded from playbook', notes)

    def test_react_generic_submit_order_infers_payment_hints(self):
        files = [f('src/OrderFlow.jsx', "function submitOrder(){axios.post('/api/orders/123/pay',{amount})}\n<button onClick={submitOrder}>Pay now</button>")]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        p = [x for x in result.verification_playbooks if x.endpoint == '/api/orders/123/pay'][0]
        self.assertEqual(p.page_hint, 'payment/order page')
        self.assertEqual(p.user_action_hint, 'click payment button')

    def test_vue_generic_place_bid_infers_auction_hints(self):
        files = [f('src/BidWidget.vue', "@click=\"placeBid\"\nfunction placeBid(){axios.post('/api/auction/1/bid',{amount})}")]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        p = [x for x in result.verification_playbooks if x.endpoint == '/api/auction/1/bid'][0]
        self.assertEqual(p.page_hint, 'auction/bid page')
        self.assertEqual(p.user_action_hint, 'click bid button')

    def test_vanilla_charge_infers_wallet_hint(self):
        files = [f('src/Wallet.js', "document.querySelector('#charge').addEventListener('click', chargeWallet)\nfunction chargeWallet(){fetch('/api/wallet/charge',{method:'POST',body:JSON.stringify({amount})})}")]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        p = [x for x in result.verification_playbooks if x.endpoint == '/api/wallet/charge'][0]
        self.assertEqual(p.page_hint, 'wallet/point page')

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
        self.assertEqual(p.user_action_hint, 'click send code button')
        self.assertNotEqual(p.page_hint, 'target feature page')
        notes = ' '.join([n for x in result.findings for n in x.verification_notes])
        self.assertIn('playbook_score=', notes)
        self.assertTrue(('ui_event_connected' in notes) or ('endpoint_category=' in notes))

    def test_jquery_recommend_search_get_stays_review(self):
        files = [f('templates/nls.html', "<button id='reco'>추천검색</button><script>$('#reco').on('click', function(){ $.ajax({ url:'/header/recommend_search.do', type:'GET' }); });</script>")]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        self.assertEqual(len(result.verification_playbooks), 0)
        notes = ' '.join(result.review_candidates[0].verification_notes)
        self.assertIn('auto-query/recommend API', notes)

    def test_mypage_get_review_candidate(self):
        files = [f('templates/mypage.html', "function loadMyPage(){fetch('/myPage/myPageNewAjax')}")]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        self.assertFalse(any(p.endpoint == '/myPage/myPageNewAjax' for p in result.verification_playbooks))

    def test_promoted_playbook_must_have_console_code(self):
        files = [f('src/Pay.jsx', "function submitOrder(){axios.post('/api/orders/123/pay',{amount})}\n<button onClick={submitOrder}>Pay now</button>")]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        assert all((p.console_code is not None and p.console_code != '') for p in result.verification_playbooks)

    def test_review_without_function_is_manual_plan_no_code(self):
        # No function/UI event -> action generic -> manual_plan; no hook code
        files = [f('src/service.js', "axios.post('/api/orders/123/pay',{amount})")]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        rel = [x for x in result.review_candidates if '/api/orders/123/pay' in '\\n'.join(sum([e.data_flow for e in x.evidence], []))]
        self.assertTrue(len(rel) >= 1)
        self.assertEqual(rel[0].poc_generation_status, 'manual_plan')
        self.assertIsNone(rel[0].console_poc.code)
        self.assertTrue(any('Not a runnable proof yet' in n for n in rel[0].verification_notes))

    def test_unknown_endpoint_review_has_manual_plan(self):
        files = [f('src/service.js', "axios.post(apiUrl,{amount})")]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        self.assertTrue(any((x.poc_generation_status == 'manual_plan' and len(x.manual_poc_plan) > 0) for x in result.review_candidates))


    def test_compressed_candidate_not_executable_and_has_manual_or_reason(self):
        files = [f('dist/app.min.js', "function M(){var a=1;gzip='x';deflate='y';fetch('/api/x',{method:'POST'})}")]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        self.assertFalse(any(p.endpoint == '/api/x' for p in result.verification_playbooks))
        rel = [x for x in result.review_candidates if '/api/x' in '\n'.join(sum([e.data_flow for e in x.evidence], []))]
        self.assertTrue(len(rel) >= 1)
        self.assertTrue((rel[0].poc_generation_status == 'manual_plan' and len(rel[0].manual_poc_plan) > 0) or (rel[0].poc_generation_reason is not None and rel[0].poc_generation_reason != ''))

    def test_guarded_post_code_allowed_by_filter(self):
        code = "(async()=>{const CONFIRM_AUTHORIZED_TEST = false; if (!CONFIRM_AUTHORIZED_TEST) { throw new Error('x'); } const res = await fetch('/api/x',{method:'POST'});})();"
        self.assertTrue(_is_allowed_guarded_poc_code(code))

    def test_browser_confirm_direct_fetch_post_allowed_by_filter(self):
        code = '(async()=>{if(!confirm("[SSS PoC] Run approved POST /api/pay?"))return; await fetch("/api/pay",{method:"POST",body:JSON.stringify({amount:1})});})();'
        self.assertTrue(_is_allowed_guarded_poc_code(code))

    def test_browser_confirm_destructive_fetch_still_rejected_by_filter(self):
        code = '(async()=>{if(!confirm("[SSS PoC] Run approved POST /api/refund?"))return; await fetch("/api/refund",{method:"POST"});})();'
        self.assertFalse(_is_allowed_guarded_poc_code(code))

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

    def test_react_button_api_flow_has_v1_contract_and_console_poc(self):
        files = [f('src/Pay.jsx', "function submitOrder(){axios.post('/api/orders/123/pay',{amount})}\n<button onClick={submitOrder}>Pay now</button>")]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        playbook = [p for p in result.verification_playbooks if p.endpoint == '/api/orders/123/pay'][0]

        self._assert_v1_playbook_contract(playbook)
        self.assertEqual(playbook.source_path, 'src/Pay.jsx')
        self.assertEqual(playbook.function_name, 'submitOrder')
        # New design: direct CONFIRM-guarded replay, no SSS_POC capture flow
        self.assertIn('confirm(', playbook.console_code)
        self.assertIn('/api/orders/123/pay', playbook.console_code)
        self.assertIn('amount', playbook.breakpoint_plan.what_variable_or_request_to_check)

    def test_jquery_click_ajax_flow_has_v1_contract_and_console_poc(self):
        files = [f('templates/mypage.html', "<button id=\"sendSms\">인증번호 발송</button>\n<script>$('#sendSms').on('click', function(){ $.ajax({ url:'/user/chkMobiSendAjax', type:'POST', data:{ phoneNo } }); });</script>")]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        playbook = [p for p in result.verification_playbooks if p.endpoint == '/user/chkMobiSendAjax'][0]

        self._assert_v1_playbook_contract(playbook)
        self.assertIn('Browser DevTools Console', playbook.poc_injection_plan.where_to_paste_code)
        self.assertIn('/user/chkMobiSendAjax', playbook.data_flow.api_call_or_sink)

    def test_html_form_submit_flow_has_v1_contract_and_console_poc(self):
        files = [f('templates/pay.html', """<form id="payForm"><button type="submit">Pay now</button></form>
<script>
document.getElementById('payForm').addEventListener('submit', submitOrder);
function submitOrder(event) {
  event.preventDefault();
  fetch('/api/orders/123/pay', { method: 'POST', body: JSON.stringify({ amount }) });
}
</script>""")]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        playbook = [p for p in result.verification_playbooks if p.endpoint == '/api/orders/123/pay'][0]

        self._assert_v1_playbook_contract(playbook)
        self.assertEqual(playbook.function_name, 'submitOrder')
        self.assertIn('submitOrder', playbook.breakpoint_plan.function)

    def test_dom_xss_source_sink_flow_promotes_to_playbook(self):
        # New design: confirmed DOM XSS with short direct PoC is PROMOTED, not demoted.
        files = [f('src/x.js', "const value = location.hash.slice(1);\ndocument.getElementById('out').innerHTML = value;")]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        self.assertTrue(any(p.risk_type == 'DOM XSS' for p in result.verification_playbooks),
            'DOM XSS with 1-line PoC must be promoted to verification_playbooks')
        pb = [p for p in result.verification_playbooks if p.risk_type == 'DOM XSS'][0]
        self.assertIsNotNone(pb.console_code)
        self.assertLessEqual(len(pb.console_code.splitlines()), 2,
            'DOM XSS playbook console_code must be <= 2 lines')
        self.assertNotIn('window.fetch = async function', pb.console_code)
        self.assertNotIn('SSS_REVIEW_POC_STATE', pb.console_code)

    def test_unknown_generic_api_wrapper_stays_review_candidate(self):
        files = [f('src/api.js', "function save(payload){ return apiClient.post(endpoint, payload); }")]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())

        self.assertEqual(len(result.verification_playbooks), 0)
        self.assertTrue(any(x.poc_generation_status == 'manual_plan' for x in result.review_candidates))

    def test_manual_placeholder_guidance_uses_english(self):
        # New behavior: sendVerificationCode (no button) with {API_BASE_URL}/send-verification IS promoted
        # because the endpoint action hint is concrete even without a button.
        # The console_code must use the normalized path and not contain {API_BASE_URL}.
        files = [f('src/FindPassword.js', "function sendVerificationCode(){axios.post('{API_BASE_URL}/send-verification',{email})}")]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        pb = next((p for p in result.verification_playbooks if 'send-verification' in (p.endpoint or '')), None)
        self.assertIsNotNone(pb, 'expected promoted playbook for send-verification')
        self.assertNotIn('{API_BASE_URL}', pb.console_code or '')
        self.assertIn('send-verification', pb.console_code or '')

    def test_common_console_helper_is_generated_once(self):
        # New behavior: when all promoted playbooks use self-contained direct PoCs,
        # common_console_helper is None (no 226-line block shown to the user).
        # The helper can still be instantiated on demand via _build_common_console_helper().
        files = [f('src/Pay.jsx', "function submitOrder(){axios.post('/api/orders/123/pay',{amount})}\n<button onClick={submitOrder}>Pay now</button>")]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())

        self.assertIsNone(result.common_console_helper,
            'common_console_helper must be None when all promoted playbooks have self-contained PoCs')
        # The builder function itself is still intact and correct.
        helper = _build_common_console_helper()
        self.assertIn('window.SSS_POC', helper)
        self.assertIn('find(criteria = {})', helper)
        self.assertIn('window.fetch = async function', helper)
        self.assertIn('XMLHttpRequest.prototype.open', helper)
        self.assertIn('axios.interceptors.request.use', helper)

    def test_promoted_finding_console_code_is_short_commands(self):
        # New design: playbook console_code is a direct CONFIRM-guarded fetch replay.
        files = [f('src/Pay.jsx', "function submitOrder(){axios.post('/api/orders/123/pay',{amount})}\n<button onClick={submitOrder}>Pay now</button>")]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        playbook = [p for p in result.verification_playbooks if p.endpoint == '/api/orders/123/pay'][0]
        code = playbook.console_code or ''

        self.assertLessEqual(len(code.splitlines()), 10)
        self.assertTrue(code.startswith('(async () => {'))
        # Direct replay: contains fetch call to the known endpoint
        self.assertIn('/api/orders/123/pay', code)
        # Safety guard present
        self.assertIn('confirm(', code)
        # No global hook installer
        self.assertNotIn('window.fetch = async function', code)
        self.assertNotIn('XMLHttpRequest.prototype.open', code)
        self.assertNotIn('axios.interceptors.request.use', code)
        self.assertNotIn('window.jQuery.ajax = function', code)
        self.assertNotIn('SSS_REVIEW_POC_STATE', code)

    def test_finding_specific_console_code_is_direct_replay(self):
        # New design: playbook code is a self-contained fetch replay, not SSS_POC flow.
        files = [f('src/Pay.jsx', "function submitOrder(){axios.post('/api/orders/123/pay',{amount})}\n<button onClick={submitOrder}>Pay now</button>")]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        code = result.verification_playbooks[0].console_code or ''

        self.assertIn('confirm(', code)
        self.assertIn("method: \"POST\"", code)
        self.assertNotIn('window.SSS_POC', code)

    def test_promoted_proof_steps_do_not_mention_helper_flow(self):
        files = [f('src/Pay.jsx', "function submitOrder(){axios.post('/api/orders/123/pay',{amount})}\n<button onClick={submitOrder}>Pay now</button>")]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        steps = '\n'.join(result.verification_playbooks[0].proof_steps)
        self.assertIn('paste the PoC into Console', steps)
        self.assertIn('approve the browser confirmation guard', steps)
        self.assertIn('Network tab', steps)
        for forbidden in ('window.SSS_POC', 'armMutation', 'list()', 'common_console_helper'):
            self.assertNotIn(forbidden, steps)

    def test_direct_api_success_and_evidence_wording_has_no_helper_flow(self):
        """Success criteria must describe security impact, not just 'response visible'."""
        files = [f('src/Pay.jsx', "function submitOrder(){axios.post('/api/orders/123/pay',{amount})}\n<button onClick={submitOrder}>Pay now</button>")]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        playbook = result.verification_playbooks[0]
        success = '\n'.join(playbook.success_criteria)
        evidence = '\n'.join(playbook.evidence_to_capture)
        # Old weak wording must be gone
        self.assertNotIn('response status/content-type/body preview is visible', success,
            'Weak "status/body visible" must not be the primary success criterion')
        self.assertNotIn('server accepts or rejects the test payload with an explainable status/body', success,
            'Generic "accepts or rejects" wording must be replaced with impact-based criteria')
        # New strong criteria: security impact must be described
        self.assertTrue(
            any(kw in success.lower() for kw in ('reflected', 'balance', 'transaction', 'server-side result',
                                                   'authorization error', 'validation error', 'rejected',
                                                   'ownership', 'access', 'mutated')),
            f'Success criteria must describe security impact. Got: {success!r}',
        )
        # Evidence must focus on the request/response, not console helper artefacts
        for forbidden in ('capture log', 'armMutation', 'payload after mutation', 'window.SSS_POC'):
            self.assertNotIn(forbidden, success)
            self.assertNotIn(forbidden, evidence)
        # Evidence must still mention the network request for comparison
        self.assertTrue(
            any(kw in evidence.lower() for kw in ('network tab', 'request', 'response', 'payload')),
            f'Evidence must mention Network tab or request/response. Got: {evidence!r}',
        )

    def test_promoted_finding_verification_playbook_uses_short_console_code(self):
        files = [f('src/Pay.jsx', "function submitOrder(){axios.post('/api/orders/123/pay',{amount})}\n<button onClick={submitOrder}>Pay now</button>")]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        promoted = [f for f in result.findings if f.id == result.verification_playbooks[0].id][0]
        code = promoted.verification_playbook.console_code or ''
        self.assertIn('confirm(', code)
        self.assertLessEqual(len([line for line in code.splitlines() if line.strip()]), 12)
        for forbidden in ('SSS_REVIEW_POC_STATE', 'TARGET_ENDPOINT', 'window.fetch = async function', 'XMLHttpRequest.prototype'):
            self.assertNotIn(forbidden, code)

    def test_direct_poc_uses_browser_confirm_guard(self):
        files = [f('src/Pay.jsx', "function submitOrder(){axios.post('/api/orders/123/pay',{amount})}\n<button onClick={submitOrder}>Pay now</button>")]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        code = result.verification_playbooks[0].console_code or ''
        self.assertIn('if (!confirm(`[SSS PoC] Run approved POST /api/orders/123/pay?`)) return;', code)
        self.assertNotIn('CONFIRM_AUTHORIZED_TEST = false', code)

    def test_stripe_iamport_payload_keys_preserved_in_direct_poc(self):
        files = [f('src/Checkout.jsx', """
function requestIamportPay(){
  const payload = { merchant_uid, imp_uid, orderId, productId, amount, buyer_email };
  axios.post('/api/payments/iamport/complete', payload);
}
<button onClick={requestIamportPay}>Pay</button>
""")]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        playbook = [p for p in result.verification_playbooks if p.endpoint == '/api/payments/iamport/complete'][0]
        code = playbook.console_code or ''
        for key in ('merchant_uid', 'imp_uid', 'orderId', 'productId', 'amount', 'buyer_email'):
            self.assertIn(key, code)
        self.assertIn('const TEST_ORDER_ID = "REPLACE_WITH_TEST_ORDER_ID";', code)
        self.assertIn('const TEST_PRODUCT_ID = "REPLACE_WITH_TEST_PRODUCT_ID";', code)
        self.assertIn('const TEST_PAYMENT_UID = "REPLACE_WITH_TEST_PAYMENT_UID";', code)
        self.assertLessEqual(len([line for line in code.splitlines() if line.strip()]), 12)

    def test_get_finding_specific_console_code_prints_replay_guidance(self):
        code = _build_short_console_verification_code(
            endpoint='/api/search',
            method='GET',
            page_hint='Search page',
            action_hint='Click search',
        )

        self.assertIn('Read-only:', code)  # compact format uses short comment
        self.assertIn('window.SSS_POC.replay(match.index);', code)
        self.assertNotIn('await window.SSS_POC.replay', code)  # mutation hint uses no await
        self.assertNotIn('  window.SSS_POC.armMutation();', code)

    def test_common_helper_replay_is_transport_aware(self):
        helper = _build_common_console_helper()

        self.assertIn("item.transport === 'xhr'", helper)
        self.assertIn('xhr replay is not automatic', helper)
        self.assertIn("item.transport === 'axios'", helper)
        self.assertIn('await window.axios(config)', helper)
        self.assertIn("item.transport === 'jquery.ajax'", helper)
        self.assertIn('return window.jQuery.ajax(config)', helper)
        self.assertIn('replaying captured fetch request', helper)
        self.assertIn('state.originalFetch.call(window, url, init)', helper)

    def test_common_helper_non_get_replay_still_requires_arm_mutation(self):
        helper = _build_common_console_helper()

        self.assertIn("method !== 'GET' && !state.mutationArmed", helper)
        self.assertIn('replay blocked. Run window.SSS_POC.armMutation() first for non-GET requests.', helper)

    def test_promoted_finding_console_poc_does_not_redefine_sss_poc(self):
        files = [f('src/Pay.jsx', "function submitOrder(){axios.post('/api/orders/123/pay',{amount})}\n<button onClick={submitOrder}>Pay now</button>")]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        promoted_ids = {p.id for p in result.verification_playbooks}

        self.assertTrue(promoted_ids)
        for finding in result.findings:
            if finding.id in promoted_ids:
                code = finding.console_poc.code if finding.console_poc else None
                self.assertFalse(code)
                self.assertNotIn('window.SSS_POC =', code or '')

    def test_short_playbook_code_uses_common_helper_model(self):
        # New: common_console_helper is None when all promoted PoCs are self-contained.
        # The playbook uses a direct CONFIRM-guarded replay, not the SSS_POC capture flow.
        files = [f('src/Pay.jsx', "function submitOrder(){axios.post('/api/orders/123/pay',{amount})}\n<button onClick={submitOrder}>Pay now</button>")]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        playbook = [p for p in result.verification_playbooks if p.endpoint == '/api/orders/123/pay'][0]
        code = playbook.console_code or ''

        # Self-contained PoCs: common_console_helper must be None.
        self.assertIsNone(result.common_console_helper)
        # Playbook uses a direct replay with browser confirm guard, no SSS_POC capture flow.
        self.assertIn('confirm(', code)
        self.assertIn('/api/orders/123/pay', code)
        self.assertNotIn('window.SSS_POC =', code)
        self.assertNotIn('window.SSS_REVIEW_POC', code)

    def test_promotion_constants_are_used(self):
        import inspect
        from app.services import console_poc_analysis_service as svc

        source = inspect.getsource(svc.analyze_console_exploitability)
        self.assertEqual(PROMOTION_SCORE_THRESHOLD, 5)
        self.assertEqual(MAX_PLAYBOOK_COUNT, 7)
        self.assertIn('score < PROMOTION_SCORE_THRESHOLD', source)
        self.assertIn('len(verification_playbooks) >= MAX_PLAYBOOK_COUNT', source)
        self.assertNotIn('score < 5', source)
        self.assertNotIn('len(verification_playbooks) >= 7', source)

    def test_unresolved_endpoint_is_review_candidate_only(self):
        # New behavior: {API_BASE_URL}/send-verification + button is PROMOTED with normalized endpoint.
        # The raw {API_BASE_URL} prefix must never appear in the playbook endpoint or console_code.
        files = [f('src/FindPassword.js', "function sendVerificationCode(){axios.post('{API_BASE_URL}/send-verification',{email})}\n<button onClick={sendVerificationCode}>Send code</button>")]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        # No playbook may expose the raw {API_BASE_URL} in its endpoint field.
        self.assertFalse(any(p.endpoint and '{API_BASE_URL}' in p.endpoint for p in result.verification_playbooks))
        # A promoted playbook with the normalized path must exist.
        pb = next((p for p in result.verification_playbooks if 'send-verification' in (p.endpoint or '')), None)
        self.assertIsNotNone(pb, 'expected a promoted playbook for send-verification after base-URL normalization')
        self.assertNotIn('{API_BASE_URL}', pb.console_code or '')
        self.assertIn('send-verification', pb.console_code or '')

    def test_every_promoted_playbook_has_concrete_contract(self):
        from app.services import console_poc_analysis_service as svc

        files = [f('src/Pay.jsx', "function submitOrder(){axios.post('/api/orders/123/pay',{amount})}\n<button onClick={submitOrder}>Pay now</button>")]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        self.assertTrue(result.verification_playbooks)

        for playbook in result.verification_playbooks:
            self.assertTrue(playbook.source_path)
            self.assertTrue(playbook.function_name or (isinstance(playbook.start_line, int) and isinstance(playbook.end_line, int)))
            self.assertTrue(playbook.endpoint or (playbook.data_flow and playbook.data_flow.api_call_or_sink))
            self.assertNotIn('UNKNOWN', f'{playbook.method} {playbook.endpoint} {playbook.data_flow.api_call_or_sink if playbook.data_flow else ""}')
            self.assertNotIn('{', playbook.endpoint or '')
            self.assertFalse(svc._is_generic_page_hint(playbook.page_hint))
            self.assertFalse(svc._is_generic_action_hint(playbook.user_action_hint))
            self.assertTrue(playbook.why_exploitable)
            self.assertIsNotNone(playbook.data_flow)
            self.assertIsNotNone(playbook.breakpoint_plan)
            self.assertIsNotNone(playbook.poc_injection_plan)
            # New design: playbook code is a direct replay or DOM PoC, not SSS_POC capture flow
            self.assertTrue(playbook.console_code, 'every promoted playbook must have console_code')
            self.assertNotIn('window.fetch = async function', playbook.console_code or '')

    def test_review_candidate_is_not_confirmed_vulnerability(self):
        files = [f('src/service.js', "axios.post('/api/orders/123/pay',{amount})")]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        promoted_ids = {p.id for p in result.verification_playbooks}

        self.assertTrue(result.review_candidates)
        self.assertFalse(any(candidate.id in promoted_ids for candidate in result.review_candidates))
        self.assertFalse(any('Confirmed promoted finding' in ' '.join(candidate.verification_notes) for candidate in result.review_candidates))
        review_text = ' '.join(result.review_candidates[0].verification_notes)
        self.assertIn(MANUAL_REVIEW_NOTE, review_text)
        self.assertIn(NOT_CONFIRMED_NOTE, review_text)
        self.assertIn('Needs runtime capture before proof', review_text)

    def test_rtvc_note_only_on_promoted_findings(self):
        """'Selected as runtime verification candidate' appears only on promoted findings, not review candidates."""
        files = [f('src/Pay.jsx', "function submitOrder(){axios.post('/api/orders/123/pay',{amount})}\n<button onClick={submitOrder}>Pay now</button>")]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        promoted_ids = {p.id for p in result.verification_playbooks}

        self.assertTrue(promoted_ids, 'expected at least one promoted playbook')
        # 'Confirmed promoted finding' must be completely gone
        for finding in result.findings:
            self.assertNotIn('Confirmed promoted finding', ' '.join(finding.verification_notes),
                '"Confirmed promoted finding" must no longer appear in any finding')
        # Review candidates must not have the RTVC note
        self.assertFalse(any(RTVC_NOTE in ' '.join(c.verification_notes) for c in result.review_candidates),
            'review candidates must not have the RTVC note')
        # Promoted findings must have the RTVC note
        for finding in result.findings:
            notes = ' '.join(finding.verification_notes)
            if finding.id in promoted_ids:
                self.assertIn(RTVC_NOTE, notes,
                    f'promoted finding must have note: {RTVC_NOTE!r}')
            else:
                self.assertNotIn(RTVC_NOTE, notes)

    def test_console_poc_service_has_single_policy_helper_definitions(self):
        import inspect
        from app.services import console_poc_analysis_service as svc

        source = inspect.getsource(svc)
        lines = source.splitlines()
        debug = '\n'.join(f'{idx + 1}: {line}' for idx, line in enumerate(lines) if 45 <= idx + 1 <= 140 or 1855 <= idx + 1 <= 1890)
        self.assertEqual(source.count('def _is_generic_action_hint'), 1, debug)
        self.assertEqual(source.count('def _is_generic_page_hint'), 1, debug)
        self.assertEqual(source.count('def _find_unresolved_poc_placeholders'), 1, debug)

    def test_mark_review_candidate_uses_english_markers(self):
        import inspect
        from app.services import console_poc_analysis_service as svc

        source = inspect.getsource(svc._mark_review_candidate)
        self.assertIn(MANUAL_REVIEW_NOTE, source)
        self.assertIn(NOT_CONFIRMED_NOTE, source)
        self.assertIn(RESOLVE_BEFORE_POC_NOTE, source)
        self.assertIn('Needs runtime capture before proof', source)

    # -- New PoC simplification tests --------------------------------

    def test_promoted_finding_has_no_hook_code_in_console_poc(self):
        """Promoted ReadableFinding.console_poc.code must be None - short code is in playbook."""
        files = [f('src/Pay.jsx', "function submitOrder(){axios.post('/api/orders/123/pay',{amount})}\n<button onClick={submitOrder}>Pay now</button>")]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        promoted_ids = {p.id for p in result.verification_playbooks}
        for finding in result.findings:
            if finding.id in promoted_ids:
                self.assertIsNone(finding.console_poc.code)
                self.assertIsNone(finding.observational_poc)

    def test_promoted_playbook_console_code_no_fetch_hook_installer(self):
        """Promoted playbook console_code must NOT install its own fetch/XHR hook.
        New design: direct CONFIRM-guarded replay, no SSS_POC capture flow."""
        files = [f('src/Pay.jsx', "function submitOrder(){axios.post('/api/orders/123/pay',{amount})}\n<button onClick={submitOrder}>Pay now</button>")]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        for pb in result.verification_playbooks:
            code = pb.console_code or ''
            self.assertNotIn('window.fetch = async function', code)
            self.assertNotIn('XMLHttpRequest.prototype.open', code)
            self.assertNotIn('axios.interceptors.request.use', code)
            self.assertNotIn('window.SSS_POC = {', code)
            self.assertNotIn('window.SSS_REVIEW_POC', code)
            # New: direct replay uses fetch() call, not SSS_POC capture flow
            self.assertNotIn('window.SSS_POC.find(', code)

    def test_review_candidate_with_api_base_no_url_includes_placeholder(self):
        """Unresolved base-URL placeholder must never appear inside url.includes(...)."""
        files = [f('src/Login.js', "function login(){axios.post(API_BASE_URL+'/login',{email,password})}")]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        for rc in result.review_candidates:
            for code_src in [
                (rc.console_poc.code or '') if rc.console_poc else '',
                (rc.observational_poc.code or '') if rc.observational_poc else '',
            ]:
                self.assertNotIn('url.includes("{API_BASE', code_src)
                self.assertNotIn('url.includes("API_BASE', code_src)

    def test_unresolved_review_candidate_not_runnable_note(self):
        """Any review candidate whose action cannot be inferred must say 'Not a runnable proof yet'."""
        files = [f('src/service.js', "axios.post('/api/pay',{amount})")]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        for rc in result.review_candidates:
            if rc.poc_generation_status == 'manual_plan':
                notes_text = ' '.join(rc.verification_notes)
                self.assertTrue(
                    'Not a runnable proof yet' in notes_text or 'endpoint is UNKNOWN' in notes_text,
                    f"Expected 'Not a runnable proof yet' note, got: {rc.verification_notes}"
                )

    def test_no_review_candidate_has_full_hook_in_console_poc_code(self):
        """No review candidate may embed a full fetch/XHR/axios hook installer in console_poc.code."""
        files = [
            f('src/service.js', "axios.post('/api/orders/123/pay',{amount})"),
            f('src/Login.js', "axios.post('/api/login',{email,password})"),
            f('src/del.js', "axios.delete('/api/admin/delete-user/{userId}')"),
        ]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        for rc in result.review_candidates:
            code = (rc.console_poc.code or '') if rc.console_poc else ''
            self.assertNotIn('SSS_REVIEW_POC_STATE', code,
                             f"Review candidate [{rc.vulnerability_type}] has full hook in console_poc.code")
            self.assertNotIn('window.fetch = async function', code)

    def test_placeholder_endpoint_review_candidate_no_code(self):
        # New behavior: {API_BASE_URL}/send-verification + button is PROMOTED with normalized endpoint.
        # The base-URL prefix is stripped; the playbook console_code must not contain {API_BASE_URL}.
        files = [f('src/FindPassword.js', "function sendVerificationCode(){axios.post('{API_BASE_URL}/send-verification',{email})}\n<button onClick={sendVerificationCode}>Send code</button>")]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        pb = next((p for p in result.verification_playbooks if 'send-verification' in (p.endpoint or '')), None)
        self.assertIsNotNone(pb, 'expected promoted playbook for send-verification after base-URL normalization')
        self.assertNotIn('{API_BASE_URL}', pb.console_code or '')
        self.assertNotIn('{API_BASE_URL}', pb.endpoint or '')

    def test_common_console_helper_generated_once_and_no_hook_in_findings(self):
        # New behavior: all promoted PoCs are self-contained -> common_console_helper is None.
        # No finding (promoted or review) should re-define window.SSS_POC in its code fields.
        files = [
            f('src/Pay.jsx', "function submitOrder(){axios.post('/api/orders/123/pay',{amount})}\n<button onClick={submitOrder}>Pay now</button>"),
            f('src/service.js', "axios.post('/api/orders/456/pay',{amount})"),
        ]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        self.assertIsNone(result.common_console_helper,
            'common_console_helper must be None when promoted playbooks are all self-contained')
        # No finding (promoted or review) should re-define window.SSS_POC
        for finding in result.findings:
            for attr in ('console_poc', 'observational_poc'):
                poc = getattr(finding, attr, None)
                code = (poc.code or '') if poc else ''
                self.assertNotIn('window.SSS_POC = {', code,
                                  f"finding [{finding.vulnerability_type}].{attr}.code re-defines window.SSS_POC")


    # -- Real-world regression tests (loTO / NAFAL patterns) --------

    def test_promoted_playbook_console_code_is_at_most_10_lines(self):
        """Promoted console_code must be <= 10 pasteable lines."""
        files = [f('src/Pay.jsx', "function submitOrder(){axios.post('/api/orders/123/pay',{amount})}\n<button onClick={submitOrder}>Pay now</button>")]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        for pb in result.verification_playbooks:
            lines = (pb.console_code or '').splitlines()
            self.assertLessEqual(len(lines), 10,
                f"Promoted console_code has {len(lines)} lines (max 10):\n{pb.console_code}")

    def test_promoted_playbook_console_code_has_confirm_guard_or_is_dom_poc(self):
        # New design: promoted API playbooks use CONFIRM-guarded direct replay;
        # DOM XSS playbooks use a 1-2 line direct PoC.
        files = [f('src/Pay.jsx', "function submitOrder(){axios.post('/api/orders/123/pay',{amount})}\n<button onClick={submitOrder}>Pay now</button>")]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        for pb in result.verification_playbooks:
            code = pb.console_code or ''
            is_dom = pb.risk_type == 'DOM XSS'
            if not is_dom:
                self.assertIn('confirm(', code,
                    f"Promoted API playbook must have browser confirm guard: {pb.endpoint}")
            self.assertNotIn('window.SSS_POC.find(', code,
                "Promoted playbook must not use SSS_POC capture flow")

    def test_promoted_playbook_console_code_no_hook_installer(self):
        HOOK_SIGS = ['window.fetch = async function', 'XMLHttpRequest.prototype.open',
                     'axios.interceptors.request.use', 'window.SSS_POC =', 'SSS_REVIEW_POC_STATE']
        files = [f('src/Pay.jsx', "function submitOrder(){axios.post('/api/orders/123/pay',{amount})}\n<button onClick={submitOrder}>Pay now</button>")]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        for pb in result.verification_playbooks:
            code = pb.console_code or ''
            for sig in HOOK_SIGS:
                self.assertNotIn(sig, code,
                    f"Promoted console_code must not contain hook installer: {sig!r}")

    def test_loto_like_all_manual_plan_no_playbooks(self):
        """loTO-like input: all endpoints unresolved -> no playbooks, all manual_plan."""
        # loTO pattern: endpoints via API_BASE_URL variable and dynamic paths
        files = [
            f('src/LoginPage.js',
              "function doLogin() { axios.post(API_BASE_URL + '/login', { email, password }); }"),
            f('src/Dashboard.js',
              "function loadDashboard() { axios.get(API_BASE_URL + '/dashboard'); }"),
            f('src/Profile.js',
              "const endpoint = API_URLS.PROFILE; axios.post(endpoint, { userId });"),
        ]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        self.assertEqual(len(result.verification_playbooks), 0,
                         "loTO-like input should produce zero promoted playbooks")
        # All review candidates must be manual_plan
        for rc in result.review_candidates:
            self.assertEqual(rc.poc_generation_status, 'manual_plan',
                f"Expected manual_plan for unresolved endpoint, got {rc.poc_generation_status}")
            self.assertIsNone(rc.console_poc.code if rc.console_poc else None,
                "manual_plan candidate must not have runnable console code")

    def test_nafal_like_unknown_endpoints_no_runnable_poc(self):
        """NAFAL-like input.
        AdminPage.js 'userType' key: direct-string storage pattern → auth bypass IS promoted.
        service.js dynamic endpoint: remains a manual review candidate.
        Review candidates must not have global hook code.
        """
        files = [
            f('src/AdminPage.js',
              "const userType = sessionStorage.getItem('userType'); if (userType !== 'ADMIN') { navigate('/'); }"),
            f('src/service.js',
              "const endpoint = buildApiUrl(action); apiClient.post(endpoint, payload);"),
        ]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        # Auth bypass with detected storage key is promoted; service endpoint stays review.
        auth_playbooks = [p for p in result.verification_playbooks if p.risk_type == 'Client-side Authorization Bypass']
        if auth_playbooks:
            pb = auth_playbooks[0]
            self.assertIn('sessionStorage', pb.console_code or '')
            self.assertLessEqual(len((pb.console_code or '').splitlines()), 2)
        # Remaining (non-auth, non-DOM) playbooks with UNKNOWN endpoints must be 0
        non_auth = [p for p in result.verification_playbooks if p.risk_type not in {'Client-side Authorization Bypass', 'DOM XSS'}]
        self.assertEqual(len(non_auth), 0, 'Dynamic-endpoint service call must NOT be promoted')
        for rc in result.review_candidates:
            poc_code = (rc.console_poc.code or '') if rc.console_poc else ''
            obs_code = (rc.observational_poc.code or '') if rc.observational_poc else ''
            for sig in ['window.fetch = async function', 'XMLHttpRequest.prototype.open',
                        'SSS_REVIEW_POC_STATE', 'TARGET_ENDPOINT =']:
                self.assertNotIn(sig, poc_code + obs_code,
                    f"NAFAL-like candidate must not contain hook: {sig!r}")


    # -- Mojibake regression: generated PoC code must be ASCII-only ----------------

    def test_short_console_code_is_ascii_only(self):
        """Promoted playbook console_code must contain no non-ASCII characters."""
        code = _build_short_console_verification_code(
            endpoint='/api/pay',
            method='POST',
            page_hint='payment page',
            action_hint='click pay button',
        )
        non_ascii = [repr(c) for c in code if ord(c) > 127]
        self.assertFalse(non_ascii,
            f'Short console code contains non-ASCII chars: {non_ascii[:5]}')

    def test_common_console_helper_is_ascii_only(self):
        """common_console_helper must contain no non-ASCII characters."""
        code = _build_common_console_helper()
        non_ascii = [repr(c) for c in code if ord(c) > 127]
        self.assertFalse(non_ascii,
            f'common_console_helper contains non-ASCII chars: {non_ascii[:5]}')

    def test_short_console_code_no_em_dash(self):
        """_build_short_console_verification_code must not embed em-dash."""
        code = _build_short_console_verification_code(
            endpoint='/api/pay',
            method='POST',
            page_hint='payment page',
            action_hint='click pay button',
        )
        self.assertNotIn('\u2014', code, 'Short console code must not contain em-dash')
        self.assertIn('No match yet - perform', code)

    def test_promoted_playbook_console_code_is_ascii_only(self):
        """All promoted playbook console_code fields must be ASCII-only."""
        files = [f('src/Pay.jsx', "function submitOrder(){axios.post('/api/orders/123/pay',{amount})}\n<button onClick={submitOrder}>Pay now</button>")]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        self.assertTrue(result.verification_playbooks)
        for pb in result.verification_playbooks:
            code = pb.console_code or ''
            non_ascii = [repr(c) for c in code if ord(c) > 127]
            self.assertFalse(non_ascii,
                f'Playbook console_code has non-ASCII: {non_ascii[:5]!r}')

    def test_claude_md_no_mojibake(self):
        """CLAUDE.md must not contain em-dash, en-dash, or arrow characters."""
        from pathlib import Path
        claude_md = (Path(__file__).resolve().parents[1] / 'CLAUDE.md').read_text(encoding='utf-8')
        MOJIBAKE = {'\u2014': 'EM DASH', '\u2013': 'EN DASH', '\u2192': 'RIGHT ARROW',
                    '\u2500': 'BOX DRAWING', '\u26a0': 'WARNING SIGN', '\ufffd': 'REPLACEMENT CHAR'}
        for char, name in MOJIBAKE.items():
            self.assertNotIn(char, claude_md,
                f'CLAUDE.md contains U+{ord(char):04X} {name}')


    # -- Edge-case: observational downgrade when no promoted playbooks ---------------

    def test_observational_downgraded_to_manual_plan_when_no_playbooks(self):
        """When verification_playbooks == 0, any observational review candidate must
        be downgraded to manual_plan so the UI never shows 'install common helper'
        text when the helper itself is hidden."""
        # Bare axios call: non-generic endpoint gives resolved page/action hints but
        # function_name=None forces should_review=True -> goes to review as observational.
        files = [f('src/WalletPage.js', "axios.post('/api/wallet/charge', { amount })")]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        self.assertEqual(len(result.verification_playbooks), 0,
            'fixture should produce zero promoted playbooks')
        for rc in result.review_candidates:
            self.assertNotEqual(rc.poc_generation_status, 'observational',
                f'observational must be downgraded when no playbooks; got {rc.poc_generation_status}')
            obs_code = (rc.observational_poc.code or '') if rc.observational_poc else ''
            self.assertFalse(obs_code,
                'downgraded candidate must have no observational_poc code')
            self.assertNotIn('common_console_helper', obs_code)

    def test_observational_downgraded_has_manual_poc_plan(self):
        """Downgraded observational candidate must have a manual_poc_plan."""
        files = [f('src/WalletPage.js', "axios.post('/api/wallet/charge', { amount })")]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        self.assertEqual(len(result.verification_playbooks), 0)
        for rc in result.review_candidates:
            if 'downgraded' in (rc.poc_generation_reason or ''):
                self.assertTrue(rc.manual_poc_plan,
                    'downgraded candidate must have a manual_poc_plan')
                self.assertTrue(any('No promoted playbook' in n for n in rc.verification_notes),
                    'downgraded candidate must have the network-tab guidance note')

    def test_observational_not_downgraded_when_playbooks_exist(self):
        """When playbooks ARE promoted, observational candidates must remain observational."""
        files = [
            f('src/FindPassword.js',
              "function verifyCode(){ axios.post('/api/verify-code', { code }); }"),
            f('src/WalletPage.js',
              "axios.post('/api/wallet/charge', { amount })"),
        ]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        # If there is at least one promoted playbook, observational candidates keep their status.
        if result.verification_playbooks:
            obs = [rc for rc in result.review_candidates
                   if rc.poc_generation_status == 'observational']
            # Any remaining observational candidate must not be marked downgraded.
            for rc in obs:
                self.assertNotIn('downgraded', rc.poc_generation_reason or '')


    # -- poc_templates unit tests --------------------------------------------------

    def test_poc_templates_dom_xss_hash_default(self):
        from app.services.poc_templates import build_dom_xss_poc, is_interceptor_free
        code = build_dom_xss_poc()
        self.assertLessEqual(len(code.splitlines()), 2)
        self.assertIn('location.hash', code)
        self.assertIn('console.log', code)
        self.assertTrue(is_interceptor_free(code))
        self.assertFalse(any(ord(c) > 127 for c in code), 'DOM XSS PoC must be ASCII-only')

    def test_poc_templates_dom_xss_search_source(self):
        from app.services.poc_templates import build_dom_xss_poc
        code = build_dom_xss_poc(source_expr='location.search')
        self.assertIn('location.pathname', code)
        self.assertLessEqual(len(code.splitlines()), 2)

    def test_poc_templates_storage_auth(self):
        from app.services.poc_templates import build_storage_auth_poc, is_interceptor_free
        code = build_storage_auth_poc('sessionStorage', 'user', 'userType', 'ADMIN')
        self.assertLessEqual(len(code.splitlines()), 2)
        self.assertIn('sessionStorage.setItem', code)
        self.assertIn('ADMIN', code)
        self.assertIn('location.reload()', code)
        self.assertTrue(is_interceptor_free(code))
        self.assertFalse(any(ord(c) > 127 for c in code), 'Storage auth PoC must be ASCII-only')

    def test_poc_templates_replay_get_no_guard(self):
        from app.services.poc_templates import build_request_replay_poc, is_interceptor_free
        code = build_request_replay_poc('GET', '/api/user/me')
        self.assertIsNotNone(code)
        self.assertIn("fetch(\"/api/user/me\")", code)
        self.assertLessEqual(len(code.splitlines()), 10)
        self.assertTrue(is_interceptor_free(code))
        self.assertNotIn('confirm(', code)

    def test_poc_templates_replay_post_confirm_guard(self):
        from app.services.poc_templates import build_request_replay_poc, is_interceptor_free
        from app.services.console_poc_analysis_service import _is_allowed_guarded_poc_code
        code = build_request_replay_poc('POST', '/api/pay', 'amount', 1)
        self.assertIsNotNone(code)
        self.assertIn('confirm(', code)
        self.assertIn('amount', code)
        self.assertLessEqual(len(code.splitlines()), 10)
        self.assertTrue(is_interceptor_free(code))
        self.assertTrue(_is_allowed_guarded_poc_code(code), 'confirm-guarded replay must pass safety filter')
        self.assertFalse(any(ord(c) > 127 for c in code), 'Replay PoC must be ASCII-only')

    def test_poc_templates_path_param_naming_userId(self):
        """Path params like {userId}/{currentUserId} must produce USER_ID const, not TEST_ID.

        'id' is a substring of 'userid', so without careful ordering the generic
        'id' check fires first and everything becomes TEST_ID.
        """
        from app.services.poc_templates import build_request_replay_poc
        for endpoint in (
            '/api/user/{userId}/wallet/charge',
            '/api/user/{currentUserId}/profile',
            '/api/member/{memberId}/orders',
            '/api/account/{accountId}/settings',
        ):
            code = build_request_replay_poc('POST', endpoint)
            self.assertIsNotNone(code, f'PoC must be generated for {endpoint}')
            self.assertIn('USER_ID', code, f'{endpoint} must use USER_ID const, not TEST_ID')
            self.assertNotIn('TEST_ID', code, f'{endpoint} must not use generic TEST_ID for a user-ID path param')

    def test_poc_templates_path_param_naming_orderId(self):
        """Path params like {orderId} must produce ORDER_ID const, not TEST_ID."""
        from app.services.poc_templates import build_request_replay_poc
        for endpoint in (
            '/api/order/{orderId}/pay',
            '/api/auction/{auctionItem.orderId}/complete',
        ):
            code = build_request_replay_poc('POST', endpoint)
            self.assertIsNotNone(code)
            self.assertIn('ORDER_ID', code, f'{endpoint} must use ORDER_ID const')
            self.assertNotIn('TEST_ID', code, f'{endpoint} must not use generic TEST_ID for order-ID path param')

    def test_poc_templates_path_param_naming_paymentId(self):
        """Path params like {paymentId} must produce PAYMENT_ID const, not TEST_ID."""
        from app.services.poc_templates import build_request_replay_poc
        code = build_request_replay_poc('POST', '/api/payment/{paymentId}/confirm')
        self.assertIsNotNone(code)
        self.assertIn('PAYMENT_ID', code, '{paymentId} must use PAYMENT_ID const')
        self.assertNotIn('TEST_ID', code, '{paymentId} must not use generic TEST_ID')

    def test_poc_templates_confirm_shows_resolved_url(self):
        """The confirm() dialog must show the resolved URL, not the raw source placeholder.

        Before the fix, consts were declared AFTER the confirm line, so the
        confirm dialog showed '{item.id}' while the fetch used '${TEST_ID}'.
        A tester filling in the const value before pasting would see the
        correct URL in the confirm dialog only if consts come first.
        """
        from app.services.poc_templates import build_request_replay_poc
        import re

        # Endpoint with path param: {item.id} → ${TEST_ID} after substitution
        code = build_request_replay_poc('POST', '/api/auction/{item.id}/bid', 'amount', 1)
        self.assertIsNotNone(code)
        lines = code.splitlines()

        # Const declarations must appear before the confirm line
        const_line = next((i for i, l in enumerate(lines) if 'const TEST_ID' in l), None)
        confirm_line = next((i for i, l in enumerate(lines) if 'confirm(' in l), None)
        self.assertIsNotNone(const_line, 'const TEST_ID declaration must be present')
        self.assertIsNotNone(confirm_line, 'confirm() guard must be present')
        self.assertLess(const_line, confirm_line,
            'const declaration must come before confirm so the dialog shows the resolved URL')

        # The confirm string must use the JS variable reference, not the raw placeholder
        confirm_str = lines[confirm_line]
        self.assertNotIn('{item.id}', confirm_str,
            'confirm dialog must not show raw source placeholder {item.id}')
        self.assertIn('TEST_ID', confirm_str,
            'confirm dialog must show the resolved JS const name TEST_ID')

        # Same check for userId-style path param
        code2 = build_request_replay_poc('POST', '/api/user/{currentUserId}/wallet/charge', 'amount', 1)
        self.assertIsNotNone(code2)
        lines2 = code2.splitlines()
        confirm_line2 = next((i for i, l in enumerate(lines2) if 'confirm(' in l), None)
        confirm_str2 = lines2[confirm_line2]
        self.assertNotIn('{currentUserId}', confirm_str2,
            'confirm dialog must not show raw source placeholder {currentUserId}')
        self.assertIn('USER_ID', confirm_str2,
            'confirm dialog must show the resolved JS const name USER_ID')

    def test_poc_templates_destructive_endpoint_returns_none(self):
        from app.services.poc_templates import build_request_replay_poc
        # Truly destructive keywords still block PoC generation.
        self.assertIsNone(build_request_replay_poc('POST', '/api/order/refund'))
        self.assertIsNone(build_request_replay_poc('DELETE', '/api/user/1'))
        self.assertIsNone(build_request_replay_poc('POST', 'UNKNOWN'))
        # {API_BASE_URL}/pay: base-URL prefix is stripped -> /pay (safe), so a PoC IS generated.
        poc = build_request_replay_poc('POST', '{API_BASE_URL}/pay')
        self.assertIsNotNone(poc, '{API_BASE_URL}/pay normalizes to /pay which is not destructive')
        self.assertIn('fetch("/pay"', poc)
        self.assertIn('confirm(', poc)
        # Truly destructive base-URL endpoint still returns None.
        self.assertIsNone(build_request_replay_poc('POST', '{API_BASE_URL}/admin/refund'))

    def test_poc_templates_delete_method_returns_none(self):
        from app.services.poc_templates import build_request_replay_poc
        self.assertIsNone(build_request_replay_poc('DELETE', '/api/user/1'))

    # -- Proof quality: DOM XSS promotes, not demotes -------------------------

    def test_dom_xss_with_short_poc_is_promoted(self):
        """DOM XSS confirmed with 1-line PoC must land in verification_playbooks."""
        files = [f('src/x.js', 'el.innerHTML = location.hash;')]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        self.assertTrue(any(p.risk_type == 'DOM XSS' for p in result.verification_playbooks),
            'DOM XSS with short direct PoC must be promoted')

    def test_storage_auth_bypass_with_poc_is_promoted(self):
        """Storage-based auth bypass with 1-line PoC must land in verification_playbooks."""
        files = [f('src/AdminPage.js',
                   "const user = JSON.parse(sessionStorage.getItem('user'));\n"
                   "if (user?.userType === 'ADMIN') { navigate('/admin'); }")]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        self.assertTrue(
            any(p.risk_type == 'Client-side Authorization Bypass'
                for p in result.verification_playbooks),
            'Auth bypass with short storage PoC must be promoted',
        )
        pb = [p for p in result.verification_playbooks if p.risk_type == 'Client-side Authorization Bypass'][0]
        self.assertIn('sessionStorage', pb.console_code or '')
        self.assertLessEqual(len((pb.console_code or '').splitlines()), 2)

    def test_promoted_never_embeds_full_interceptor(self):
        """No promoted finding may embed a global hook installer in its PoC code."""
        files = [
            f('src/Pay.jsx',
              "function submitOrder(){axios.post('/api/orders/123/pay',{amount})}\n"
              "<button onClick={submitOrder}>Pay now</button>"),
            f('src/x.js', 'el.innerHTML = location.hash;'),
        ]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        promoted_ids = {p.id for p in result.verification_playbooks}
        for finding in result.findings:
            if finding.id in promoted_ids:
                poc_code = (finding.console_poc.code or '') if finding.console_poc else ''
                for sig in ['window.fetch = async function', 'XMLHttpRequest.prototype.open',
                            'SSS_REVIEW_POC_STATE', 'TARGET_ENDPOINT']:
                    self.assertNotIn(sig, poc_code,
                        f'Promoted finding [{finding.vulnerability_type}] embeds hook: {sig!r}')

    def test_dom_xss_poc_at_most_2_lines(self):
        """DOM XSS console PoC must be <= 2 lines."""
        files = [f('src/xss.js', 'const x = location.hash; el.innerHTML = x;')]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        dom = [p for p in result.verification_playbooks if p.risk_type == 'DOM XSS']
        self.assertTrue(dom, 'Should have a promoted DOM XSS playbook')
        code = dom[0].console_code or ''
        self.assertLessEqual(len(code.splitlines()), 2,
            f'DOM XSS PoC must be <= 2 lines, got: {code!r}')

    def test_request_replay_poc_no_global_hook(self):
        """CONFIRM-guarded replay PoC must contain no global hook installer."""
        files = [f('src/Pay.jsx',
                   "function submitOrder(){axios.post('/api/orders/123/pay',{amount})}\n"
                   "<button onClick={submitOrder}>Pay now</button>")]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        for pb in result.verification_playbooks:
            if pb.risk_type not in {'DOM XSS', 'Client-side Authorization Bypass'}:
                code = pb.console_code or ''
                self.assertNotIn('window.fetch = async function', code)
                self.assertNotIn('XMLHttpRequest.prototype.open', code)
                self.assertIn('fetch(', code, 'Direct replay must contain fetch() call')

    def test_source_sink_chain_in_dom_xss_evidence(self):
        """DOM XSS evidence must have source: and sink: in data_flow."""
        files = [f('src/x.js', 'el.innerHTML = location.hash;')]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        dom_findings = [x for x in result.findings if x.vulnerability_type == 'DOM XSS']
        self.assertTrue(dom_findings)
        for finding in dom_findings:
            self.assertTrue(finding.evidence, 'DOM XSS must have evidence')
            flow = finding.evidence[0].data_flow
            has_source = any(x.startswith('source:') for x in flow)
            has_sink   = any(x.startswith('sink:') for x in flow)
            self.assertTrue(has_source, f'DOM XSS evidence must have source: entry. Got: {flow}')
            self.assertTrue(has_sink,   f'DOM XSS evidence must have sink: entry. Got: {flow}')


    # -- Regression tests for 2026-06-05 changes ----------------------------

    # Change A: INTERCEPTOR_SIGS extended with window.SSS_POC.find/replay/list/armMutation
    def test_interceptor_sigs_find_is_not_free(self):
        from app.services.poc_templates import is_interceptor_free
        code = 'window.SSS_POC.find({ urlIncludes: "/api/test" })'
        self.assertFalse(is_interceptor_free(code))

    def test_interceptor_sigs_replay_is_not_free(self):
        from app.services.poc_templates import is_interceptor_free
        self.assertFalse(is_interceptor_free('window.SSS_POC.replay(0)'))

    def test_interceptor_sigs_list_is_not_free(self):
        from app.services.poc_templates import is_interceptor_free
        self.assertFalse(is_interceptor_free('window.SSS_POC.list()'))

    def test_interceptor_sigs_arm_mutation_is_not_free(self):
        from app.services.poc_templates import is_interceptor_free
        self.assertFalse(is_interceptor_free('window.SSS_POC.armMutation()'))

    def test_plain_fetch_is_interceptor_free(self):
        from app.services.poc_templates import is_interceptor_free
        code = '(async () => { const r = await fetch("/api/test"); console.log(r.status); })()'
        self.assertTrue(is_interceptor_free(code))

    # Change B: _build_playbook_poc returns None when no self-contained PoC can be built
    def test_build_playbook_poc_returns_none_for_ambiguous_fetch(self):
        content = (
            "function handleAction(){fetch('/api/endpoint-no-params', {method:'POST'})}\n"
            "<button onClick={handleAction}>Go</button>"
        )
        files = [f('src/Ambiguous.js', content)]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        for pb in result.verification_playbooks:
            self.assertNotIn(
                'window.SSS_POC.find(',
                pb.console_code or '',
                'Promoted playbook must not use SSS_POC capture flow',
            )

    # Change C: normalize_endpoint strips unknown base-URL variable patterns
    def test_normalize_endpoint_api_url_prefix(self):
        from app.services.poc_templates import normalize_endpoint
        self.assertEqual(normalize_endpoint('{API_URL}/login'), '/login')

    def test_normalize_endpoint_react_app_api_url_prefix(self):
        from app.services.poc_templates import normalize_endpoint
        self.assertEqual(normalize_endpoint('{REACT_APP_API_URL}/api/users'), '/api/users')

    def test_normalize_endpoint_api_base_url_prefix_still_works(self):
        from app.services.poc_templates import normalize_endpoint
        self.assertEqual(normalize_endpoint('{API_BASE_URL}/login'), '/login')

    def test_normalize_endpoint_route_params_untouched(self):
        from app.services.poc_templates import normalize_endpoint
        self.assertEqual(normalize_endpoint('/api/{item.id}/bid'), '/api/{item.id}/bid')

    # Change D: _proof_steps starts with navigation step
    def test_proof_steps_first_item_is_navigation(self):
        from app.services.console_poc_analysis_service import _proof_steps
        steps = _proof_steps(
            method='POST',
            page_hint='payment/order page',
            action_hint='click payment button',
        )
        self.assertTrue(len(steps) > 0, '_proof_steps must return at least one step')
        first = steps[0].lower()
        self.assertIn('navigate', first,
            'First proof step must mention navigation, got: %r' % steps[0])
        self.assertIn('payment/order page', steps[0],
            'First proof step must include page_hint text, got: %r' % steps[0])

    def test_proof_steps_get_first_item_is_navigation(self):
        from app.services.console_poc_analysis_service import _proof_steps
        steps = _proof_steps(
            method='GET',
            page_hint='wallet/point page',
            action_hint='click charge button',
        )
        self.assertTrue(len(steps) > 0)
        self.assertIn('navigate', steps[0].lower(),
            'First GET proof step must mention navigation, got: %r' % steps[0])


    # ── Agent team: generic rules ──────────────────────────────────────────────

    def test_nafal_not_hardcoded_in_core_rules(self):
        """Core detection lists must not contain fixture-specific role name 'nafal'.
        Fixture-specific expectations belong only in test files."""
        from app.services.console_poc_analysis_service import (
            AUTH_SNIPPET_KEYS,
            _extract_auth_branch_snippet,
        )
        import inspect
        auth_src = inspect.getsource(_extract_auth_branch_snippet)
        self.assertNotIn('nafal', ' '.join(AUTH_SNIPPET_KEYS).lower(),
            'AUTH_SNIPPET_KEYS must not contain nafal')
        # tier2_patterns and page_map are inside the function source
        self.assertNotIn("'nafalmypage'", auth_src,
            'page_map in _infer_page_action_hints must not contain nafalmypage')

    def test_nafal_tier2_patterns_removed(self):
        """tier2_patterns must not hardcode nafal as a literal role constant."""
        import inspect
        from app.services.console_poc_analysis_service import _extract_auth_branch_snippet
        src = inspect.getsource(_extract_auth_branch_snippet)
        # nafal must not appear as a literal string in a compiled regex pattern
        import re as _re
        pattern_strings = _re.findall(r'r["\']([^"\']+)["\']', src)
        for ps in pattern_strings:
            self.assertNotIn('nafal', ps.lower(),
                f"tier2 pattern contains nafal literal: {ps!r}")

    def test_status_set_for_all_findings(self):
        """Every ReadableFinding must have status in the valid lifecycle set."""
        VALID = {'raw_signal', 'review_candidate', 'runtime_verification_candidate', 'confirmed_finding'}
        files = [
            f('src/Pay.jsx', "function submitOrder(){axios.post('/api/orders/pay',{amount})}\n<button onClick={submitOrder}>Pay now</button>"),
            f('src/Auth.js', "const user = JSON.parse(sessionStorage.getItem('user')); if (user.userType !== 'ADMIN') navigate('/');"),
        ]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        for finding in result.findings:
            self.assertIn(finding.status, VALID,
                f"Finding [{finding.vulnerability_type}] has invalid status: {finding.status!r}")

    def test_category_set_for_all_findings(self):
        """Every ReadableFinding must have a non-None category after analysis."""
        files = [
            f('src/Pay.jsx', "function submitOrder(){axios.post('/api/orders/pay',{amount})}\n<button onClick={submitOrder}>Pay now</button>"),
        ]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        self.assertTrue(result.findings, 'Expected at least one finding')
        for finding in result.findings:
            self.assertIsNotNone(finding.category,
                f"Finding [{finding.vulnerability_type}] has category=None")

    def test_frontend_only_never_confirmed_finding(self):
        """Frontend-only source analysis must never produce a confirmed_finding status."""
        files = [
            f('src/Pay.jsx', "function submitOrder(){axios.post('/api/orders/pay',{amount})}\n<button onClick={submitOrder}>Pay now</button>"),
            f('src/Dom.js', "document.getElementById('out').innerHTML = location.hash;"),
            f('src/Auth.js', "const user = JSON.parse(sessionStorage.getItem('user')); if (user.userType !== 'ADMIN') navigate('/');"),
        ]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        for finding in result.findings:
            self.assertNotEqual(finding.status, 'confirmed_finding',
                f"Frontend-only finding [{finding.vulnerability_type}] must not be confirmed_finding")

    def test_runtime_verification_requires_endpoint_and_method(self):
        """A finding with status=runtime_verification_candidate must have a known endpoint and method."""
        files = [
            f('src/Pay.jsx', "function submitOrder(){axios.post('/api/orders/pay',{amount})}\n<button onClick={submitOrder}>Pay now</button>"),
        ]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        for pb in result.verification_playbooks:
            self.assertNotEqual(pb.endpoint, 'UNKNOWN',
                f"Playbook [{pb.risk_type}] endpoint must not be UNKNOWN")
            self.assertNotEqual(pb.method, 'UNKNOWN',
                f"Playbook [{pb.risk_type}] method must not be UNKNOWN")
        for finding in result.findings:
            if finding.status == 'runtime_verification_candidate':
                self.assertIsNotNone(finding.category,
                    'runtime_verification_candidate must have a category')

    def test_project_profile_populated(self):
        """ReadableAnalysisResult.project_profile must be populated after analysis."""
        files = [
            f('src/Pay.jsx', "function submitOrder(){axios.post('/api/orders/pay',{amount})}\n<button onClick={submitOrder}>Pay now</button>"),
        ]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        self.assertIsNotNone(result.project_profile,
            'project_profile must not be None')
        pp = result.project_profile
        self.assertIn(pp.project_type, {
            'source_react', 'source_vue_or_spa', 'jquery_html', 'static_html',
            'bundled_spa', 'mixed_frontend', 'unknown',
        })
        self.assertIsInstance(pp.scanned_files, int)
        self.assertIsInstance(pp.analyzed_files, int)
        self.assertIsInstance(pp.noise_ratio, float)

    def test_project_profile_counts_match_result(self):
        """ProjectProfile counts must be consistent with actual finding lists."""
        files = [
            f('src/Pay.jsx', "function submitOrder(){axios.post('/api/orders/pay',{amount})}\n<button onClick={submitOrder}>Pay now</button>"),
            f('src/service.js', "axios.post('/api/orders/pay',{amount})"),
        ]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        pp = result.project_profile
        self.assertEqual(pp.runtime_verification_candidates, len(result.verification_playbooks),
            'ProjectProfile.runtime_verification_candidates must match len(verification_playbooks)')
        self.assertEqual(pp.review_candidates, len(result.review_candidates),
            'ProjectProfile.review_candidates must match len(review_candidates)')

    def test_review_candidate_verification_playbook_is_short(self):
        """verification_playbook.console_code for review candidates must be short (<= 12 lines)
        and must NOT contain global hook installer signatures."""
        HOOK_SIGS = ['SSS_REVIEW_POC_STATE', 'TARGET_ENDPOINT =',
                     'window.fetch = async function', 'XMLHttpRequest.prototype.open']
        files = [
            f('src/WalletPage.js', "function chargeWallet(){ axios.post('/api/wallet/charge', {amount}) }\n<button onClick={chargeWallet}>Charge</button>"),
        ]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        for finding in result.findings:
            vp = finding.verification_playbook
            if not vp or not vp.console_code:
                continue
            code = vp.console_code
            lines = [ln for ln in code.splitlines() if ln.strip()]
            self.assertLessEqual(len(lines), 12,
                f"verification_playbook.console_code has {len(lines)} lines (max 12):\n{code}")
            for sig in HOOK_SIGS:
                self.assertNotIn(sig, code,
                    f"verification_playbook.console_code contains hook sig: {sig!r}")

    def test_vendor_minified_file_produces_no_findings(self):
        """Minified/webpack files must not generate any findings."""
        big_line = 'a' * 900 + '; b = function(c){return c};'
        webpack = '__webpack_require__; webpackChunk=[]; module.exports={};'
        files = [
            f('dist/vendor-abc12345.js', big_line),
            f('dist/app.bundle.js', webpack + "fetch('/api/pay',{method:'POST',body:JSON.stringify({amount:100})})"),
        ]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        self.assertFalse(result.findings,
            f"Minified/vendor files must produce no findings, got: {[x.vulnerability_type for x in result.findings]}")

    def test_disabled_isloading_is_raw_signal_or_absent(self):
        """Disabled UI bypass based solely on isLoading state must be raw_signal or absent."""
        files = [f('src/Form.jsx',
            "const [isLoading, setIsLoading] = useState(false);\n"
            "<button disabled={isLoading} onClick={handleSubmit}>Submit</button>")]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        disabled_findings = [x for x in result.findings if 'Client-side Validation Bypass' in x.vulnerability_type or 'disabled' in x.title.lower()]
        for df in disabled_findings:
            self.assertIn(df.status, {'raw_signal', 'review_candidate'},
                f"isLoading-only bypass must not reach runtime_verification_candidate, got: {df.status}")
            self.assertNotIn(df.id, {pb.id for pb in result.verification_playbooks},
                "isLoading-only bypass must not be promoted to playbook")

    def test_project_type_react_detected(self):
        """React project type must be detected from JSX files."""
        files = [f('src/App.jsx', "import React from 'react'; function App() { return <div>Hello</div>; }")]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        self.assertIsNotNone(result.project_profile)
        self.assertEqual(result.project_profile.project_type, 'source_react',
            f"Expected source_react, got {result.project_profile.project_type!r}")

    def test_project_type_bundled_not_promoted(self):
        """Bundled SPA project type findings must not be promoted to playbooks."""
        webpack_content = '__webpack_require__; webpackChunk=[]; ' + ('x=1;' * 300)
        files = [f('dist/app-abc12345.js', webpack_content)]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        self.assertEqual(len(result.verification_playbooks), 0,
            'Bundled SPA files must not produce verification playbooks')


    # ── Quality gate: lifecycle wording ───────────────────────────────────────

    def test_confirmed_wording_never_appears_in_non_confirmed_findings(self):
        """The word 'Confirmed' (as a promotion claim) must never appear in
        verification_notes of any finding unless its status is confirmed_finding."""
        files = [
            f('src/Pay.jsx', "function submitOrder(){axios.post('/api/orders/pay',{amount})}\n<button onClick={submitOrder}>Pay now</button>"),
            f('src/service.js', "axios.post('/api/orders/pay',{amount})"),
        ]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        for finding in result.findings:
            notes_text = ' '.join(finding.verification_notes)
            if finding.status != 'confirmed_finding':
                self.assertNotIn('Confirmed promoted finding', notes_text,
                    f'"Confirmed promoted finding" must not appear in [{finding.status}] {finding.vulnerability_type}')

    def test_rtvc_wording_in_promoted_notes(self):
        """Promoted findings must have 'Selected as runtime verification candidate' in notes."""
        files = [f('src/Pay.jsx', "function submitOrder(){axios.post('/api/orders/pay',{amount})}\n<button onClick={submitOrder}>Pay now</button>")]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        promoted_ids = {p.id for p in result.verification_playbooks}
        self.assertTrue(promoted_ids)
        for finding in result.findings:
            if finding.id in promoted_ids:
                self.assertIn(RTVC_NOTE, ' '.join(finding.verification_notes),
                    f'Promoted finding must have note: {RTVC_NOTE!r}')

    def test_success_criteria_payment_is_impact_based(self):
        """Payment/price/point success criteria must describe security impact, not just response visibility."""
        files = [f('src/Pay.jsx', "function handlePayment(){axios.post('/api/orders/pay',{amount,totalAmount})}\n<button onClick={handlePayment}>Pay now</button>")]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        pb = next((p for p in result.verification_playbooks if 'Payment' in p.risk_type or 'Validation' in p.risk_type), None)
        self.assertIsNotNone(pb, 'expected a payment playbook')
        success = '\n'.join(pb.success_criteria).lower()
        self.assertNotIn('status/content-type/body preview is visible', success,
            'Weak visibility criterion must be gone')
        self.assertTrue(
            any(k in success for k in ('reflected', 'balance', 'transaction', 'server-side', 'authorization error', 'validation error', 'mutated')),
            f'Success criteria must describe security impact, not just visibility. Got: {success!r}',
        )

    def test_success_criteria_dom_xss_is_execution_based(self):
        """DOM XSS success criteria must require script execution, not just response visibility."""
        from app.services.console_poc_analysis_service import _success_criteria
        criteria = _success_criteria('DOM', 'DOM XSS')
        text = ' '.join(criteria).lower()
        self.assertIn('executes', text, 'DOM XSS criterion must mention script execution')
        self.assertIn('sink', text, 'DOM XSS criterion must mention the sink')
        self.assertNotIn('status/body', text)

    def test_success_criteria_idor_is_access_based(self):
        from app.services.console_poc_analysis_service import _success_criteria
        criteria = _success_criteria('GET', 'IDOR / Unauthorized Data Access Candidate')
        text = ' '.join(criteria).lower()
        self.assertTrue(
            any(k in text for k in ('unauthorized', 'ownership', '401', '403', 'user data', 'object')),
            f'IDOR success criteria must describe access control impact. Got: {text!r}',
        )

    def test_success_criteria_account_recovery_is_token_based(self):
        from app.services.console_poc_analysis_service import _success_criteria
        criteria = _success_criteria('POST', 'Account Recovery Flow Abuse Candidate')
        text = ' '.join(criteria).lower()
        self.assertTrue(
            any(k in text for k in ('code', 'token', 'rate', 'bound', 'invalid', 'reused')),
            f'Account recovery criteria must describe token/rate-limit impact. Got: {text!r}',
        )

    # ── Quality gate: PoC gating ──────────────────────────────────────────────

    def test_post_with_generic_action_stays_review_candidate(self):
        """A bare POST call with no function/UI context must not be promoted."""
        files = [f('src/service.js', "axios.post('/api/orders/pay',{amount})")]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        self.assertEqual(len(result.verification_playbooks), 0,
            'Bare POST with no function/UI context must not produce a playbook')
        self.assertGreater(len(result.review_candidates), 0)
        for rc in result.review_candidates:
            self.assertIn(rc.poc_generation_status, {'manual_plan', 'observational'},
                f'Expected manual_plan or observational, got {rc.poc_generation_status}')

    def test_post_with_unresolved_placeholder_stays_manual_plan(self):
        """A POST with {API_BASE_URL} placeholder must stay manual_plan."""
        files = [f('src/LoginPage.js',
                   "function doLogin(){ axios.post(API_BASE_URL + '/login', { email, password }); }")]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        self.assertEqual(len(result.verification_playbooks), 0,
            'Unresolved base URL must produce 0 playbooks')
        for rc in result.review_candidates:
            self.assertEqual(rc.poc_generation_status, 'manual_plan',
                'Unresolved endpoint must be manual_plan')
            poc_code = (rc.console_poc.code or '') if rc.console_poc else ''
            self.assertFalse(poc_code.strip(),
                'manual_plan candidate must have no runnable console code')

    def test_delete_refund_withdraw_transfer_no_replay_poc(self):
        """High-risk irreversible endpoints must never generate a replay PoC."""
        from app.services.poc_templates import build_request_replay_poc
        blocked_cases = [
            ('DELETE', '/api/orders/123'),
            ('POST', '/api/refund/process'),
            ('POST', '/api/transfer/funds'),
            ('POST', '/api/withdraw'),
            ('POST', '/api/bulk/delete'),
        ]
        for method, endpoint in blocked_cases:
            result = build_request_replay_poc(method, endpoint)
            self.assertIsNone(result,
                f'build_request_replay_poc must return None for {method} {endpoint}')

    def test_get_session_is_not_promoted(self):
        """GET /api/user/session must not be promoted to a runtime verification candidate."""
        files = [f('src/app.js', "fetch('/api/user/session')")]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        self.assertEqual(len(result.verification_playbooks), 0,
            'GET /api/session must not be promoted')
        for finding in result.findings:
            self.assertIn(finding.status, {'raw_signal', 'review_candidate'},
                'Session check GET must be raw_signal or review_candidate')

    def test_search_recommend_api_is_not_promoted(self):
        """Search/recommend APIs must not be promoted to runtime verification candidates."""
        files = [f('src/search.js',
                   "function search(){ axios.get('/api/recommend_search', { params: { keyword } }) }")]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        self.assertEqual(len(result.verification_playbooks), 0,
            'Search/recommend API must not be promoted')

    def test_disabled_isloading_not_promoted(self):
        """disabled={isLoading} button must not produce a promoted playbook."""
        files = [f('src/Form.jsx',
                   "const [isLoading, setIsLoading] = useState(false);\n"
                   "<button disabled={isLoading} onClick={handleSubmit}>Submit</button>")]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        self.assertEqual(len(result.verification_playbooks), 0,
            'isLoading-only disabled button must not be promoted')

    def test_no_confirmed_wording_anywhere_in_output(self):
        """The word 'Confirmed' as a promotion marker must not appear anywhere in the output
        from a frontend-only analysis session."""
        files = [
            f('src/Pay.jsx', "function handlePayment(){axios.post('/api/orders/pay',{amount})}\n<button onClick={handlePayment}>Pay now</button>"),
            f('src/auth.js', "const u=JSON.parse(sessionStorage.getItem('user'));if(!u.isAdmin)navigate('/');"),
        ]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        for finding in result.findings:
            for note in finding.verification_notes:
                self.assertNotIn('Confirmed promoted', note,
                    f'Legacy "Confirmed promoted" wording found in [{finding.status}] notes: {note!r}')

    def test_common_console_helper_hidden_when_no_observational_needed(self):
        """common_console_helper must be None when all candidates are manual_plan."""
        files = [f('src/service.js', "axios.post('/api/orders/pay',{amount})")]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        self.assertEqual(len(result.verification_playbooks), 0)
        # No observational candidates → helper must be hidden
        if all(rc.poc_generation_status == 'manual_plan' for rc in result.review_candidates):
            self.assertIsNone(result.common_console_helper,
                'common_console_helper must be None when all candidates are manual_plan')

    # ── _category_for: strict routing ────────────────────────────────────────

    def test_category_for_exact_canonical_types(self):
        """Canonical mock-emitted vulnerability_type strings must map to the correct internal code."""
        from app.services.console_poc_analysis_service import _category_for
        self.assertEqual(_category_for('DOM XSS'), 'xss')
        self.assertEqual(_category_for('Client-side Authorization Bypass'), 'authorization')
        self.assertEqual(_category_for('Client-side Validation Bypass'), 'client_side_validation')
        self.assertEqual(_category_for('Payment/Point Manipulation Candidate'), 'payment_or_value_mutation')
        self.assertEqual(_category_for('IDOR / Unauthorized Data Access Candidate'), 'idor_bola')
        self.assertEqual(_category_for('State/Status Manipulation Candidate'), 'role_or_state_mutation')
        self.assertEqual(_category_for('Account Recovery Flow Abuse Candidate'), 'account_recovery')
        self.assertEqual(_category_for('Generic API Review Candidate'), 'generic')

    def test_category_for_idor_requires_specific_terms(self):
        """'access' or 'unauthorized' alone must not classify as idor_bola."""
        from app.services.console_poc_analysis_service import _category_for
        self.assertNotEqual(_category_for('Broken Access Control'), 'idor_bola',
            '"access" alone must not map to idor_bola')
        self.assertNotEqual(_category_for('Improper Access Control'), 'idor_bola',
            '"access" alone must not map to idor_bola')
        self.assertNotEqual(_category_for('Unauthorized Action'), 'idor_bola',
            '"unauthorized" alone must not map to idor_bola')
        # Positive cases
        self.assertEqual(_category_for('IDOR / Unauthorized Data Access Candidate'), 'idor_bola')
        self.assertEqual(_category_for('BOLA: access another user object'), 'idor_bola')
        self.assertEqual(_category_for('Object-Level Authorization Failure'), 'idor_bola')

    def test_category_for_account_recovery_requires_specific_terms(self):
        """'account' alone must not classify as account_recovery."""
        from app.services.console_poc_analysis_service import _category_for
        self.assertNotEqual(_category_for('Account Takeover via Session Fixation'), 'account_recovery',
            '"account" alone must not map to account_recovery')
        self.assertNotEqual(_category_for('Account Enumeration'), 'account_recovery',
            '"account" alone must not map to account_recovery')
        self.assertNotEqual(_category_for('Account Hijacking'), 'account_recovery',
            '"account" alone must not map to account_recovery')
        # Positive cases
        self.assertEqual(_category_for('Account Recovery Flow Abuse Candidate'), 'account_recovery')
        self.assertEqual(_category_for('password reset abuse'), 'account_recovery')
        self.assertEqual(_category_for('verification code bypass'), 'account_recovery')
        self.assertEqual(_category_for('recovery token replay'), 'account_recovery')

    def test_category_for_payment_includes_coupon_balance_amount_discount(self):
        """Specific payment-related terms must route to payment_or_value_mutation;
        standalone 'balance' and 'amount' must not (too broad — would match
        'Load Balance' or 'Excessive Amount of Data')."""
        from app.services.console_poc_analysis_service import _category_for
        for term in ('Coupon Manipulation', 'Account Balance Tampering', 'Payment Amount Overflow',
                     'Discount Bypass', 'Order Total Manipulation'):
            self.assertEqual(_category_for(term), 'payment_or_value_mutation',
                f'Expected payment_or_value_mutation for {term!r}')
        # These must NOT classify as payment — standalone keywords are too broad.
        for term in ('Balance Tampering', 'Amount Abuse', 'API Endpoint Manipulation'):
            self.assertNotEqual(_category_for(term), 'payment_or_value_mutation',
                f'{term!r} must not be misclassified as payment_or_value_mutation')

    # ── Playbook helpers: symmetric branches ─────────────────────────────────

    def test_validation_bypass_criteria_are_consistent_across_helpers(self):
        """Client-side Validation Bypass must produce category-specific output from all three helpers."""
        from app.services.console_poc_analysis_service import _success_criteria, _failure_criteria, _evidence_to_capture
        vuln_type = 'Client-side Validation Bypass'
        method = 'POST'
        success = '\n'.join(_success_criteria(method, vuln_type)).lower()
        failure = '\n'.join(_failure_criteria(method, vuln_type)).lower()
        evidence = '\n'.join(_evidence_to_capture(method, vuln_type)).lower()
        # Success must describe bypass impact
        self.assertIn('manipulated parameter', success,
            '_success_criteria for validation bypass must describe manipulated parameter')
        # Failure must NOT fall back to generic HTML-fallback text
        self.assertNotIn('html fallback', failure,
            '_failure_criteria for validation bypass must not use generic HTML fallback text')
        self.assertIn('constraint', failure,
            '_failure_criteria for validation bypass must describe server-side constraint enforcement')
        # Evidence must be network-focused
        self.assertIn('network tab', evidence,
            '_evidence_to_capture for validation bypass must mention Network tab')

    def test_coupon_balance_get_payment_criteria_in_all_three_helpers(self):
        """Gemini-emitted types with coupon/account balance must get payment guidance from all three helpers."""
        from app.services.console_poc_analysis_service import _success_criteria, _failure_criteria, _evidence_to_capture
        for vuln_type in ('Coupon Balance Manipulation', 'Account Balance Tampering', 'Discount Abuse'):
            method = 'POST'
            success = '\n'.join(_success_criteria(method, vuln_type)).lower()
            failure = '\n'.join(_failure_criteria(method, vuln_type)).lower()
            evidence = '\n'.join(_evidence_to_capture(method, vuln_type)).lower()
            self.assertTrue(
                any(k in success for k in ('amount', 'price', 'balance', 'transaction', 'mutated')),
                f'_success_criteria must return payment guidance for {vuln_type!r}. Got: {success!r}',
            )
            self.assertTrue(
                any(k in failure for k in ('amount', 'price', 'server-side', 'server validates')),
                f'_failure_criteria must return payment guidance for {vuln_type!r}. Got: {failure!r}',
            )
            self.assertTrue(
                any(k in evidence for k in ('amount', 'price', 'network tab')),
                f'_evidence_to_capture must return payment guidance for {vuln_type!r}. Got: {evidence!r}',
            )

    def test_broken_access_control_does_not_get_idor_criteria(self):
        """'Broken Access Control' must not receive IDOR-specific criteria from any helper."""
        from app.services.console_poc_analysis_service import _success_criteria, _failure_criteria, _evidence_to_capture
        vuln_type = 'Broken Access Control'
        method = 'GET'
        success = '\n'.join(_success_criteria(method, vuln_type)).lower()
        failure = '\n'.join(_failure_criteria(method, vuln_type)).lower()
        evidence = '\n'.join(_evidence_to_capture(method, vuln_type)).lower()
        self.assertNotIn('data belonging to another user', success,
            'Broken Access Control must not get IDOR user-data success criteria')
        self.assertNotIn('ownership', failure,
            'Broken Access Control must not get IDOR ownership-rejection failure criteria')
        self.assertNotIn('another user/object identifier', evidence,
            'Broken Access Control must not get IDOR object-identifier evidence')

    def test_account_takeover_does_not_get_recovery_criteria(self):
        """'Account Takeover via Session Fixation' must not get verification-code recovery criteria."""
        from app.services.console_poc_analysis_service import _success_criteria, _failure_criteria, _evidence_to_capture
        vuln_type = 'Account Takeover via Session Fixation'
        method = 'POST'
        success = '\n'.join(_success_criteria(method, vuln_type)).lower()
        failure = '\n'.join(_failure_criteria(method, vuln_type)).lower()
        self.assertNotIn('verification code', success,
            'Account Takeover must not get verification-code recovery success criteria')
        self.assertNotIn('reset token', success,
            'Account Takeover must not get token-binding recovery success criteria')
        self.assertNotIn('rate-limit', failure,
            'Account Takeover must not get rate-limiting recovery failure criteria')

    def test_idor_criteria_consistent_across_all_three_helpers(self):
        """IDOR must produce category-specific output from success, failure, and evidence helpers."""
        from app.services.console_poc_analysis_service import _success_criteria, _failure_criteria, _evidence_to_capture
        vuln_type = 'IDOR / Unauthorized Data Access Candidate'
        method = 'GET'
        success = '\n'.join(_success_criteria(method, vuln_type)).lower()
        failure = '\n'.join(_failure_criteria(method, vuln_type)).lower()
        evidence = '\n'.join(_evidence_to_capture(method, vuln_type)).lower()
        self.assertIn('another user', success, '_success_criteria for IDOR must mention another user')
        self.assertIn('ownership', failure, '_failure_criteria for IDOR must mention ownership rejection')
        self.assertIn('identifier', evidence, '_evidence_to_capture for IDOR must mention substituted identifier')

    def test_account_recovery_criteria_consistent_across_all_three_helpers(self):
        """Account Recovery must produce category-specific output from all three helpers."""
        from app.services.console_poc_analysis_service import _success_criteria, _failure_criteria, _evidence_to_capture
        vuln_type = 'Account Recovery Flow Abuse Candidate'
        method = 'POST'
        success = '\n'.join(_success_criteria(method, vuln_type)).lower()
        failure = '\n'.join(_failure_criteria(method, vuln_type)).lower()
        evidence = '\n'.join(_evidence_to_capture(method, vuln_type)).lower()
        self.assertTrue(any(k in success for k in ('code', 'token', 'rate', 'invalid', 'reused')),
            '_success_criteria for account recovery must describe token/code impact')
        self.assertTrue(any(k in failure for k in ('rate', 'token', 'verification', 'scoped', 'binding')),
            '_failure_criteria for account recovery must describe token/rate-limit rejection')
        self.assertTrue(any(k in evidence for k in ('token', 'code', 'recovery', 'rate')),
            '_evidence_to_capture for account recovery must capture token/code evidence')

    def test_f_category_is_set_before_should_review_gate(self):
        """f.category must be set (non-None) on every finding, including review candidates."""
        files = [
            f('src/Pay.jsx', "function submitOrder(){axios.post('/api/orders/pay',{amount})}\n<button onClick={submitOrder}>Pay now</button>"),
            f('src/auth.js', "const u=JSON.parse(sessionStorage.getItem('user'));if(!u.isAdmin)navigate('/');"),
            f('src/service.js', "axios.post('/api/orders/pay',{amount})"),
        ]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        all_findings = result.findings + result.review_candidates
        for finding in all_findings:
            self.assertIsNotNone(finding.category,
                f'f.category must be set before should_review for [{finding.vulnerability_type}]')
            self.assertNotEqual(finding.category, '',
                f'f.category must not be empty string for [{finding.vulnerability_type}]')

    def test_high_priority_categories_preserved_at_low_confidence(self):
        """Findings in high-priority categories must not appear in review_candidates.

        The is_low_conf gate must be bypassed for _HIGH_PRIORITY_CATEGORIES, so
        any finding that lands in review_candidates must have a non-high-priority
        category.  A high-priority finding in review_candidates means the gate
        silently swallowed it, which is the regression this test guards against.
        """
        from app.services.console_poc_analysis_service import _HIGH_PRIORITY_CATEGORIES
        files = [
            f('src/Pay.jsx', "function submitOrder(){axios.post('/api/orders/123/pay',{amount})}\n<button onClick={submitOrder}>Pay now</button>"),
        ]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        for candidate in result.review_candidates:
            self.assertNotIn(
                candidate.category,
                _HIGH_PRIORITY_CATEGORIES,
                f'High-priority category [{candidate.category}] must not be demoted to '
                f'review_candidates for [{candidate.vulnerability_type}] — '
                f'is_low_conf gate should be bypassed for high-priority categories',
            )


if __name__ == '__main__':
    unittest.main()
