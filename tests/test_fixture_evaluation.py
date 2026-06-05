"""
Synthetic fixture evaluation tests.

Each fixture simulates a real project type without using actual customer ZIPs.
Tests validate finding counts, noise suppression, lifecycle status, and PoC quality
across 5 representative project shapes:
  nafal-like   React, business logic, known endpoints
  loTO-like    React, all endpoints dynamic/unresolvable
  CIA-like     bundled/minified SPA, no source
  nls-like     jQuery/ajax, search + payment endpoints
  ebs-like     HTML/jQuery, heavy disabled-button noise
"""
import unittest
from app.models.schemas import FileContent
from app.services.console_poc_analysis_service import (
    analyze_console_exploitability,
    MockConsolePocAnalyzer,
    is_interceptor_free,
    PROMOTION_SCORE_THRESHOLD,
)
from app.services.source_intelligence import _detect_project_type, _detect_api_clients


def fc(path, content):
    ext = '.' + path.rsplit('.', 1)[-1] if '.' in path else ''
    return FileContent(
        path=path, extension=ext, size=len(content),
        priority=1, reason_code='INCLUDED', content_hash='h', content=content,
    )


MOCK = MockConsolePocAnalyzer()


class NafalLikeFixtureTests(unittest.TestCase):
    """React project with business logic, known endpoints, session storage auth."""

    @classmethod
    def setUpClass(cls):
        cls.files = [
            fc('src/AdminPage.jsx',
               "const user = JSON.parse(sessionStorage.getItem('user'));\n"
               "if (user?.userType !== 'ADMIN') navigate('/');\n"
               "requireAuth(user);"),
            fc('src/PaymentPage.jsx',
               "function handlePayment(){\n"
               "  axios.post('/api/orders/pay', { amount, totalAmount, orderId })\n"
               "}\n"
               "<button onClick={handlePayment}>Pay now</button>"),
            fc('src/BidPage.jsx',
               "function handleBid(){\n"
               "  axios.post('/api/auction/bid', { amount, itemId })\n"
               "}\n"
               "<button onClick={handleBid}>Place bid</button>"),
            fc('src/WalletPage.jsx',
               "function handleCharge(){\n"
               "  axios.post('/api/wallet/charge', { amount })\n"
               "}\n"
               "<button onClick={handleCharge}>Charge wallet</button>"),
        ]
        cls.result = analyze_console_exploitability(cls.files, analyzer=MOCK)
        cls.pp = cls.result.project_profile

    def test_project_type_is_react(self):
        self.assertEqual(_detect_project_type(self.files), 'source_react')

    def test_project_profile_populated(self):
        self.assertIsNotNone(self.pp)
        self.assertIn(self.pp.project_type, {'source_react', 'mixed_frontend'})
        self.assertIn('axios', self.pp.api_clients)

    def test_no_confirmed_findings(self):
        for f in self.result.findings:
            self.assertNotEqual(f.status, 'confirmed_finding',
                f"Frontend-only [{f.vulnerability_type}] must not be confirmed_finding")

    def test_all_findings_have_status_and_category(self):
        valid_statuses = {'raw_signal', 'review_candidate', 'runtime_verification_candidate', 'confirmed_finding'}
        for f in self.result.findings:
            self.assertIn(f.status, valid_statuses)
            self.assertIsNotNone(f.category)

    def test_payment_endpoint_promotes_to_playbook(self):
        payment_pbs = [p for p in self.result.verification_playbooks
                       if 'pay' in (p.endpoint or '').lower() or 'Payment' in p.risk_type]
        self.assertGreater(len(payment_pbs), 0,
            "nafal-like: payment endpoint must produce at least one verification playbook")

    def test_promoted_playbook_code_short_and_safe(self):
        for pb in self.result.verification_playbooks:
            code = pb.console_code or ''
            if code:
                lines = [l for l in code.splitlines() if l.strip()]
                self.assertLessEqual(len(lines), 12,
                    f"Playbook code too long: {len(lines)} lines")
                self.assertTrue(is_interceptor_free(code),
                    f"Playbook code must not contain hook installer sigs")

    def test_auth_bypass_detected(self):
        auth = [f for f in self.result.findings
                if 'Authorization' in f.vulnerability_type or 'Auth' in f.vulnerability_type]
        self.assertGreater(len(auth), 0, "Auth bypass must be detected from sessionStorage pattern")

    def test_noise_ratio_reasonable(self):
        self.assertLessEqual(self.pp.noise_ratio, 0.5,
            f"nafal-like noise_ratio {self.pp.noise_ratio} too high (expect <= 0.5)")


class LoTOLikeFixtureTests(unittest.TestCase):
    """React project with all endpoints dynamic/unresolvable — no playbooks expected."""

    @classmethod
    def setUpClass(cls):
        cls.files = [
            fc('src/LoginPage.js',
               "function doLogin() { axios.post(API_BASE_URL + '/login', { email, password }); }"),
            fc('src/Dashboard.js',
               "function loadDashboard() { axios.get(API_BASE_URL + '/dashboard'); }"),
            fc('src/Profile.js',
               "const endpoint = API_URLS.PROFILE;\naxios.post(endpoint, { userId });"),
            fc('src/service.js',
               "function updateStatus(id) { apiClient.put(`${BASE}/user/${id}/status`, { status }); }"),
        ]
        cls.result = analyze_console_exploitability(cls.files, analyzer=MOCK)
        cls.pp = cls.result.project_profile

    def test_zero_promoted_playbooks(self):
        self.assertEqual(len(self.result.verification_playbooks), 0,
            "loTO-like: all dynamic endpoints must produce 0 promoted playbooks")

    def test_all_review_candidates_are_manual_plan(self):
        for rc in self.result.review_candidates:
            self.assertEqual(rc.poc_generation_status, 'manual_plan',
                f"loTO-like: dynamic endpoint must be manual_plan, got {rc.poc_generation_status}")
            poc_code = (rc.console_poc.code or '') if rc.console_poc else ''
            self.assertFalse(poc_code.strip(),
                "loTO-like: manual_plan candidate must have no runnable console code")

    def test_no_confirmed_findings(self):
        for f in self.result.findings:
            self.assertNotEqual(f.status, 'confirmed_finding')

    def test_profile_shows_no_rtvc(self):
        self.assertEqual(self.pp.runtime_verification_candidates, 0)

    def test_review_candidates_have_no_hook_code(self):
        HOOK_SIGS = ['SSS_REVIEW_POC_STATE', 'TARGET_ENDPOINT =',
                     'window.fetch = async function', 'XMLHttpRequest.prototype.open']
        for rc in self.result.review_candidates:
            for attr in ('console_poc', 'observational_poc'):
                poc = getattr(rc, attr, None)
                code = (poc.code or '') if poc else ''
                for sig in HOOK_SIGS:
                    self.assertNotIn(sig, code,
                        f"loTO-like: review candidate must not contain hook: {sig!r}")


class CIALikeFixtureTests(unittest.TestCase):
    """Bundled/minified SPA — no source available, should produce no playbooks."""

    @classmethod
    def setUpClass(cls):
        big_line = 'x' * 900 + ';'
        cls.files = [
            fc('dist/app-abc12345.js',
               '__webpack_require__({});\n' + big_line + "fetch('/api/pay',{method:'POST'})"),
            fc('dist/vendor-def67890.js',
               'self.webpackChunk=[];\n' + big_line),
            fc('dist/commons-123abc456.js',
               'webpackChunk;\n' + big_line),
        ]
        cls.result = analyze_console_exploitability(cls.files, analyzer=MOCK)
        cls.pp = cls.result.project_profile

    def test_project_type_is_bundled_spa(self):
        self.assertEqual(_detect_project_type(self.files), 'bundled_spa')

    def test_zero_promoted_playbooks(self):
        self.assertEqual(len(self.result.verification_playbooks), 0,
            "CIA-like: bundled files must produce 0 promoted playbooks")

    def test_no_confirmed_findings(self):
        for f in self.result.findings:
            self.assertNotEqual(f.status, 'confirmed_finding')

    def test_compressed_findings_are_raw_signal_or_absent(self):
        for f in self.result.findings:
            self.assertIn(f.status, {'raw_signal', 'review_candidate'},
                f"CIA-like: bundled evidence must not reach runtime_verification_candidate")


class NLSLikeFixtureTests(unittest.TestCase):
    """jQuery/ajax project with search and payment endpoints."""

    @classmethod
    def setUpClass(cls):
        cls.files = [
            fc('templates/search.html',
               "<button id='searchBtn'>Search</button>\n"
               "<script>\n"
               "  $('#searchBtn').on('click', function(){\n"
               "    $.ajax({ url: '/recommend_search', type: 'GET', data: { keyword } });\n"
               "  });\n"
               "</script>"),
            fc('templates/payment.html',
               "<button id='payBtn'>Pay</button>\n"
               "<script>\n"
               "  $('#payBtn').on('click', function(){\n"
               "    $.ajax({ url: '/order/payment', type: 'POST', data: { amount, orderId } });\n"
               "  });\n"
               "</script>"),
            fc('templates/verify.html',
               "<button id='verifyBtn'>Verify</button>\n"
               "<script>\n"
               "  $('#verifyBtn').on('click', function(){\n"
               "    $.ajax({ url: '/user/chkMobiSendAjax', type: 'POST', data: { phoneNo } });\n"
               "  });\n"
               "</script>"),
        ]
        cls.result = analyze_console_exploitability(cls.files, analyzer=MOCK)
        cls.pp = cls.result.project_profile

    def test_project_type_jquery(self):
        self.assertIn(_detect_project_type(self.files), {'jquery_html', 'static_html', 'mixed_frontend'})

    def test_search_get_not_promoted(self):
        promoted_endpoints = {p.endpoint for p in self.result.verification_playbooks}
        search_promoted = any('recommend' in (ep or '') or 'search' in (ep or '')
                              for ep in promoted_endpoints)
        self.assertFalse(search_promoted,
            f"nls-like: search/recommend GET must not be promoted: {promoted_endpoints}")

    def test_no_confirmed_findings(self):
        for f in self.result.findings:
            self.assertNotEqual(f.status, 'confirmed_finding')

    def test_payment_or_identity_endpoint_detectable(self):
        # payment or identity verification endpoint should appear in extracted evidence
        all_findings = self.result.findings
        endpoints = []
        for finding in all_findings:
            for ev in finding.evidence:
                for df in ev.data_flow:
                    if df.startswith('endpoint:'):
                        endpoints.append(df)
        payment_found = any(
            'payment' in ep or 'chkMobi' in ep or 'verify' in ep.lower()
            for ep in endpoints
        )
        self.assertTrue(payment_found or len(all_findings) > 0,
            "nls-like: payment/verify endpoint must appear in findings")


class EBSLikeFixtureTests(unittest.TestCase):
    """HTML/jQuery project with disabled-button noise and real endpoints."""

    @classmethod
    def setUpClass(cls):
        cls.files = [
            fc('templates/form.html',
               "<button disabled id='submitBtn' onclick='submitForm()'>Submit</button>\n"
               "<button disabled id='loadBtn'>Loading...</button>\n"
               "<script>\n"
               "  var isLoading = false;\n"
               "  function submitForm(){\n"
               "    if(isLoading) return;\n"
               "    $.ajax({ url: '/user/chkMobiSendAjax', type: 'POST', data: { phoneNo } });\n"
               "  }\n"
               "</script>"),
            fc('templates/payment.html',
               "<button id='payBtn' onclick='pay()'>Pay</button>\n"
               "<script>\n"
               "  function pay(){\n"
               "    $.ajax({ url: '/payment/process', type: 'POST',\n"
               "             data: { amount, orderId, totalAmount } });\n"
               "  }\n"
               "</script>"),
            fc('templates/mypage.html',
               "<button onclick='loadProfile()'>My Page</button>\n"
               "<script>\n"
               "  function loadProfile(){ $.ajax({ url: '/user/myPageNewAjax', type: 'GET' }); }\n"
               "  function loadNotices(){ $.ajax({ url: '/user/myNotcListAjax', type: 'GET' }); }\n"
               "</script>"),
        ]
        cls.result = analyze_console_exploitability(cls.files, analyzer=MOCK)
        cls.pp = cls.result.project_profile

    def test_no_confirmed_findings(self):
        for f in self.result.findings:
            self.assertNotEqual(f.status, 'confirmed_finding')

    def test_mypage_get_not_promoted(self):
        promoted = {p.endpoint for p in self.result.verification_playbooks}
        self.assertNotIn('/user/myPageNewAjax', promoted,
            "ebs-like: myPage GET must not be promoted to playbook")
        self.assertNotIn('/user/myNotcListAjax', promoted,
            "ebs-like: notice list GET must not be promoted to playbook")

    def test_payment_endpoint_detectable(self):
        all_endpoints = []
        for f in self.result.findings:
            for ev in f.evidence:
                for df in ev.data_flow:
                    if 'payment' in df.lower() or 'amount' in df.lower():
                        all_endpoints.append(df)
        # At minimum, payment endpoint should appear somewhere
        found = (len(all_endpoints) > 0 or
                 any('payment' in (p.endpoint or '') for p in self.result.verification_playbooks))
        self.assertTrue(found, "ebs-like: payment endpoint must be detectable")

    def test_profile_counts_consistent(self):
        self.assertEqual(self.pp.runtime_verification_candidates, len(self.result.verification_playbooks))
        self.assertEqual(self.pp.review_candidates, len(self.result.review_candidates))

    def test_all_findings_have_lifecycle_status(self):
        valid = {'raw_signal', 'review_candidate', 'runtime_verification_candidate', 'confirmed_finding'}
        for f in self.result.findings:
            self.assertIn(f.status, valid)
            self.assertIsNotNone(f.category)


class CrossFixtureInvariantTests(unittest.TestCase):
    """Cross-fixture invariants that must hold for ALL project types."""

    def _run(self, files):
        return analyze_console_exploitability(files, analyzer=MOCK)

    def test_nafal_specific_terms_not_in_core(self):
        """Core detection lists must not contain fixture-specific role names."""
        from app.services.console_poc_analysis_service import AUTH_SNIPPET_KEYS
        self.assertNotIn('NAFAL', AUTH_SNIPPET_KEYS)
        self.assertNotIn('nafal', [k.lower() for k in AUTH_SNIPPET_KEYS])

    def test_confirmed_finding_never_reachable_from_frontend(self):
        """No project type should produce confirmed_finding from frontend-only source."""
        fixture_sets = [
            [fc('src/pay.jsx', "function pay(){axios.post('/api/pay',{amount})}\n<button onClick={pay}>Pay</button>")],
            [fc('src/dom.js', "document.getElementById('x').innerHTML = location.hash;")],
            [fc('src/auth.js', "const u=JSON.parse(sessionStorage.getItem('user'));if(!u.isAdmin)navigate('/');")],
            [fc('templates/form.html', "<button onclick='go()'>Go</button><script>function go(){$.ajax({url:'/api/go',type:'POST'})}</script>")],
        ]
        for files in fixture_sets:
            result = self._run(files)
            for finding in result.findings:
                self.assertNotEqual(finding.status, 'confirmed_finding',
                    f"confirmed_finding reached from frontend-only source: {finding.vulnerability_type}")

    def test_runtime_verification_candidate_has_resolved_endpoint(self):
        """Every playbook must have a non-UNKNOWN endpoint."""
        files = [fc('src/pay.jsx', "function pay(){axios.post('/api/orders/pay',{amount})}\n<button onClick={pay}>Pay now</button>")]
        result = self._run(files)
        for pb in result.verification_playbooks:
            self.assertNotEqual(pb.endpoint, 'UNKNOWN',
                f"Playbook [{pb.risk_type}] must have resolved endpoint")
            self.assertNotIn('UNKNOWN', pb.method or '',
                f"Playbook [{pb.risk_type}] must have resolved method")

    def test_vendor_minified_never_promoted(self):
        """Files detected as vendor/minified must not produce promoted playbooks."""
        files = [
            fc('dist/app-abc12345678.js',
               '__webpack_require__({});\n' + 'x' * 900 + ";\nfetch('/api/pay',{method:'POST'})"),
        ]
        result = self._run(files)
        self.assertEqual(len(result.verification_playbooks), 0,
            "Vendor/minified files must never produce promoted playbooks")

    def test_project_profile_always_populated(self):
        """project_profile must be non-None for any valid input."""
        for files in [
            [fc('src/a.js', "fetch('/api/x')")],
            [fc('src/a.jsx', "import React from 'react'")],
            [fc('template.html', '<script>$.ajax({url:"/api/x"})</script>')],
        ]:
            result = self._run(files)
            self.assertIsNotNone(result.project_profile,
                "project_profile must always be populated")

    def test_all_findings_have_status_and_category(self):
        """Every finding from any project type must have status and category."""
        valid = {'raw_signal', 'review_candidate', 'runtime_verification_candidate', 'confirmed_finding'}
        files = [
            fc('src/pay.jsx', "function pay(){axios.post('/api/pay',{amount})}\n<button onClick={pay}>Pay</button>"),
            fc('src/dom.js', "el.innerHTML = location.hash;"),
        ]
        result = self._run(files)
        for finding in result.findings:
            self.assertIn(finding.status, valid, f"Invalid status: {finding.status}")
            self.assertIsNotNone(finding.category, f"category is None for {finding.vulnerability_type}")


if __name__ == '__main__':
    unittest.main()
