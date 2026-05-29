import unittest

from fastapi.testclient import TestClient

from app.main import app


class RoutesUiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)

    def test_get_root_returns_index_html(self):
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)
        html = response.text
        self.assertTrue(
            'ZIP' in html or '소스코드' in html or '취약점 분석' in html,
            'Expected upload UI text not found in index page',
        )

    def test_static_app_js_served(self):
        response = self.client.get('/static/app.js')
        self.assertEqual(response.status_code, 200)

    def test_static_app_js_renders_sss_v1_fields_without_raw_source_snippet(self):
        response = self.client.get('/static/app.js')
        self.assertEqual(response.status_code, 200)
        js = response.text
        for field in [
            '${path}:${start}-${end}',
            'Console verification code was not generated.',
            'Source location:',
            'Risk:',
            'Confidence:',
            'function_name',
            'root_cause',
            'why_exploitable',
            'data_flow',
            'breakpoint_plan',
            'poc_injection_plan',
            'verification_playbook.console_code',
            'success_criteria',
            'failure_criteria',
        ]:
            self.assertIn(field, js)
        self.assertNotIn('ev.snippet', js)
        self.assertNotIn('근거 snippet', js)

    def test_static_styles_css_served(self):
        response = self.client.get('/static/styles.css')
        self.assertEqual(response.status_code, 200)


if __name__ == '__main__':
    unittest.main()
