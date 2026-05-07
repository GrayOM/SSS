import unittest

from app.models.schemas import FileContent
from app.services.console_poc_analysis_service import (
    MockConsolePocAnalyzer,
    analyze_console_exploitability,
    select_console_relevant_files,
)


def f(path, content):
    return FileContent(path=path, extension='.js', size=len(content), priority=1, reason_code='INCLUDED', content_hash='h', content=content)


class ConsolePocAnalysisTests(unittest.TestCase):
    def test_select_relevant_files(self):
        files = [f('src/login.js', 'const token = localStorage.getItem("t")'), f('src/a.js', 'const x=1')]
        selected = select_console_relevant_files(files)
        self.assertEqual(selected[0].path, 'src/login.js')

    def test_auth_bypass_finding(self):
        files = [f('src/auth.js', "if(userType==='ADMIN'){navigate('/admin')}")]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        self.assertTrue(any(x.vulnerability_type == 'Client-side Authorization Bypass' for x in result.findings))

    def test_dom_xss_finding(self):
        files = [f('src/x.js', 'const x=location.hash; el.innerHTML=x;')]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        self.assertTrue(any(x.vulnerability_type == 'DOM XSS' for x in result.findings))

    def test_validation_bypass_finding(self):
        files = [f('src/pay.js', 'const price=1; const fd = new FormData(); axios.post("/api/order", fd);')]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        self.assertTrue(any(x.vulnerability_type == 'Client-side Validation Bypass' for x in result.findings))

    def test_console_poc_type_and_safety(self):
        files = [f('src/x.js', 'const x=location.hash; el.innerHTML=x;')]
        result = analyze_console_exploitability(files, analyzer=MockConsolePocAnalyzer())
        poc = result.findings[0].console_poc
        self.assertEqual(poc.poc_type, 'browser_console')
        self.assertNotIn('delete', (poc.code or '').lower())
        self.assertNotIn('payment', (poc.code or '').lower())


if __name__ == '__main__':
    unittest.main()
