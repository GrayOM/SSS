import unittest

from app.models.schemas import FileContent
from app.services.console_poc_analysis_service import (
    GeminiConsolePocAnalyzer,
    MockConsolePocAnalyzer,
    analyze_console_exploitability,
    select_console_relevant_files,
)


def f(path, content):
    return FileContent(path=path, extension='.js', size=len(content), priority=1, reason_code='INCLUDED', content_hash='h', content=content)


class FakeGeminiClient:
    def __init__(self, payload):
        self.payload = payload

    def analyze(self, prompt: str) -> str:
        return self.payload

    def generate(self, prompt: str) -> str:
        return ''


class ConsolePocAnalysisTests(unittest.TestCase):
    def test_select_relevant_files(self):
        files = [f('src/login.js', 'const token = localStorage.getItem("t")'), f('src/a.js', 'const x=1')]
        selected = select_console_relevant_files(files)
        self.assertEqual(selected[0].path, 'src/login.js')

    def test_auth_bypass_finding(self):
        result = analyze_console_exploitability([f('src/auth.js', "if(userType==='ADMIN'){navigate('/admin')}")], analyzer=MockConsolePocAnalyzer())
        self.assertTrue(any(x.vulnerability_type == 'Client-side Authorization Bypass' for x in result.findings))

    def test_dom_xss_finding(self):
        result = analyze_console_exploitability([f('src/x.js', 'const x=location.hash; el.innerHTML=x;')], analyzer=MockConsolePocAnalyzer())
        self.assertTrue(any(x.vulnerability_type == 'DOM XSS' for x in result.findings))

    def test_validation_bypass_finding(self):
        result = analyze_console_exploitability([f('src/pay.js', 'const price=1; const fd = new FormData(); axios.post("/api/order", fd);')], analyzer=MockConsolePocAnalyzer())
        self.assertTrue(any(x.vulnerability_type == 'Client-side Validation Bypass' for x in result.findings))

    def test_console_poc_type_and_safety(self):
        result = analyze_console_exploitability([f('src/x.js', 'const x=location.hash; el.innerHTML=x;')], analyzer=MockConsolePocAnalyzer())
        poc = result.findings[0].console_poc
        self.assertEqual(poc.poc_type, 'browser_console')
        self.assertNotIn('delete', (poc.code or '').lower())

    def test_gemini_parser_supports_fenced_json(self):
        payload = '```json\n{"findings": []}\n```'
        analyzer = GeminiConsolePocAnalyzer(FakeGeminiClient(payload))
        self.assertEqual(analyzer.analyze([f('src/a.js', 'x')]), [])

    def test_gemini_invalid_severity_confidence_skipped(self):
        payload = '{"findings":[{"id":"1","title":"t","vulnerability_type":"DOM XSS","severity":"urgent","confidence":"certain","affected_files":["a"],"summary":"s","evidence":[{"source_path":"a","start_line":1,"end_line":1,"snippet":"x","reason":"r"}],"attack_scenario":["a"],"impact":"i","root_cause":"r","remediation":"m"}]}'
        analyzer = GeminiConsolePocAnalyzer(FakeGeminiClient(payload))
        self.assertEqual(analyzer.analyze([f('src/a.js', 'x')]), [])

    def test_gemini_empty_evidence_skipped(self):
        payload = '{"findings":[{"id":"1","title":"t","vulnerability_type":"DOM XSS","severity":"high","confidence":"medium","affected_files":["a"],"summary":"s","evidence":[],"attack_scenario":["a"],"impact":"i","root_cause":"r","remediation":"m"}]}'
        analyzer = GeminiConsolePocAnalyzer(FakeGeminiClient(payload))
        self.assertEqual(analyzer.analyze([f('src/a.js', 'x')]), [])

    def test_gemini_dangerous_poc_code_removed(self):
        payload = '{"findings":[{"id":"1","title":"t","vulnerability_type":"DOM XSS","severity":"high","confidence":"medium","affected_files":["a"],"summary":"s","evidence":[{"source_path":"a","start_line":1,"end_line":1,"snippet":"x","reason":"r"}],"console_poc":{"poc_type":"browser_console","description":"d","preconditions":[],"steps":[],"code":"fetch(\"/pay\")","expected_result":"e","safety":"s"},"attack_scenario":["a"],"impact":"i","root_cause":"r","remediation":"m"}]}'
        analyzer = GeminiConsolePocAnalyzer(FakeGeminiClient(payload))
        findings = analyzer.analyze([f('src/a.js', 'x')])
        self.assertEqual(findings[0].console_poc.code, None)


if __name__ == '__main__':
    unittest.main()
