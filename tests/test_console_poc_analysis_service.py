import unittest

from app.models.schemas import FileContent
from app.services.console_poc_analysis_service import GeminiConsolePocAnalyzer, MockConsolePocAnalyzer, analyze_console_exploitability, select_console_relevant_files


def f(path, content):
    return FileContent(path=path, extension='.js', size=len(content), priority=1, reason_code='INCLUDED', content_hash='h', content=content)


class FakeGeminiClient:
    def __init__(self, payload): self.payload = payload
    def analyze(self, prompt: str) -> str: return self.payload
    def generate(self, prompt: str) -> str: return ''


class ConsolePocAnalysisTests(unittest.TestCase):
    def test_select_relevant_files_case_insensitive_content(self):
        selected = select_console_relevant_files([f('src/a.js', 'const Role = "ADMIN"; const x = LocalStorage.getItem("u")')])
        self.assertEqual(len(selected), 1)

    def test_auth_dom_validation_findings(self):
        r1 = analyze_console_exploitability([f('src/auth.js', "if(userType==='ADMIN'){navigate('/admin')}")], analyzer=MockConsolePocAnalyzer())
        self.assertTrue(any(x.vulnerability_type == 'Client-side Authorization Bypass' for x in r1.findings))
        r2 = analyze_console_exploitability([f('src/x.js', 'const x=location.hash; el.innerHTML=x;')], analyzer=MockConsolePocAnalyzer())
        self.assertTrue(any(x.vulnerability_type == 'DOM XSS' for x in r2.findings))
        r3 = analyze_console_exploitability([f('src/pay.js', 'const price=1; const fd = new FormData(); axios.post("/api/order", fd);')], analyzer=MockConsolePocAnalyzer())
        self.assertTrue(any(x.vulnerability_type == 'Client-side Validation Bypass' for x in r3.findings))

    def test_gemini_fenced_json_parse(self):
        analyzer = GeminiConsolePocAnalyzer(FakeGeminiClient('```json\n{"findings": []}\n```'))
        self.assertEqual(analyzer.analyze([f('src/a.js', 'x')]), [])

    def test_dangerous_poc_removed_and_note_added(self):
        payload = '{"findings":[{"id":"1","title":"t","vulnerability_type":"DOM XSS","severity":"high","confidence":"medium","affected_files":["a"],"summary":"s","evidence":[{"source_path":"a","start_line":1,"end_line":1,"snippet":"x","reason":"r"}],"console_poc":{"poc_type":"browser_console","description":"d","preconditions":[],"steps":[],"code":"fetch(\"/pay\")","expected_result":"e","safety":"s"},"attack_scenario":["a"],"impact":"i","root_cause":"r","remediation":"m"}]}'
        findings = GeminiConsolePocAnalyzer(FakeGeminiClient(payload)).analyze([f('src/a.js', 'x')])
        self.assertIsNone(findings[0].console_poc.code)
        self.assertIn('위험 요청 가능성이 있어 Console PoC code를 제거했습니다.', findings[0].verification_notes)


if __name__ == '__main__':
    unittest.main()
