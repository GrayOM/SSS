import unittest

from app.models.schemas import CodeChunk
from app.services.analysis_service import GeminiAnalyzer


class FakeGeminiClient:
    def __init__(self, payload: str):
        self.payload = payload
        self.called = False

    def analyze(self, prompt: str) -> str:
        self.called = True
        return self.payload

    def generate(self, prompt: str) -> str:
        return 'poc'


def _chunk() -> CodeChunk:
    return CodeChunk(
        source_path='src/app.js', extension='.js', priority=1, source_content_hash='h',
        chunk_index=0, total_chunks=1, start_line=1, end_line=10, chunk_hash='ch', content='x'
    )


class GeminiAnalyzerTests(unittest.TestCase):
    def test_valid_json_converts_to_findings(self):
        payload = '{"findings":[{"vulnerability_type":"DOM XSS","severity":"high","confidence":"medium","source_path":"src/app.js","start_line":1,"end_line":10,"evidence":[{"source_path":"src/app.js","start_line":1,"end_line":10,"snippet":"x","reason":"r"}],"attack_scenario":["a"],"safe_poc":"p","impact":"i","root_cause":"r","remediation":"m","related_cwe":["CWE-79"]}]}'
        client = FakeGeminiClient(payload)
        analyzer = GeminiAnalyzer(client)
        findings = analyzer.analyze_chunk(_chunk())
        self.assertEqual(len(findings), 1)
        self.assertTrue(client.called)

    def test_invalid_json_returns_empty(self):
        analyzer = GeminiAnalyzer(FakeGeminiClient('not json'))
        self.assertEqual(analyzer.analyze_chunk(_chunk()), [])

    def test_missing_findings_key_returns_empty(self):
        analyzer = GeminiAnalyzer(FakeGeminiClient('{"result":[]}'))
        self.assertEqual(analyzer.analyze_chunk(_chunk()), [])

    def test_missing_required_fields_skipped(self):
        analyzer = GeminiAnalyzer(FakeGeminiClient('{"findings":[{"severity":"high"}]}'))
        self.assertEqual(analyzer.analyze_chunk(_chunk()), [])


if __name__ == '__main__':
    unittest.main()
