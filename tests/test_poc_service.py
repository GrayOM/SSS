import unittest

from app.models.schemas import AnalysisEvidence, VulnerabilityFinding
from app.services.poc_service import GeminiPocGenerator, MockPocGenerator


class FakeGeminiClient:
    def __init__(self, response: str):
        self.response = response
        self.called = False
        self.last_prompt = ''

    def analyze(self, prompt: str) -> str:
        return '{}'

    def generate(self, prompt: str) -> str:
        self.called = True
        self.last_prompt = prompt
        return self.response


def _finding(safe_poc=None):
    return VulnerabilityFinding(
        id='1', vulnerability_type='DOM XSS', severity='high', confidence='medium',
        source_path='src/a.js', start_line=1, end_line=2,
        evidence=[AnalysisEvidence(source_path='src/a.js', start_line=1, end_line=2, snippet='x', reason='r')],
        attack_scenario=['a'], safe_poc=safe_poc, impact='i', root_cause='r', remediation='m', related_cwe=['CWE-79']
    )


class PocServiceTests(unittest.TestCase):
    def test_gemini_poc_generator_calls_client_and_returns_response(self):
        client = FakeGeminiClient('SAFE_POC')
        svc = GeminiPocGenerator(client)
        result = svc.generate_safe_poc(_finding())
        self.assertTrue(client.called)
        self.assertIn('destructive payload 금지', client.last_prompt)
        self.assertEqual(result, 'SAFE_POC')

    def test_mock_poc_generator_returns_existing_safe_poc(self):
        svc = MockPocGenerator()
        self.assertEqual(svc.generate_safe_poc(_finding('POC')), 'POC')

    def test_mock_poc_generator_returns_default_when_missing(self):
        svc = MockPocGenerator()
        self.assertEqual(svc.generate_safe_poc(_finding(None)), 'Safe PoC not generated')


if __name__ == '__main__':
    unittest.main()
