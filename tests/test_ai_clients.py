import unittest

from app.services.ai_clients import GeminiClient, MockGeminiClient


class AIClientsTests(unittest.TestCase):
    def test_gemini_client_requires_api_key(self):
        with self.assertRaises(ValueError):
            GeminiClient(api_key=None, model='gemini-2.5-flash-lite')

    def test_mock_gemini_client_returns_strings(self):
        client = MockGeminiClient()
        self.assertIsInstance(client.analyze('x'), str)
        self.assertIsInstance(client.generate('y'), str)


if __name__ == '__main__':
    unittest.main()
