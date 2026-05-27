from typing import Protocol


class GeminiClientProtocol(Protocol):
    def analyze(self, prompt: str) -> str:
        ...

    def generate(self, prompt: str) -> str:
        ...


class MockGeminiClient:
    def analyze(self, prompt: str) -> str:
        return '{"findings": []}'

    def generate(self, prompt: str) -> str:
        return 'Safe PoC not generated'


class GeminiClient:
    def __init__(self, api_key: str | None, model: str):
        if not api_key:
            raise ValueError('GEMINI_API_KEY is required')
        self.api_key = api_key
        self.model = model

    def _build_client(self):
        from google import genai

        return genai.Client(api_key=self.api_key)

    def analyze(self, prompt: str) -> str:
        client = self._build_client()
        try:
            response = client.models.generate_content(model=self.model, contents=prompt)
        except Exception as exc:
            raise RuntimeError('Gemini API request failed') from exc
        return getattr(response, 'text', '') or ''

    def generate(self, prompt: str) -> str:
        client = self._build_client()
        try:
            response = client.models.generate_content(model=self.model, contents=prompt)
        except Exception as exc:
            raise RuntimeError('Gemini API request failed') from exc
        return getattr(response, 'text', '') or ''
