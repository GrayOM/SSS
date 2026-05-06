import unittest

from app.models.schemas import CodeChunk
from app.services.prompt_builder import build_analysis_prompt


class PromptBuilderTests(unittest.TestCase):
    def test_prompt_contains_required_fields_and_rules(self):
        chunk = CodeChunk(
            source_path='src/a.js', extension='.js', priority=1, source_content_hash='h',
            chunk_index=0, total_chunks=1, start_line=10, end_line=20, chunk_hash='ch',
            content='el.innerHTML = location.hash;'
        )
        prompt = build_analysis_prompt(chunk)
        self.assertIn('src/a.js', prompt)
        self.assertIn('start_line: 10', prompt)
        self.assertIn('end_line: 20', prompt)
        self.assertIn('el.innerHTML = location.hash;', prompt)
        self.assertIn('Evidence', prompt)
        self.assertIn('destructive exploit', prompt)
        self.assertIn('{"findings": []}', prompt)
        self.assertIn('markdown code fence를 사용하지 마라', prompt)
        self.assertIn('JSON 외 설명 문장을 출력하지 마라', prompt)
        self.assertIn('severity는 low, medium, high, critical', prompt)
        self.assertIn('confidence는 low, medium, high', prompt)


if __name__ == '__main__':
    unittest.main()
