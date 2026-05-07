import unittest

from app.models.schemas import CodeChunk, FileContent
from app.services.prompt_builder import build_analysis_prompt, build_console_poc_analysis_prompt


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
        self.assertIn('Evidence', prompt)

    def test_console_prompt_contains_required_security_instructions(self):
        long_content = 'a' * 1400 + ' innerHTML ... location.hash ...'
        files = [FileContent(path='src/a.js', extension='.js', size=len(long_content), priority=1, reason_code='INCLUDED', content_hash='h', content=long_content)]
        prompt = build_console_poc_analysis_prompt(files)
        self.assertIn('source -> state/storage/API/DOM sink', prompt)
        self.assertIn('Return JSON only', prompt)
        self.assertIn('Do not create findings without code evidence', prompt)
        self.assertIn('non-destructive verification only', prompt)
        self.assertIn('{"findings": []}', prompt)
        self.assertIn('[SNIPPET', prompt)
        self.assertIn('innerHTML', prompt)


if __name__ == '__main__':
    unittest.main()
