import unittest

from app.models.schemas import CodeChunk, FileContent
from app.services.prompt_builder import build_analysis_prompt, build_console_poc_analysis_prompt


class PromptBuilderTests(unittest.TestCase):
    def test_build_analysis_prompt_has_schema_fields(self):
        prompt = build_analysis_prompt(CodeChunk(source_path='a.js', extension='.js', priority=1, source_content_hash='h', chunk_index=0, total_chunks=1, start_line=1, end_line=2, chunk_hash='c', content='x'))
        self.assertIn('Return schema example', prompt)
        for k in ['vulnerability_type', 'severity', 'confidence', 'evidence', 'attack_scenario', 'safe_poc', 'impact', 'root_cause', 'remediation', 'related_cwe']:
            self.assertIn(k, prompt)

    def test_console_prompt_has_lines_and_tail_keyword(self):
        long_content = '\n'.join(['line'] * 200 + ['tail innerHTML location.hash'])
        files = [FileContent(path='src/a.js', extension='.js', size=len(long_content), priority=1, reason_code='INCLUDED', content_hash='h', content=long_content)]
        prompt = build_console_poc_analysis_prompt(files)
        self.assertIn('[LINES', prompt)
        self.assertIn('tail innerHTML location.hash', prompt)


if __name__ == '__main__':
    unittest.main()
