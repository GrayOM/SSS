import unittest

from app.models.schemas import AnalysisResult, CodeChunk
from app.services.response_mapper import to_safe_analysis_result


class ResponseMapperTests(unittest.TestCase):
    def test_to_safe_analysis_result_removes_skipped_chunks(self):
        chunk = CodeChunk(
            source_path='src/app.js',
            extension='.js',
            priority=1,
            source_content_hash='h',
            chunk_index=0,
            total_chunks=1,
            start_line=1,
            end_line=1,
            chunk_hash='c',
            content='',
        )
        result = AnalysisResult(total_chunks=1, analyzed_chunks=0, finding_count=0, findings=[], skipped_chunks=[chunk])
        safe = to_safe_analysis_result(result)
        self.assertEqual(len(result.skipped_chunks), 1)
        self.assertEqual(safe.skipped_chunks, [])


if __name__ == '__main__':
    unittest.main()
