import unittest

from app.models.schemas import CodeChunk
from app.services.analysis_service import analyze_chunks


def _chunk(content: str, idx: int = 0) -> CodeChunk:
    return CodeChunk(
        source_path='src/app.js',
        extension='.js',
        priority=1,
        source_content_hash='sourcehash',
        chunk_index=idx,
        total_chunks=1,
        start_line=1,
        end_line=5,
        chunk_hash='chunkhash',
        content=content,
    )


class AnalysisServiceTests(unittest.TestCase):
    def test_empty_chunks_returns_valid_result(self):
        result = analyze_chunks([])
        self.assertEqual(result.total_chunks, 0)
        self.assertEqual(result.analyzed_chunks, 0)
        self.assertEqual(result.finding_count, 0)

    def test_dom_xss_pattern_creates_finding(self):
        content = "el.innerHTML = location.hash;"
        result = analyze_chunks([_chunk(content)])
        self.assertEqual(result.finding_count, 1)
        self.assertEqual(result.findings[0].vulnerability_type, 'DOM XSS')

    def test_eval_pattern_creates_finding(self):
        result = analyze_chunks([_chunk('eval(userInput)')])
        self.assertEqual(result.finding_count, 1)
        self.assertEqual(result.findings[0].vulnerability_type, 'Unsafe eval')

    def test_command_injection_pattern_creates_finding(self):
        result = analyze_chunks([_chunk('exec(userInput)')])
        self.assertEqual(result.finding_count, 1)
        self.assertEqual(result.findings[0].vulnerability_type, 'Command Injection')

    def test_finding_id_is_deterministic(self):
        chunk = _chunk('eval(userInput)', idx=3)
        r1 = analyze_chunks([chunk])
        r2 = analyze_chunks([chunk])
        self.assertEqual(r1.findings[0].id, r2.findings[0].id)

    def test_counts_are_correct(self):
        chunks = [_chunk('eval(x)'), _chunk('safe code', idx=1), _chunk('', idx=2)]
        result = analyze_chunks(chunks)
        self.assertEqual(result.total_chunks, 3)
        self.assertEqual(result.analyzed_chunks, 2)
        self.assertEqual(result.finding_count, 1)
        self.assertEqual(len(result.skipped_chunks), 1)

    def test_evidence_fields_present(self):
        result = analyze_chunks([_chunk('eval(x)')])
        evidence = result.findings[0].evidence[0]
        self.assertEqual(evidence.source_path, 'src/app.js')
        self.assertEqual(evidence.start_line, 1)
        self.assertEqual(evidence.end_line, 5)

    def test_safe_code_generates_no_finding(self):
        result = analyze_chunks([_chunk('const x = 1;')])
        self.assertEqual(result.finding_count, 0)


if __name__ == '__main__':
    unittest.main()
