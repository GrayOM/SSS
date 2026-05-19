import unittest

from app.models.schemas import CodeChunk
from app.services.analysis_service import MockAnalyzer, analyze_chunks, get_analyzer


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


class FakeAnalyzer:
    def analyze_chunk(self, chunk: CodeChunk):
        return []


class AnalysisServiceTests(unittest.TestCase):
    def test_empty_chunks_returns_valid_result(self):
        result = analyze_chunks([])
        self.assertEqual(result.total_chunks, 0)
        self.assertEqual(result.analyzed_chunks, 0)
        self.assertEqual(result.finding_count, 0)

    def test_dom_xss_pattern_creates_finding(self):
        content = 'el.innerHTML = location.hash;'
        result = analyze_chunks([_chunk(content)])
        self.assertEqual(result.finding_count, 1)
        self.assertEqual(result.findings[0].vulnerability_type, 'DOM XSS')


    def test_webpack_chunk_dom_xss_not_reported(self):
        content = 'self.webpackChunkgatsby=[]; el.innerHTML = location.hash;'
        result = analyze_chunks([_chunk(content)])
        self.assertEqual(result.finding_count, 0)

    def test_empty_innerhtml_not_reported(self):
        result = analyze_chunks([_chunk('el.innerHTML = "";')])
        self.assertEqual(result.finding_count, 0)

    def test_static_innerhtml_not_reported(self):
        result = analyze_chunks([_chunk("el.innerHTML = '<span>static</span>';" )])
        self.assertEqual(result.finding_count, 0)

    def test_eval_pattern_creates_finding(self):
        result = analyze_chunks([_chunk('eval(userInput)')])
        self.assertEqual(result.finding_count, 1)
        self.assertEqual(result.findings[0].vulnerability_type, 'Unsafe eval')

    def test_command_injection_pattern_creates_finding(self):
        result = analyze_chunks([_chunk("require('child_process').exec(userInput)")])
        self.assertEqual(result.finding_count, 1)
        self.assertEqual(result.findings[0].vulnerability_type, 'Command Injection')

    def test_multiple_findings_in_one_chunk(self):
        chunk = _chunk('el.innerHTML = location.hash; eval(userInput);')
        result = analyze_chunks([chunk])
        self.assertEqual(result.finding_count, 2)
        vuln_types = {f.vulnerability_type for f in result.findings}
        self.assertIn('DOM XSS', vuln_types)
        self.assertIn('Unsafe eval', vuln_types)

    def test_regex_exec_is_not_command_injection(self):
        result = analyze_chunks([_chunk('const result = /a/.exec(input);')])
        self.assertEqual(result.finding_count, 0)

    def test_finding_id_is_deterministic(self):
        chunk = _chunk('eval(userInput)', idx=3)
        r1 = analyze_chunks([chunk])
        r2 = analyze_chunks([chunk])
        self.assertEqual(r1.findings[0].id, r2.findings[0].id)

    def test_ids_are_unique_for_multiple_findings_in_same_chunk(self):
        chunk = _chunk('el.innerHTML = location.hash; eval(userInput);')
        result = analyze_chunks([chunk])
        self.assertEqual(len(result.findings), 2)
        self.assertNotEqual(result.findings[0].id, result.findings[1].id)

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

    def test_analyze_chunks_uses_injected_analyzer(self):
        class CountingAnalyzer:
            def __init__(self):
                self.called = 0

            def analyze_chunk(self, chunk: CodeChunk):
                self.called += 1
                return []

        analyzer = CountingAnalyzer()
        analyze_chunks([_chunk('const a = 1;')], analyzer=analyzer)
        self.assertEqual(analyzer.called, 1)

    def test_analyze_chunks_uses_get_analyzer_when_none(self):
        from app.services import analysis_service

        original = analysis_service.get_analyzer
        try:
            analysis_service.get_analyzer = lambda: FakeAnalyzer()
            result = analyze_chunks([_chunk('const a = 1;')])
            self.assertEqual(result.finding_count, 0)
        finally:
            analysis_service.get_analyzer = original

    def test_analyze_chunks_with_mock_backend_setting(self):
        from app.services import analysis_service

        original_backend = analysis_service.settings.ANALYZER_BACKEND
        try:
            analysis_service.settings.ANALYZER_BACKEND = 'mock'
            result = analyze_chunks([_chunk('eval(userInput)')])
            self.assertEqual(result.finding_count, 1)
            self.assertEqual(result.findings[0].vulnerability_type, 'Unsafe eval')
        finally:
            analysis_service.settings.ANALYZER_BACKEND = original_backend

    def test_get_analyzer_returns_mock_for_mock_backend(self):
        from app.services import analysis_service

        original_backend = analysis_service.settings.ANALYZER_BACKEND
        try:
            analysis_service.settings.ANALYZER_BACKEND = 'mock'
            analyzer = get_analyzer()
            self.assertIsInstance(analyzer, MockAnalyzer)
        finally:
            analysis_service.settings.ANALYZER_BACKEND = original_backend

    def test_get_analyzer_raises_for_unknown_backend(self):
        from app.services import analysis_service

        original_backend = analysis_service.settings.ANALYZER_BACKEND
        try:
            analysis_service.settings.ANALYZER_BACKEND = 'unknown'
            with self.assertRaises(ValueError) as cm:
                get_analyzer()
            self.assertIn('Supported backends: mock, gemini.', str(cm.exception))
            self.assertIn('OpenAI/Claude backends are not implemented yet.', str(cm.exception))
        finally:
            analysis_service.settings.ANALYZER_BACKEND = original_backend


if __name__ == '__main__':
    unittest.main()
