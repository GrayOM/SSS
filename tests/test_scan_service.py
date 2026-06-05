"""
Unit tests for scan_service.scan_extracted_directory.

Verifies that:
- scan_extracted_directory returns an UploadAnalysisResponse
- total_files_scanned, included_count, excluded_count are accurate
- FileAnalysisResult entries carry the correct reason_code, extension, and priority
- InclusionDecision schema is honoured end-to-end (no old tuple-return leakage)
- Multiple project-type layouts produce correct aggregate counts
"""
import tempfile
import unittest
from pathlib import Path

from app.models.schemas import FileAnalysisResult, InclusionDecision, UploadAnalysisResponse
from app.services.scan_service import scan_extracted_directory


class ScanServiceReturnSchemaTests(unittest.TestCase):
    """scan_extracted_directory must return UploadAnalysisResponse with correct schema."""

    def test_returns_upload_analysis_response(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / 'src' / 'app.js'
            p.parent.mkdir()
            p.write_text('const x = 1;')
            result = scan_extracted_directory(Path(td))
        self.assertIsInstance(result, UploadAnalysisResponse)

    def test_file_entries_are_file_analysis_result(self):
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / 'a.js').write_text('x')
            result = scan_extracted_directory(Path(td))
        for entry in result.files:
            self.assertIsInstance(entry, FileAnalysisResult)

    def test_counts_sum_to_total(self):
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / 'a.js').write_text('x')
            (Path(td) / 'b.ts').write_text('x')
            (Path(td) / 'secret.env').write_text('KEY=val')
            result = scan_extracted_directory(Path(td))
        self.assertEqual(
            result.total_files_scanned,
            result.included_count + result.excluded_count,
            'total_files_scanned must equal included + excluded',
        )

    def test_file_entry_has_required_fields(self):
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / 'app.jsx').write_text('import React from "react";')
            result = scan_extracted_directory(Path(td))
        entry = result.files[0]
        self.assertTrue(entry.path)
        self.assertTrue(entry.extension)
        self.assertIsInstance(entry.include, bool)
        self.assertIsInstance(entry.priority, int)
        self.assertTrue(entry.reason)
        self.assertTrue(entry.reason_code)
        self.assertIsInstance(entry.size, int)


class ScanServiceInclusionCountTests(unittest.TestCase):
    """Counts must reflect actual filter decisions for each file type."""

    def _scan(self, files: dict[str, str]) -> UploadAnalysisResponse:
        with tempfile.TemporaryDirectory() as td:
            for rel, content in files.items():
                p = Path(td) / rel
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text(content)
            result = scan_extracted_directory(Path(td))
        return result

    def test_js_ts_jsx_tsx_vue_included(self):
        files = {
            'src/a.js': 'x',
            'src/b.ts': 'x',
            'src/c.jsx': 'x',
            'src/d.tsx': 'x',
            'src/e.vue': 'x',
        }
        result = self._scan(files)
        self.assertEqual(result.included_count, 5)
        self.assertEqual(result.excluded_count, 0)
        self.assertEqual(result.total_files_scanned, 5)

    def test_mjs_cjs_included(self):
        files = {'src/m.mjs': 'export default 1;', 'src/c.cjs': 'module.exports=1;'}
        result = self._scan(files)
        self.assertEqual(result.included_count, 2)
        self.assertEqual(result.excluded_count, 0)

    def test_html_hbs_pug_ejs_included_with_template_priority(self):
        files = {
            'templates/a.html': '<html/>',
            'templates/b.hbs': '{{name}}',
            'templates/c.pug': 'h1 Hello',
            'templates/d.ejs': '<%= x %>',
        }
        result = self._scan(files)
        self.assertEqual(result.included_count, 4)
        for entry in result.files:
            self.assertEqual(entry.reason_code, 'INCLUDED_TEMPLATE',
                f'{entry.path} must be INCLUDED_TEMPLATE')
            self.assertEqual(entry.priority, 3,
                f'{entry.path} must have template priority 3')

    def test_json_package_json_dockerfile_included_as_config(self):
        files = {
            'package.json': '{"name":"x"}',
            'Dockerfile': 'FROM scratch',
            'config.json': '{"key":"val"}',
        }
        result = self._scan(files)
        self.assertEqual(result.included_count, 3)
        for entry in result.files:
            self.assertEqual(entry.reason_code, 'INCLUDED_CONFIG',
                f'{entry.path} must be INCLUDED_CONFIG')

    def test_env_excluded_env_example_sample_included(self):
        files = {
            '.env': 'SECRET=real',
            '.env.example': 'SECRET=your_value',
            '.env.sample': 'SECRET=your_value',
        }
        result = self._scan(files)
        self.assertEqual(result.included_count, 2, '.env.example and .env.sample must be included')
        self.assertEqual(result.excluded_count, 1, '.env must be excluded')
        env_entries = [e for e in result.files if e.path == '.env']
        self.assertFalse(env_entries[0].include)

    def test_min_js_bundle_js_chunk_js_excluded(self):
        # Use src/ (not excluded dir) so the minified-pattern check fires, not dir check
        files = {
            'src/app.min.js': 'x',
            'src/app.bundle.js': 'x',
            'src/vendors.chunk.js': 'x',
            'bundle.js': 'x',
        }
        result = self._scan(files)
        self.assertEqual(result.excluded_count, 4)
        self.assertEqual(result.included_count, 0)
        for entry in result.files:
            self.assertEqual(entry.reason_code, 'EXCLUDED_MINIFIED',
                f'{entry.path} must be EXCLUDED_MINIFIED')

    def test_node_modules_vendor_dist_build_coverage_git_excluded(self):
        excluded_dirs = {
            'node_modules/lodash/index.js': 'x',
            'vendor/jquery.js': 'x',
            'dist/output.js': 'x',
            'build/app.js': 'x',
            'coverage/report.js': 'x',
            '.git/hooks/pre-commit': 'x',
        }
        result = self._scan(excluded_dirs)
        self.assertEqual(result.excluded_count, 6)
        self.assertEqual(result.included_count, 0)
        for entry in result.files:
            self.assertFalse(entry.include, f'{entry.path} must be excluded')
            self.assertEqual(entry.reason_code, 'EXCLUDED_DIR',
                f'{entry.path} must be EXCLUDED_DIR')

    def test_mixed_project_counts(self):
        """Realistic mix: 4 source, 2 template, 1 config, 3 excluded."""
        files = {
            'src/App.jsx': 'import React from "react";',
            'src/api.ts': 'export const BASE="/api";',
            'src/utils.js': 'export const noop=()=>{};',
            'src/App.vue': '<template><div/></template>',
            'templates/index.html': '<html/>',
            'templates/email.hbs': '{{name}}',
            'package.json': '{"name":"app"}',
            'node_modules/axios/index.js': 'x',
            'dist/bundle.js': 'x',
            '.env': 'SECRET=s3cr3t',
        }
        result = self._scan(files)
        self.assertEqual(result.total_files_scanned, 10)
        self.assertEqual(result.included_count, 7)
        self.assertEqual(result.excluded_count, 3)

    def test_source_priority_higher_than_template(self):
        files = {
            'src/app.js': 'const x=1;',
            'templates/page.html': '<p>hi</p>',
        }
        result = self._scan(files)
        js_entry = next(e for e in result.files if e.path.endswith('.js'))
        html_entry = next(e for e in result.files if e.path.endswith('.html'))
        self.assertLess(js_entry.priority, html_entry.priority,
            'Source files (priority=1) must rank above templates (priority=3)')

    def test_empty_directory_returns_zero_counts(self):
        with tempfile.TemporaryDirectory() as td:
            result = scan_extracted_directory(Path(td))
        self.assertEqual(result.total_files_scanned, 0)
        self.assertEqual(result.included_count, 0)
        self.assertEqual(result.excluded_count, 0)
        self.assertEqual(result.files, [])

    def test_path_is_relative_to_extracted_dir(self):
        """File paths in the response must be relative, not absolute."""
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / 'src' / 'app.js').parent.mkdir()
            (Path(td) / 'src' / 'app.js').write_text('x')
            result = scan_extracted_directory(Path(td))
        for entry in result.files:
            self.assertFalse(entry.path.startswith('/'),
                f'Path must be relative, got: {entry.path!r}')
            # Normalized to forward slashes or OS sep
            self.assertIn('src', entry.path)

    def test_webpack_content_signature_excluded(self):
        """Files with webpack runtime content signatures are excluded."""
        files = {
            'public/runtime.js': '__webpack_require__({chunkId:"abc"});',
            'public/app.js': 'self.webpackChunk=[];',
        }
        result = self._scan(files)
        self.assertEqual(result.excluded_count, 2)
        for entry in result.files:
            self.assertFalse(entry.include, f'{entry.path} must be excluded (webpack sig)')

    def test_directories_not_counted(self):
        """scan_extracted_directory must skip directories and only count files."""
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / 'src').mkdir()
            (Path(td) / 'src' / 'app.js').write_text('x')
            result = scan_extracted_directory(Path(td))
        self.assertEqual(result.total_files_scanned, 1,
            'Directories must not be counted in total_files_scanned')

    def test_inclusion_decision_schema_consumed(self):
        """FileAnalysisResult.reason_code must come from InclusionDecision (not a plain tuple)."""
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / 'app.js').write_text('x')
            result = scan_extracted_directory(Path(td))
        entry = result.files[0]
        # reason_code is a string, not a boolean or int (old tuple: (True, 'source file'))
        self.assertIsInstance(entry.reason_code, str)
        self.assertGreater(len(entry.reason_code), 0)
        # Must be one of the known codes, not a generic truthy value
        known_codes = {
            'INCLUDED_SOURCE', 'INCLUDED_CONFIG', 'INCLUDED_TEMPLATE',
            'EXCLUDED_DIR', 'EXCLUDED_EXTENSION', 'EXCLUDED_MINIFIED',
            'EXCLUDED_BINARY', 'EXCLUDED_THIRD_PARTY_LIBRARY', 'EXCLUDED_TOO_LARGE',
        }
        self.assertIn(entry.reason_code, known_codes,
            f'Unexpected reason_code: {entry.reason_code!r}')


if __name__ == '__main__':
    unittest.main()
