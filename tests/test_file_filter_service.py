import tempfile
import unittest
from pathlib import Path

from app.services.file_filter_service import should_include_file


class FileFilterServiceTests(unittest.TestCase):
    def test_gatsby_webpack_hashed_files_excluded(self):
        names = [
            'app-bd3d900226fb938894f0.js',
            'commons-0c93c27e22e15f6b978b.js',
            'framework-481beeb6bc5ccc2a4757.js',
            'component---src-templates-page-js-994cbc94a939325112f0.js',
            'webpack-runtime-e40458c34c56e5b4d6a1.js',
            '108-2b0f895ed536225b58f0.js',
        ]
        with tempfile.TemporaryDirectory() as td:
            for name in names:
                p = Path(td) / name
                p.write_text('const x = 1;')
                d = should_include_file(p)
                self.assertFalse(d.include)
                self.assertEqual(d.reason_code, 'EXCLUDED_MINIFIED')

    def test_application_common_main_are_included(self):
        with tempfile.TemporaryDirectory() as td:
            for name in ('application.js', 'common.js', 'main.js'):
                p = Path(td) / name
                p.write_text('const x = 1;')
                self.assertTrue(should_include_file(p).include)

    def test_jquery_ui_stays_third_party_excluded(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / 'jquery-ui.js'
            p.write_text('const x = 1;')
            d = should_include_file(p)
            self.assertFalse(d.include)
            self.assertEqual(d.reason_code, 'EXCLUDED_THIRD_PARTY_LIBRARY')

    def test_content_signature_excludes_random_js(self):
        with tempfile.TemporaryDirectory() as td:
            for i, sig in enumerate(('self.webpackChunk', '__webpack_require__')):
                p = Path(td) / f'random{i}.js'
                p.write_text(f'const a=1; {sig}(x);')
                d = should_include_file(p)
                self.assertFalse(d.include)
                self.assertEqual(d.reason_code, 'EXCLUDED_MINIFIED')


if __name__ == '__main__':
    unittest.main()
