import tempfile
import unittest
from pathlib import Path
from zipfile import ZipFile

from app.services.file_filter_service import should_include_file
from app.services.zip_service import ZipSecurityError, extract_zip


class FilterPolicyTests(unittest.TestCase):
    def test_jquery_custom_validation_is_included(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / 'jquery-custom-validation.js'
            path.write_text('const x = 1;')
            d = should_include_file(path)
            self.assertTrue(d.include)

    def test_jquery_min_is_excluded(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / 'jquery.min.js'
            path.write_text('minified')
            d = should_include_file(path)
            self.assertFalse(d.include)
            self.assertEqual(d.reason_code, 'EXCLUDED_MINIFIED')

    def test_ts_tsx_vue_ejs_are_included(self):
        with tempfile.TemporaryDirectory() as td:
            for ext in ('.ts', '.tsx', '.vue', '.ejs'):
                path = Path(td) / f'file{ext}'
                path.write_text('test')
                self.assertTrue(should_include_file(path).include)

    def test_node_modules_is_excluded(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / 'node_modules' / 'a.js'
            path.parent.mkdir(parents=True)
            path.write_text('const y = 2;')
            d = should_include_file(path)
            self.assertFalse(d.include)
            self.assertEqual(d.reason_code, 'EXCLUDED_DIR')


class ZipSecurityTests(unittest.TestCase):
    def test_zip_slip_is_blocked(self):
        with tempfile.TemporaryDirectory() as td:
            upload = Path(td) / 'bad.zip'
            workspace = Path(td) / 'ws'
            workspace.mkdir()
            with ZipFile(upload, 'w') as zf:
                zf.writestr('../escape.js', 'oops')

            with self.assertRaises(ZipSecurityError):
                extract_zip(upload, workspace)


if __name__ == '__main__':
    unittest.main()
