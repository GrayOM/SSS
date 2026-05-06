import tempfile
import unittest
from pathlib import Path
from zipfile import ZIP_STORED, ZipInfo, ZipFile

from app.core.config import settings
from app.services.file_filter_service import should_include_file
from app.services.zip_service import ZipSecurityError, extract_zip


class FilterPolicyTests(unittest.TestCase):
    def test_ts_tsx_vue_ejs_included(self):
        with tempfile.TemporaryDirectory() as td:
            for ext in ('.ts', '.tsx', '.vue', '.ejs'):
                file_path = Path(td) / f'file{ext}'
                file_path.write_text('ok')
                self.assertTrue(should_include_file(file_path).include)

    def test_env_excluded_and_env_example_included(self):
        with tempfile.TemporaryDirectory() as td:
            env_file = Path(td) / '.env'
            env_file.write_text('SECRET=x')
            self.assertFalse(should_include_file(env_file).include)

            env_example = Path(td) / '.env.example'
            env_example.write_text('KEY=VALUE')
            self.assertTrue(should_include_file(env_example).include)

    def test_dockerfile_and_package_json_included(self):
        with tempfile.TemporaryDirectory() as td:
            dockerfile = Path(td) / 'Dockerfile'
            dockerfile.write_text('FROM scratch')
            self.assertTrue(should_include_file(dockerfile).include)

            package_json = Path(td) / 'package.json'
            package_json.write_text('{"name": "x"}')
            self.assertTrue(should_include_file(package_json).include)

    def test_node_modules_and_dist_excluded(self):
        with tempfile.TemporaryDirectory() as td:
            nm_path = Path(td) / 'node_modules' / 'index.js'
            nm_path.parent.mkdir(parents=True)
            nm_path.write_text('x')
            self.assertFalse(should_include_file(nm_path).include)

            dist_path = Path(td) / 'dist' / 'bundle.js'
            dist_path.parent.mkdir(parents=True)
            dist_path.write_text('x')
            self.assertFalse(should_include_file(dist_path).include)

    def test_jquery_custom_included_and_jquery_min_excluded(self):
        with tempfile.TemporaryDirectory() as td:
            custom = Path(td) / 'jquery-custom-validation.js'
            custom.write_text('const x=1')
            self.assertTrue(should_include_file(custom).include)

            minified = Path(td) / 'jquery.min.js'
            minified.write_text('minified')
            decision = should_include_file(minified)
            self.assertFalse(decision.include)
            self.assertEqual(decision.reason_code, 'EXCLUDED_MINIFIED')


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

    def test_symlink_entry_is_blocked(self):
        with tempfile.TemporaryDirectory() as td:
            upload = Path(td) / 'symlink.zip'
            workspace = Path(td) / 'ws'
            workspace.mkdir()

            zi = ZipInfo('link')
            zi.create_system = 3
            zi.external_attr = 0o120777 << 16
            with ZipFile(upload, 'w') as zf:
                zf.writestr(zi, 'target')

            with self.assertRaises(ZipSecurityError):
                extract_zip(upload, workspace)

    def test_member_count_limit_exceeded(self):
        with tempfile.TemporaryDirectory() as td:
            upload = Path(td) / 'many.zip'
            workspace = Path(td) / 'ws'
            workspace.mkdir()

            original = settings.MAX_ZIP_MEMBERS
            settings.MAX_ZIP_MEMBERS = 1
            try:
                with ZipFile(upload, 'w', compression=ZIP_STORED) as zf:
                    zf.writestr('a.js', '1')
                    zf.writestr('b.js', '2')
                with self.assertRaises(ZipSecurityError):
                    extract_zip(upload, workspace)
            finally:
                settings.MAX_ZIP_MEMBERS = original

    def test_uncompressed_size_limit_exceeded(self):
        with tempfile.TemporaryDirectory() as td:
            upload = Path(td) / 'large.zip'
            workspace = Path(td) / 'ws'
            workspace.mkdir()

            original = settings.MAX_UNCOMPRESSED_SIZE_MB
            settings.MAX_UNCOMPRESSED_SIZE_MB = 0
            try:
                with ZipFile(upload, 'w', compression=ZIP_STORED) as zf:
                    zf.writestr('big.js', 'abc')
                with self.assertRaises(ZipSecurityError):
                    extract_zip(upload, workspace)
            finally:
                settings.MAX_UNCOMPRESSED_SIZE_MB = original


if __name__ == '__main__':
    unittest.main()
