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



    def test_config_filename_included_and_old_backup_excluded(self):
        with tempfile.TemporaryDirectory() as td:
            cfg = Path(td) / 'config.js'
            cfg.write_text('export default {}')
            self.assertTrue(should_include_file(cfg).include)

            backup = Path(td) / 'old-config-backup.txt'
            backup.write_text('legacy')
            self.assertFalse(should_include_file(backup).include)



    def test_webpack_config_included_as_config(self):
        with tempfile.TemporaryDirectory() as td:
            file_path = Path(td) / 'webpack.config.js'
            file_path.write_text('module.exports = {}')
            decision = should_include_file(file_path)
            self.assertTrue(decision.include)
            self.assertEqual(decision.reason_code, 'INCLUDED_CONFIG')

    def test_bundle_patterns_excluded(self):
        with tempfile.TemporaryDirectory() as td:
            for name in ('webpack.bundle.js', 'app.bundle.js'):
                file_path = Path(td) / name
                file_path.write_text('bundle')
                decision = should_include_file(file_path)
                self.assertFalse(decision.include)
                self.assertEqual(decision.reason_code, 'EXCLUDED_MINIFIED')

    def test_config_js_included_and_old_backup_excluded(self):
        with tempfile.TemporaryDirectory() as td:
            config_file = Path(td) / 'config.js'
            config_file.write_text('export default {}')
            config_decision = should_include_file(config_file)
            self.assertTrue(config_decision.include)
            self.assertEqual(config_decision.reason_code, 'INCLUDED_CONFIG')

            backup = Path(td) / 'old-config-backup.txt'
            backup.write_text('legacy')
            self.assertFalse(should_include_file(backup).include)



    def test_react_hash_artifacts_excluded_but_main_js_included(self):
        with tempfile.TemporaryDirectory() as td:
            hashed = Path(td) / 'main.3128be0a.js'
            hashed.write_text('x')
            self.assertFalse(should_include_file(hashed).include)

            plain_main = Path(td) / 'main.js'
            plain_main.write_text('const x=1')
            self.assertTrue(should_include_file(plain_main).include)

            static_js = Path(td) / 'static' / 'js' / 'main.3128be0a.js'
            static_js.parent.mkdir(parents=True)
            static_js.write_text('x')
            self.assertFalse(should_include_file(static_js).include)

            webpack_cfg = Path(td) / 'webpack.config.js'
            webpack_cfg.write_text('module.exports = {}')
            self.assertTrue(should_include_file(webpack_cfg).include)

class ZipSecurityTests(unittest.TestCase):
    def test_absolute_path_is_blocked(self):
        with tempfile.TemporaryDirectory() as td:
            upload = Path(td) / 'abs.zip'
            workspace = Path(td) / 'ws'
            workspace.mkdir()
            with ZipFile(upload, 'w') as zf:
                zf.writestr('/absolute/path.js', 'oops')
            with self.assertRaises(ZipSecurityError):
                extract_zip(upload, workspace)

    def test_windows_drive_absolute_path_is_blocked(self):
        with tempfile.TemporaryDirectory() as td:
            upload = Path(td) / 'winabs.zip'
            workspace = Path(td) / 'ws'
            workspace.mkdir()
            with ZipFile(upload, 'w') as zf:
                zf.writestr('C:\\evil.js', 'oops')
            with self.assertRaises(ZipSecurityError):
                extract_zip(upload, workspace)

    def test_backslash_path_normalized_and_extracted(self):
        with tempfile.TemporaryDirectory() as td:
            upload = Path(td) / 'backslash-ok.zip'
            workspace = Path(td) / 'ws'
            workspace.mkdir()
            with ZipFile(upload, 'w') as zf:
                zf.writestr('foo\\bar.js', 'ok')
            extracted = extract_zip(upload, workspace)
            self.assertTrue((extracted / 'foo' / 'bar.js').exists())

    def test_backslash_traversal_is_blocked(self):
        with tempfile.TemporaryDirectory() as td:
            upload = Path(td) / 'backslash-slip.zip'
            workspace = Path(td) / 'ws'
            workspace.mkdir()
            with ZipFile(upload, 'w') as zf:
                zf.writestr('..\\evil.js', 'oops')
            with self.assertRaises(ZipSecurityError):
                extract_zip(upload, workspace)

    def test_windows_unc_absolute_path_is_blocked(self):
        with tempfile.TemporaryDirectory() as td:
            upload = Path(td) / 'uncabs.zip'
            workspace = Path(td) / 'ws'
            workspace.mkdir()
            with ZipFile(upload, 'w') as zf:
                zf.writestr('\\\\server\\share\\evil.js', 'oops')
            with self.assertRaises(ZipSecurityError):
                extract_zip(upload, workspace)

    def test_zip_slip_is_blocked(self):
        with tempfile.TemporaryDirectory() as td:
            upload = Path(td) / 'bad.zip'
            workspace = Path(td) / 'ws'
            workspace.mkdir()
            with ZipFile(upload, 'w') as zf:
                zf.writestr('../escape.js', 'oops')

            with self.assertRaises(ZipSecurityError):
                extract_zip(upload, workspace)

    def test_normal_directory_allowed(self):
        with tempfile.TemporaryDirectory() as td:
            upload = Path(td) / 'ok.zip'
            workspace = Path(td) / 'ws'
            workspace.mkdir()
            with ZipFile(upload, 'w') as zf:
                zf.writestr('src/', '')
                zf.writestr('src/app.js', 'ok')
            extracted = extract_zip(upload, workspace)
            self.assertTrue((extracted / 'src' / 'app.js').exists())

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
