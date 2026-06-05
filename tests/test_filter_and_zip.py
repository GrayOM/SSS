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

    def test_third_party_library_excluded(self):
        with tempfile.TemporaryDirectory() as td:
            jq_ui = Path(td) / 'jquery-ui.js'
            jq_ui.write_text('x')
            self.assertFalse(should_include_file(jq_ui).include)
            self.assertEqual(should_include_file(jq_ui).reason_code, 'EXCLUDED_THIRD_PARTY_LIBRARY')

            app = Path(td) / 'application.js'
            app.write_text('x')
            self.assertTrue(should_include_file(app).include)

            vendor = Path(td) / 'vendor' / 'jquery-ui.js'
            vendor.parent.mkdir(parents=True)
            vendor.write_text('x')
            self.assertFalse(should_include_file(vendor).include)



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


class FilterPolicyExtendedTests(unittest.TestCase):
    """Additional filter policy tests filling gaps in the test suite."""

    # ── Source extensions ─────────────────────────────────────────────────────

    def test_mjs_cjs_included_as_source(self):
        with tempfile.TemporaryDirectory() as td:
            for ext in ('.mjs', '.cjs'):
                p = Path(td) / f'module{ext}'
                p.write_text('export default 1;')
                d = should_include_file(p)
                self.assertTrue(d.include, f'{ext} must be included')
                self.assertEqual(d.reason_code, 'INCLUDED_SOURCE', f'{ext} reason_code wrong')
                self.assertEqual(d.priority, 1, f'{ext} must have PRIORITY_SOURCE=1')

    def test_jsx_tsx_included_as_source(self):
        with tempfile.TemporaryDirectory() as td:
            for ext in ('.jsx', '.tsx'):
                p = Path(td) / f'Component{ext}'
                p.write_text('export default function C(){return <div/>;}')
                d = should_include_file(p)
                self.assertTrue(d.include, f'{ext} must be included')
                self.assertEqual(d.reason_code, 'INCLUDED_SOURCE')
                self.assertEqual(d.priority, 1)

    def test_vue_included_as_source(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / 'App.vue'
            p.write_text('<template><div/></template>')
            d = should_include_file(p)
            self.assertTrue(d.include)
            self.assertEqual(d.reason_code, 'INCLUDED_SOURCE')
            self.assertEqual(d.priority, 1)

    # ── Template extensions ───────────────────────────────────────────────────

    def test_html_ejs_hbs_pug_included_as_template(self):
        with tempfile.TemporaryDirectory() as td:
            for ext in ('.html', '.hbs', '.pug'):
                p = Path(td) / f'page{ext}'
                p.write_text('<div>hello</div>')
                d = should_include_file(p)
                self.assertTrue(d.include, f'{ext} must be included')
                self.assertEqual(d.reason_code, 'INCLUDED_TEMPLATE', f'{ext} reason_code wrong')
                self.assertEqual(d.priority, 3, f'{ext} must have PRIORITY_TEMPLATE=3 (lower than source)')

    def test_htm_included_as_template(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / 'index.htm'
            p.write_text('<html><body/></html>')
            d = should_include_file(p)
            self.assertTrue(d.include)
            self.assertEqual(d.reason_code, 'INCLUDED_TEMPLATE')

    # ── Env files ─────────────────────────────────────────────────────────────

    def test_env_sample_included(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / '.env.sample'
            p.write_text('API_KEY=YOUR_KEY_HERE')
            d = should_include_file(p)
            self.assertTrue(d.include, '.env.sample must be included')
            self.assertEqual(d.reason_code, 'INCLUDED_CONFIG')

    def test_env_real_excluded(self):
        with tempfile.TemporaryDirectory() as td:
            for name in ('.env', 'production.env', 'staging.env'):
                p = Path(td) / name
                p.write_text('SECRET=real_value')
                d = should_include_file(p)
                self.assertFalse(d.include, f'{name} must be excluded')

    # ── Excluded directories ──────────────────────────────────────────────────

    def test_build_coverage_git_excluded(self):
        with tempfile.TemporaryDirectory() as td:
            for dir_name in ('build', 'coverage', '.git'):
                src = Path(td) / dir_name / 'output.js'
                src.parent.mkdir(parents=True)
                src.write_text('x=1')
                d = should_include_file(src)
                self.assertFalse(d.include, f'{dir_name}/ must be excluded')
                self.assertEqual(d.reason_code, 'EXCLUDED_DIR')

    def test_vendor_libs_cdn_excluded(self):
        with tempfile.TemporaryDirectory() as td:
            for dir_name in ('vendor', 'libs', 'cdn'):
                src = Path(td) / dir_name / 'lib.js'
                src.parent.mkdir(parents=True)
                src.write_text('x=1')
                d = should_include_file(src)
                self.assertFalse(d.include, f'{dir_name}/ must be excluded')

    # ── Minified / bundle patterns ────────────────────────────────────────────

    def test_chunk_js_and_min_js_excluded(self):
        with tempfile.TemporaryDirectory() as td:
            for name in ('vendors.chunk.js', 'main.chunk.js', 'app.min.js', 'react.min.js'):
                p = Path(td) / name
                p.write_text('a=1')
                d = should_include_file(p)
                self.assertFalse(d.include, f'{name} must be excluded')
                self.assertEqual(d.reason_code, 'EXCLUDED_MINIFIED')

    def test_standalone_bundle_js_excluded(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / 'bundle.js'
            p.write_text('a=1')
            d = should_include_file(p)
            self.assertFalse(d.include, 'bundle.js must be excluded')

    def test_webpack_content_signature_exclusion(self):
        """Files containing webpack runtime signatures are excluded regardless of name."""
        with tempfile.TemporaryDirectory() as td:
            for sig in ('self.webpackChunk', '__webpack_require__', 'webpackJsonp'):
                p = Path(td) / 'app-abc.js'
                p.write_text(f'var a=1; {sig}({{}});')
                d = should_include_file(p)
                self.assertFalse(d.include, f'webpack sig {sig!r} must exclude file')

    # ── Priority ordering ─────────────────────────────────────────────────────

    def test_source_has_higher_priority_than_template(self):
        with tempfile.TemporaryDirectory() as td:
            js = Path(td) / 'a.js'
            js.write_text('x')
            html = Path(td) / 'b.html'
            html.write_text('<p>x</p>')
            dj = should_include_file(js)
            dh = should_include_file(html)
            self.assertLess(dj.priority, dh.priority,
                'Source files (priority=1) must rank higher than templates (priority=3)')

    def test_source_has_higher_priority_than_config(self):
        with tempfile.TemporaryDirectory() as td:
            js = Path(td) / 'a.js'
            js.write_text('x')
            pkg = Path(td) / 'package.json'
            pkg.write_text('{}')
            dj = should_include_file(js)
            dp = should_include_file(pkg)
            self.assertLess(dj.priority, dp.priority,
                'Source files (priority=1) must rank higher than config (priority=2)')


if __name__ == '__main__':
    unittest.main()
