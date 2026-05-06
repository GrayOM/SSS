import hashlib
import tempfile
import unittest
from pathlib import Path

from app.core.config import settings
from app.models.schemas import FileAnalysisResult, UploadAnalysisResponse
from app.services.file_content_loader import load_file_contents


def _scan_result(files: list[FileAnalysisResult]) -> UploadAnalysisResponse:
    included = sum(1 for f in files if f.include)
    return UploadAnalysisResponse(
        total_files_scanned=len(files),
        included_count=included,
        excluded_count=len(files) - included,
        files=files,
    )


class FileContentLoaderTests(unittest.TestCase):
    def test_include_true_file_loads_content_and_hash(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            f = base / 'a.js'
            data = 'console.log(1);'
            f.write_text(data, encoding='utf-8')

            result = load_file_contents(base, _scan_result([
                FileAnalysisResult(path='a.js', extension='.js', size=len(data), include=True,
                                   reason='source', reason_code='INCLUDED_SOURCE', priority=1)
            ]))

            self.assertEqual(result.loaded_count, 1)
            self.assertEqual(result.skipped_count, 0)
            self.assertEqual(result.files[0].content, data)
            self.assertEqual(result.files[0].content_hash, hashlib.sha256(data.encode('utf-8')).hexdigest())

    def test_include_false_goes_to_skipped(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            result = load_file_contents(base, _scan_result([
                FileAnalysisResult(path='a.js', extension='.js', size=1, include=False,
                                   reason='excluded', reason_code='EXCLUDED_EXTENSION', priority=100)
            ]))
            self.assertEqual(result.loaded_count, 0)
            self.assertEqual(result.skipped_count, 1)
            self.assertEqual(result.skipped[0].reason_code, 'SKIPPED_NOT_INCLUDED')

    def test_decode_fail_goes_to_skipped(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            bad = base / 'bad.js'
            bad.write_bytes(b'\xff\xfe\xfd')

            result = load_file_contents(base, _scan_result([
                FileAnalysisResult(path='bad.js', extension='.js', size=3, include=True,
                                   reason='source', reason_code='INCLUDED_SOURCE', priority=1)
            ]))
            self.assertEqual(result.skipped[0].reason_code, 'SKIPPED_DECODE_ERROR')

    def test_missing_file_goes_to_skipped(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            result = load_file_contents(base, _scan_result([
                FileAnalysisResult(path='missing.js', extension='.js', size=1, include=True,
                                   reason='source', reason_code='INCLUDED_SOURCE', priority=1)
            ]))
            self.assertEqual(result.skipped[0].reason_code, 'SKIPPED_NOT_FOUND')

    def test_path_traversal_goes_to_skipped(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            outside = base.parent / 'outside.js'
            outside.write_text('x', encoding='utf-8')
            try:
                result = load_file_contents(base, _scan_result([
                    FileAnalysisResult(path='../outside.js', extension='.js', size=1, include=True,
                                       reason='source', reason_code='INCLUDED_SOURCE', priority=1)
                ]))
                self.assertEqual(result.skipped[0].reason_code, 'SKIPPED_PATH_TRAVERSAL')
            finally:
                if outside.exists():
                    outside.unlink()

    def test_too_large_goes_to_skipped(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            big = base / 'big.js'
            big.write_text('12345', encoding='utf-8')

            original = settings.MAX_FILE_SIZE_BYTES
            settings.MAX_FILE_SIZE_BYTES = 1
            try:
                result = load_file_contents(base, _scan_result([
                    FileAnalysisResult(path='big.js', extension='.js', size=5, include=True,
                                       reason='source', reason_code='INCLUDED_SOURCE', priority=1)
                ]))
                self.assertEqual(result.skipped[0].reason_code, 'SKIPPED_TOO_LARGE')
            finally:
                settings.MAX_FILE_SIZE_BYTES = original

    def test_hash_matches_sha256(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            f = base / 'file.ts'
            raw = b'hello-world'
            f.write_bytes(raw)

            result = load_file_contents(base, _scan_result([
                FileAnalysisResult(path='file.ts', extension='.ts', size=len(raw), include=True,
                                   reason='source', reason_code='INCLUDED_SOURCE', priority=1)
            ]))
            self.assertEqual(result.files[0].content_hash, hashlib.sha256(raw).hexdigest())

    def test_counts_are_correct(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            good = base / 'ok.js'
            good.write_text('ok', encoding='utf-8')

            result = load_file_contents(base, _scan_result([
                FileAnalysisResult(path='ok.js', extension='.js', size=2, include=True,
                                   reason='source', reason_code='INCLUDED_SOURCE', priority=1),
                FileAnalysisResult(path='skip.js', extension='.js', size=1, include=False,
                                   reason='excluded', reason_code='EXCLUDED_EXTENSION', priority=100),
                FileAnalysisResult(path='missing.js', extension='.js', size=1, include=True,
                                   reason='source', reason_code='INCLUDED_SOURCE', priority=1),
            ]))
            self.assertEqual(result.total_candidates, 3)
            self.assertEqual(result.loaded_count, 1)
            self.assertEqual(result.skipped_count, 2)


if __name__ == '__main__':
    unittest.main()
