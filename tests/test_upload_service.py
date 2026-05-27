import asyncio
import io
import tempfile
import unittest
from pathlib import Path

from fastapi import HTTPException
from starlette.datastructures import UploadFile

from app.core.config import settings
from app.services import upload_service


class UploadServiceCleanupTests(unittest.TestCase):
    @staticmethod
    def _upload(filename: str, data: bytes) -> UploadFile:
        return UploadFile(file=io.BytesIO(data), filename=filename)

    @staticmethod
    def _leftover_upload_dirs(tmp_dir: str) -> list[Path]:
        return [p for p in Path(tmp_dir).glob('upload_*') if p.is_dir()]

    def test_cleanup_on_invalid_signature(self):
        original_tmp = settings.TMP_DIR
        try:
            with tempfile.TemporaryDirectory() as td:
                settings.TMP_DIR = td
                with self.assertRaises(HTTPException):
                    asyncio.run(upload_service.prepare_uploaded_zip(self._upload('bad.zip', b'NOTZIP')))
                self.assertEqual(self._leftover_upload_dirs(td), [])
        finally:
            settings.TMP_DIR = original_tmp

    def test_cleanup_on_size_limit_exceeded_streaming(self):
        original_tmp = settings.TMP_DIR
        original_limit = settings.MAX_UPLOAD_SIZE_MB
        try:
            with tempfile.TemporaryDirectory() as td:
                settings.TMP_DIR = td
                settings.MAX_UPLOAD_SIZE_MB = 0
                with self.assertRaises(HTTPException) as ctx:
                    asyncio.run(upload_service.prepare_uploaded_zip(self._upload('big.zip', b'PK' + b'a' * 100)))
                self.assertEqual(ctx.exception.status_code, 413)
                self.assertEqual(self._leftover_upload_dirs(td), [])
        finally:
            settings.MAX_UPLOAD_SIZE_MB = original_limit
            settings.TMP_DIR = original_tmp

    def test_cleanup_on_zip_security_error(self):
        original_tmp = settings.TMP_DIR
        original_extract = upload_service.extract_zip
        try:
            with tempfile.TemporaryDirectory() as td:
                settings.TMP_DIR = td

                def _raise(*args, **kwargs):
                    raise upload_service.ZipSecurityError('blocked zip')

                upload_service.extract_zip = _raise
                with self.assertRaises(HTTPException):
                    asyncio.run(upload_service.prepare_uploaded_zip(self._upload('ok.zip', b'PK\x03\x04dummy')))
                self.assertEqual(self._leftover_upload_dirs(td), [])
        finally:
            upload_service.extract_zip = original_extract
            settings.TMP_DIR = original_tmp


if __name__ == '__main__':
    unittest.main()
