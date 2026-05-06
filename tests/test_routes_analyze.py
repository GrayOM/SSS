import asyncio
import io
import unittest
import zipfile

from fastapi import HTTPException
from starlette.datastructures import UploadFile

from app.api.routes_analyze import analyze_zip
from app.api.routes_upload import upload_zip
from app.services import analysis_service


class RoutesAnalyzeTests(unittest.TestCase):
    @staticmethod
    def _zip_bytes(files: dict[str, str | bytes]) -> bytes:
        bio = io.BytesIO()
        with zipfile.ZipFile(bio, 'w', zipfile.ZIP_DEFLATED) as zf:
            for name, content in files.items():
                zf.writestr(name, content)
        return bio.getvalue()

    @staticmethod
    def _upload(filename: str, data: bytes) -> UploadFile:
        return UploadFile(file=io.BytesIO(data), filename=filename)

    def test_analyze_success_returns_full_structure(self):
        original_backend = analysis_service.settings.ANALYZER_BACKEND
        try:
            analysis_service.settings.ANALYZER_BACKEND = 'mock'
            data = self._zip_bytes({'src/app.js': 'const a = 1;'})
            result = asyncio.run(analyze_zip(self._upload('sample.zip', data)))
            body = result.model_dump()
            self.assertIn('upload', body)
            self.assertIn('content_load', body)
            self.assertIn('chunks', body)
            self.assertIn('analysis', body)
        finally:
            analysis_service.settings.ANALYZER_BACKEND = original_backend

    def test_analyze_eval_finding_created_with_mock_analyzer(self):
        original_backend = analysis_service.settings.ANALYZER_BACKEND
        try:
            analysis_service.settings.ANALYZER_BACKEND = 'mock'
            data = self._zip_bytes({'src/vuln.js': 'eval(userInput)'})
            result = asyncio.run(analyze_zip(self._upload('vuln.zip', data)))
            findings = result.analysis.findings
            self.assertGreaterEqual(len(findings), 1)
            self.assertEqual(findings[0].vulnerability_type, 'Unsafe eval')
        finally:
            analysis_service.settings.ANALYZER_BACKEND = original_backend

    def test_analyze_invalid_signature_returns_400(self):
        with self.assertRaises(HTTPException) as ctx:
            asyncio.run(analyze_zip(self._upload('bad.zip', b'NOTZIP')))
        self.assertEqual(ctx.exception.status_code, 400)

    def test_analyze_zip_slip_returns_400(self):
        data = self._zip_bytes({'../evil.js': 'alert(1)'})
        with self.assertRaises(HTTPException) as ctx:
            asyncio.run(analyze_zip(self._upload('zipslip.zip', data)))
        self.assertEqual(ctx.exception.status_code, 400)

    def test_analyze_upload_size_exceeded_returns_413(self):
        original_size = analysis_service.settings.MAX_UPLOAD_SIZE_MB
        try:
            analysis_service.settings.MAX_UPLOAD_SIZE_MB = 0
            data = self._zip_bytes({'src/a.js': 'const a = 1;'})
            with self.assertRaises(HTTPException) as ctx:
                asyncio.run(analyze_zip(self._upload('big.zip', data)))
            self.assertEqual(ctx.exception.status_code, 413)
        finally:
            analysis_service.settings.MAX_UPLOAD_SIZE_MB = original_size

    def test_existing_upload_endpoint_still_works(self):
        data = self._zip_bytes({'src/a.js': 'const a = 1;'})
        result = asyncio.run(upload_zip(self._upload('sample.zip', data)))
        body = result.model_dump()
        self.assertIn('total_files_scanned', body)
        self.assertIn('files', body)


if __name__ == '__main__':
    unittest.main()
