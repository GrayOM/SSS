import asyncio
import io
import unittest
import zipfile

from fastapi import HTTPException
from starlette.datastructures import UploadFile

from app.api.routes_analyze import analyze_zip
from app.api.routes_upload import upload_zip
from app.services import analysis_service

try:
    from fastapi.testclient import TestClient
except Exception:
    TestClient = None


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
            self.assertIn('readable_analysis', body)
            self.assertIn('finding_count', body['readable_analysis'])
        finally:
            analysis_service.settings.ANALYZER_BACKEND = original_backend

    def test_analyze_invalid_signature_returns_400(self):
        original_backend = analysis_service.settings.ANALYZER_BACKEND
        try:
            analysis_service.settings.ANALYZER_BACKEND = 'mock'
            with self.assertRaises(HTTPException):
                asyncio.run(analyze_zip(self._upload('bad.zip', b'NOTZIP')))
        finally:
            analysis_service.settings.ANALYZER_BACKEND = original_backend

    def test_analyze_response_hides_raw_content_fields(self):
        original_backend = analysis_service.settings.ANALYZER_BACKEND
        try:
            analysis_service.settings.ANALYZER_BACKEND = 'mock'
            data = self._zip_bytes({'src/vuln.js': 'const x=location.hash; el.innerHTML=x;'})
            result = asyncio.run(analyze_zip(self._upload('x.zip', data)))
            body = result.model_dump()
            if body['content_load']['files']:
                self.assertNotIn('content', body['content_load']['files'][0])
            if body['chunks']['chunks']:
                self.assertNotIn('content', body['chunks']['chunks'][0])
            if body['chunks']['skipped']:
                self.assertNotIn('content', body['chunks']['skipped'][0])
            self.assertNotIn('"content":', result.model_dump_json())
        finally:
            analysis_service.settings.ANALYZER_BACKEND = original_backend

    def test_readable_auth_bypass_finding_present(self):
        original_backend = analysis_service.settings.ANALYZER_BACKEND
        try:
            analysis_service.settings.ANALYZER_BACKEND = 'mock'
            data = self._zip_bytes({'src/auth.js': "if(userType==='ADMIN'){navigate('/admin')}"})
            result = asyncio.run(analyze_zip(self._upload('auth.zip', data)))
            types = [f.vulnerability_type for f in result.readable_analysis.findings]
            self.assertIn('Client-side Authorization Bypass', types)
        finally:
            analysis_service.settings.ANALYZER_BACKEND = original_backend

    def test_readable_dom_xss_finding_present(self):
        original_backend = analysis_service.settings.ANALYZER_BACKEND
        try:
            analysis_service.settings.ANALYZER_BACKEND = 'mock'
            data = self._zip_bytes({'src/x.js': 'const x=location.hash; el.innerHTML=x;'})
            result = asyncio.run(analyze_zip(self._upload('xss.zip', data)))
            types = [f.vulnerability_type for f in result.readable_analysis.findings]
            self.assertIn('DOM XSS', types)
        finally:
            analysis_service.settings.ANALYZER_BACKEND = original_backend

    def test_existing_upload_endpoint_still_works(self):
        data = self._zip_bytes({'src/a.js': 'const a = 1;'})
        result = asyncio.run(upload_zip(self._upload('sample.zip', data)))
        self.assertIn('total_files_scanned', result.model_dump())


if __name__ == '__main__':
    unittest.main()


@unittest.skipIf(TestClient is None, 'httpx is not installed')
class RoutesAnalyzeHttpTests(unittest.TestCase):
    def test_http_analyze_success(self):
        original_backend = analysis_service.settings.ANALYZER_BACKEND
        client = TestClient(__import__('app.main', fromlist=['app']).app)
        try:
            analysis_service.settings.ANALYZER_BACKEND = 'mock'
            import io, zipfile
            bio = io.BytesIO()
            with zipfile.ZipFile(bio, 'w', zipfile.ZIP_DEFLATED) as zf:
                zf.writestr('src/x.js', 'const x=location.hash; el.innerHTML=x;')
            res = client.post('/api/analyze', files={'file': ('a.zip', bio.getvalue(), 'application/zip')})
            self.assertEqual(res.status_code, 200)
            self.assertIn('readable_analysis', res.json())
        finally:
            analysis_service.settings.ANALYZER_BACKEND = original_backend
