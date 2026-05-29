import asyncio
import io
import json
import tempfile
import unittest
import zipfile
from pathlib import Path

from starlette.datastructures import Headers, UploadFile

from app.api.routes_analyze import analyze_zip
from app.core.config import settings
from app.services.analysis_run_repository import get_analysis_run, list_analysis_runs
from app.services import analysis_service

try:
    from fastapi.testclient import TestClient
except Exception:
    TestClient = None


class AnalysisRunPersistenceTests(unittest.TestCase):
    @staticmethod
    def _zip_bytes(files: dict[str, str | bytes]) -> bytes:
        bio = io.BytesIO()
        with zipfile.ZipFile(bio, 'w', zipfile.ZIP_DEFLATED) as zf:
            for name, content in files.items():
                zf.writestr(name, content)
        return bio.getvalue()

    @staticmethod
    def _upload(filename: str, data: bytes) -> UploadFile:
        return UploadFile(
            file=io.BytesIO(data),
            filename=filename,
            headers=Headers({'content-type': 'application/zip'}),
        )

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.original_db_path = settings.ANALYSIS_DB_PATH
        self.original_backend = analysis_service.settings.ANALYZER_BACKEND
        settings.ANALYSIS_DB_PATH = str(Path(self.tmp.name) / 'analysis-runs.sqlite3')
        analysis_service.settings.ANALYZER_BACKEND = 'mock'

    def tearDown(self):
        analysis_service.settings.ANALYZER_BACKEND = self.original_backend
        settings.ANALYSIS_DB_PATH = self.original_db_path
        self.tmp.cleanup()

    def _create_saved_run(self):
        data = self._zip_bytes({
            'src/app.js': 'const harmlessValue = "SSS_RAW_SOURCE_SHOULD_NOT_PERSIST";',
            '.env': 'SSS_ENV_SECRET_SHOULD_NOT_PERSIST=1',
        })
        asyncio.run(analyze_zip(self._upload('persisted.zip', data)))
        runs = list_analysis_runs()
        self.assertEqual(len(runs), 1)
        return runs[0]

    def test_completed_analysis_creates_saved_run(self):
        run = self._create_saved_run()

        self.assertEqual(run.original_filename, 'persisted.zip')
        self.assertEqual(run.backend, 'mock')
        self.assertEqual(run.included_file_count, 1)
        self.assertEqual(run.skipped_file_count, 1)
        self.assertEqual(run.finding_count, 0)
        self.assertEqual(run.verification_playbook_count, 0)
        self.assertEqual(run.review_candidate_count, 0)

    @unittest.skipIf(TestClient is None, 'httpx is not installed')
    def test_list_endpoint_returns_saved_runs(self):
        run = self._create_saved_run()
        client = TestClient(__import__('app.main', fromlist=['app']).app)

        response = client.get('/api/analysis-runs')

        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(len(body), 1)
        self.assertEqual(body[0]['id'], run.id)
        self.assertEqual(body[0]['original_filename'], 'persisted.zip')

    @unittest.skipIf(TestClient is None, 'httpx is not installed')
    def test_detail_endpoint_returns_safe_result_json(self):
        run = self._create_saved_run()
        client = TestClient(__import__('app.main', fromlist=['app']).app)

        response = client.get(f'/api/analysis-runs/{run.id}')

        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body['id'], run.id)
        self.assertIn('upload', body['result'])
        self.assertIn('content_load', body['result'])
        self.assertIn('chunks', body['result'])
        self.assertNotIn('content', body['result']['content_load']['files'][0])
        self.assertNotIn('content', body['result']['chunks']['chunks'][0])

    def test_raw_source_content_is_not_persisted(self):
        run = self._create_saved_run()
        detail = get_analysis_run(run.id)
        self.assertIsNotNone(detail)

        persisted = json.dumps(detail.result, ensure_ascii=False)

        self.assertNotIn('SSS_RAW_SOURCE_SHOULD_NOT_PERSIST', persisted)
        self.assertNotIn('SSS_ENV_SECRET_SHOULD_NOT_PERSIST', persisted)
        self.assertNotIn('"content":', persisted)


if __name__ == '__main__':
    unittest.main()
