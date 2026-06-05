import asyncio
import io
import json
import unittest
import zipfile

from starlette.datastructures import Headers, UploadFile

from app.api.routes_analyze import analyze_zip_with_traffic
from app.models.schemas import AnalysisResult, ReadableAnalysisResult, ReadableEvidence, ReadableFinding
from app.services import analysis_service
from app.services.runtime_traffic_service import (
    enrich_analysis_with_runtime_traffic,
    import_runtime_traffic,
    parse_curl_command,
    parse_pcap,
    parse_raw_http_request,
    parse_saz,
    parse_traffic_text,
)


class RuntimeTrafficServiceTests(unittest.TestCase):
    @staticmethod
    def _finding(endpoint: str = '/api/user/{currentUserId}/wallet/charge', method: str = 'POST') -> ReadableFinding:
        return ReadableFinding(
            id='f1',
            title='wallet charge mutation',
            vulnerability_type='Payment/Point Manipulation Candidate',
            severity='high',
            confidence='medium',
            affected_files=['src/wallet.js'],
            summary='amount can be changed client-side',
            evidence=[
                ReadableEvidence(
                    source_path='src/wallet.js',
                    start_line=1,
                    end_line=1,
                    snippet='axios.post(endpoint, { amount })',
                    reason='validation value + API call combination',
                    data_flow=[
                        'source -> state/storage -> sink',
                        f'method: {method}',
                        f'endpoint: {endpoint}',
                        'parameter: amount',
                        'sink: axios.post',
                    ],
                )
            ],
            attack_scenario=['Change amount in request body.'],
            impact='Wallet balance may be manipulated.',
            root_cause='Client-controlled amount reaches API request.',
            remediation='Validate amount and authorization server-side.',
        )

    def test_har_parser_extracts_method_url_headers_body(self):
        payload = {
            'log': {
                'entries': [
                    {
                        'startedDateTime': '2026-06-05T00:00:00Z',
                        'request': {
                            'method': 'POST',
                            'url': 'https://example.com/api/wallet/charge?debug=1',
                            'headers': [
                                {'name': 'Content-Type', 'value': 'application/json'},
                                {'name': 'Cookie', 'value': 'sid=secret'},
                            ],
                            'queryString': [{'name': 'debug', 'value': '1'}],
                            'postData': {'mimeType': 'application/json', 'text': '{"amount":1000}'},
                        },
                        'response': {
                            'status': 200,
                            'headers': [{'name': 'Set-Cookie', 'value': 'new=secret'}],
                            'content': {'mimeType': 'application/json', 'text': '{"ok":true}'},
                        },
                    }
                ]
            }
        }
        result = import_runtime_traffic(filename='traffic.har', content=json.dumps(payload).encode('utf-8'))
        self.assertEqual(result.source_format, 'har')
        self.assertEqual(result.request_count, 1)
        req = result.requests[0]
        self.assertEqual(req.method, 'POST')
        self.assertEqual(req.full_url, 'https://example.com/api/wallet/charge?debug=1')
        self.assertEqual(req.body_json, {'amount': 1000})
        self.assertEqual(req.body_keys, ['amount'])
        self.assertTrue(req.cookies_present)
        self.assertEqual(req.headers['Cookie'], '<REPLACE_WITH_COOKIE>')
        self.assertEqual(req.response.redacted_headers['Set-Cookie'], '<REDACTED>')

    def test_curl_parser_extracts_method_url_headers_body(self):
        req = parse_curl_command(
            "curl 'https://example.com/api/wallet/charge' -X POST "
            "-H 'Content-Type: application/json' -H 'Authorization: Bearer secret' "
            "--data-raw '{\"amount\":1000}'"
        )
        self.assertIsNotNone(req)
        self.assertEqual(req.method, 'POST')
        self.assertEqual(req.path, '/api/wallet/charge')
        self.assertEqual(req.body_json, {'amount': 1000})
        self.assertTrue(req.authorization_present)
        self.assertEqual(req.headers['Authorization'], '<REPLACE_WITH_AUTHORIZATION>')

    def test_raw_http_parser_extracts_method_path_headers_body(self):
        req = parse_raw_http_request(
            'POST /api/user/123/wallet/charge HTTP/1.1\r\n'
            'Host: example.com\r\n'
            'Content-Type: application/json\r\n\r\n'
            '{"amount":1000}'
        )
        self.assertIsNotNone(req)
        self.assertEqual(req.method, 'POST')
        self.assertEqual(req.full_url, 'http://example.com/api/user/123/wallet/charge')
        self.assertEqual(req.body_keys, ['amount'])

    def test_saz_parser_reads_minimal_synthetic_archive(self):
        bio = io.BytesIO()
        with zipfile.ZipFile(bio, 'w', zipfile.ZIP_DEFLATED) as zf:
            zf.writestr('raw/0001_c.txt', 'GET /api/me HTTP/1.1\r\nHost: example.com\r\n\r\n')
            zf.writestr('raw/0001_s.txt', 'HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nok')
        result = parse_saz(bio.getvalue())
        self.assertEqual(result.source_format, 'saz')
        self.assertEqual(result.request_count, 1)
        self.assertEqual(result.requests[0].response.status_code, 200)

    def test_pcap_parser_returns_clear_limitation_when_tshark_missing(self):
        result = parse_pcap(b'\x00\x01', filename='x.pcap')
        if result.request_count == 0:
            self.assertIn('PCAP/PCAPNG parsing requires tshark or an exported HTTP stream.', result.limitations)

    def test_cookie_authorization_and_csrf_headers_are_redacted(self):
        req = parse_raw_http_request(
            'POST /api/x HTTP/1.1\r\n'
            'Host: example.com\r\n'
            'Cookie: sid=secret\r\n'
            'Authorization: Bearer secret\r\n'
            'X-CSRF-Token: secret\r\n\r\n'
        )
        self.assertEqual(req.headers['Cookie'], '<REPLACE_WITH_COOKIE>')
        self.assertEqual(req.headers['Authorization'], '<REPLACE_WITH_AUTHORIZATION>')
        self.assertEqual(req.headers['X-CSRF-Token'], '<REPLACE_WITH_CSRF_TOKEN>')
        self.assertTrue(req.cookies_present)
        self.assertTrue(req.authorization_present)
        self.assertTrue(req.csrf_token_present)

    def test_runtime_request_correlates_path_template_and_placeholder(self):
        traffic = parse_traffic_text(
            'POST /api/user/123/wallet/charge HTTP/1.1\r\n'
            'Host: example.com\r\n'
            'Content-Type: application/json\r\n'
            'Cookie: sid=secret\r\n\r\n'
            '{"amount":1000}'
        )
        readable = ReadableAnalysisResult(finding_count=1, findings=[self._finding()], analyzed_focus=[])
        enriched = enrich_analysis_with_runtime_traffic(readable, traffic)
        self.assertEqual(len(enriched.correlations), 1)
        corr = enriched.correlations[0]
        self.assertEqual(corr.placeholder_mapping, {'USER_ID': '123'})
        self.assertNotIn('TEST_ID', corr.placeholder_mapping)
        self.assertEqual(corr.mutable_parameters, ['amount'])
        self.assertEqual(readable.findings[0].status, 'runtime_request_correlated_candidate')
        self.assertEqual(readable.project_profile.confirmed_findings if readable.project_profile else 0, 0)

    def test_runtime_pocs_include_confirm_and_credentials(self):
        traffic = parse_traffic_text(
            'POST /api/user/123/wallet/charge HTTP/1.1\r\n'
            'Host: example.com\r\n'
            'Content-Type: application/json\r\n'
            'Cookie: sid=secret\r\n\r\n'
            '{"amount":1000}'
        )
        readable = ReadableAnalysisResult(finding_count=1, findings=[self._finding()], analyzed_focus=[])
        corr = enrich_analysis_with_runtime_traffic(readable, traffic).correlations[0]
        browser = [p for p in corr.generated_pocs if p.poc_type == 'browser_console_fetch'][0]
        self.assertIn('confirm(', browser.code)
        self.assertIn("credentials: 'include'", browser.code)
        curl = [p for p in corr.generated_pocs if p.poc_type == 'curl'][0]
        self.assertIn('<REPLACE_WITH_COOKIE>', curl.code)

    def test_destructive_paths_do_not_generate_replay_poc(self):
        traffic = parse_traffic_text(
            'DELETE /api/user/123/wallet/withdraw HTTP/1.1\r\n'
            'Host: example.com\r\n\r\n'
        )
        readable = ReadableAnalysisResult(
            finding_count=1,
            findings=[self._finding('/api/user/{currentUserId}/wallet/withdraw', method='DELETE')],
            analyzed_focus=[],
        )
        corr = enrich_analysis_with_runtime_traffic(readable, traffic).correlations[0]
        self.assertEqual([p.poc_type for p in corr.generated_pocs], ['manual_plan'])
        self.assertIsNone(corr.generated_pocs[0].code)

    def test_captured_request_alone_never_creates_confirmed_finding(self):
        result = parse_traffic_text('GET /api/me HTTP/1.1\r\nHost: example.com\r\n\r\n')
        self.assertEqual(result.correlations, [])
        self.assertNotIn('confirmed_finding', result.model_dump_json())


class RuntimeTrafficRouteTests(unittest.TestCase):
    @staticmethod
    def _zip_bytes(files: dict[str, str | bytes]) -> bytes:
        bio = io.BytesIO()
        with zipfile.ZipFile(bio, 'w', zipfile.ZIP_DEFLATED) as zf:
            for name, content in files.items():
                zf.writestr(name, content)
        return bio.getvalue()

    @staticmethod
    def _upload(filename: str, data: bytes, content_type: str = 'application/zip') -> UploadFile:
        return UploadFile(
            file=io.BytesIO(data),
            filename=filename,
            headers=Headers({'content-type': content_type}),
        )

    def test_analyze_with_traffic_source_zip_only_returns_source_only_note(self):
        original_backend = analysis_service.settings.ANALYZER_BACKEND
        try:
            analysis_service.settings.ANALYZER_BACKEND = 'mock'
            data = self._zip_bytes({'src/app.js': 'const a = 1;'})
            result = asyncio.run(analyze_zip_with_traffic(self._upload('sample.zip', data)))
            self.assertIn('No runtime traffic provided; source-only analysis used.', result.analysis_notes)
            self.assertIsNotNone(result.readable_analysis.project_profile)
            self.assertEqual(result.readable_analysis.project_profile.confirmed_findings, 0)
            self.assertFalse(result.runtime_traffic.provided)
        finally:
            analysis_service.settings.ANALYZER_BACKEND = original_backend

    def test_existing_source_only_shape_still_has_required_sections(self):
        from app.api import routes_analyze

        original_backend = analysis_service.settings.ANALYZER_BACKEND
        original_analyze_chunks = routes_analyze.analyze_chunks
        try:
            analysis_service.settings.ANALYZER_BACKEND = 'mock'
            routes_analyze.analyze_chunks = lambda chunks: AnalysisResult(
                total_chunks=0,
                analyzed_chunks=0,
                finding_count=0,
                findings=[],
                skipped_chunks=[],
            )
            data = self._zip_bytes({'src/wallet.js': "axios.post('/api/wallet/charge', { amount })"})
            result = asyncio.run(routes_analyze.analyze_zip(self._upload('sample.zip', data)))
            self.assertIsNotNone(result.readable_analysis.project_profile)
            self.assertIsNotNone(result.readable_analysis.review_candidates)
            self.assertIsNotNone(result.readable_analysis.verification_playbooks)
            self.assertEqual(result.readable_analysis.project_profile.confirmed_findings, 0)
            self.assertIsNone(result.runtime_traffic)
        finally:
            routes_analyze.analyze_chunks = original_analyze_chunks
            analysis_service.settings.ANALYZER_BACKEND = original_backend


if __name__ == '__main__':
    unittest.main()
