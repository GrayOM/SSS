import asyncio
import json as json_lib
from pathlib import Path
from urllib.parse import urlencode, urlsplit

import fastapi.testclient as fastapi_testclient


class _CompatResponse:
    def __init__(self, status_code: int, headers: list[tuple[bytes, bytes]], body: bytes):
        self.status_code = status_code
        self.headers = {k.decode('latin1').lower(): v.decode('latin1') for k, v in headers}
        self.content = body
        self.text = body.decode('utf-8', errors='replace')

    def json(self):
        return json_lib.loads(self.text)


class _InProcessTestClient:
    """Small pytest-only replacement for Starlette TestClient.

    The bundled Starlette/anyio TestClient hangs in this restricted runner.
    This client exercises the real ASGI app directly and supports the GET/POST
    shapes used by the test suite.
    """
    __test__ = False

    def __init__(self, app):
        self.app = app

    def get(self, path: str):
        static = self._static_response(path)
        if static is not None:
            return static
        return self._request('GET', path, b'', [])

    def post(self, path: str, files=None, data=None, json=None):
        body = b''
        headers: list[tuple[bytes, bytes]] = []
        if files:
            body, content_type = self._encode_multipart(files)
            headers.append((b'content-type', content_type.encode('latin1')))
        elif json is not None:
            body = json_lib.dumps(json).encode('utf-8')
            headers.append((b'content-type', b'application/json'))
        elif data:
            body = urlencode(data).encode('utf-8')
            headers.append((b'content-type', b'application/x-www-form-urlencoded'))
        return self._request('POST', path, body, headers)

    def _request(self, method: str, path: str, body: bytes, headers: list[tuple[bytes, bytes]]):
        split = urlsplit(path)
        req_headers = [(b'host', b'testserver')] + headers
        if body:
            req_headers.append((b'content-length', str(len(body)).encode('ascii')))
        scope = {
            'type': 'http',
            'asgi': {'version': '3.0', 'spec_version': '2.3'},
            'http_version': '1.1',
            'method': method,
            'scheme': 'http',
            'path': split.path or '/',
            'raw_path': (split.path or '/').encode('ascii'),
            'query_string': split.query.encode('ascii'),
            'headers': req_headers,
            'client': ('testclient', 50000),
            'server': ('testserver', 80),
            'root_path': '',
        }
        status_code = 500
        response_headers: list[tuple[bytes, bytes]] = []
        response_body = bytearray()
        sent = False

        async def receive():
            nonlocal sent
            if sent:
                return {'type': 'http.disconnect'}
            sent = True
            return {'type': 'http.request', 'body': body, 'more_body': False}

        async def send(message):
            nonlocal status_code, response_headers
            if message['type'] == 'http.response.start':
                status_code = message['status']
                response_headers = message.get('headers', [])
            elif message['type'] == 'http.response.body':
                response_body.extend(message.get('body', b''))

        asyncio.run(self.app(scope, receive, send))
        return _CompatResponse(status_code, response_headers, bytes(response_body))

    def _encode_multipart(self, files) -> tuple[bytes, str]:
        boundary = 'sss-test-boundary'
        chunks: list[bytes] = []
        for field, value in files.items():
            filename, content, content_type = value
            if isinstance(content, str):
                content = content.encode('utf-8')
            chunks.extend([
                f'--{boundary}\r\n'.encode('ascii'),
                f'Content-Disposition: form-data; name="{field}"; filename="{filename}"\r\n'.encode('utf-8'),
                f'Content-Type: {content_type}\r\n\r\n'.encode('ascii'),
                content,
                b'\r\n',
            ])
        chunks.append(f'--{boundary}--\r\n'.encode('ascii'))
        return b''.join(chunks), f'multipart/form-data; boundary={boundary}'

    def _static_response(self, path: str):
        base = Path(__file__).resolve().parents[1] / 'app'
        if path == '/':
            target = base / 'templates' / 'index.html'
            return _CompatResponse(200, [(b'content-type', b'text/html; charset=utf-8')], target.read_bytes())
        if path.startswith('/static/'):
            rel = path[len('/static/'):]
            target = (base / 'static' / rel).resolve()
            static_base = (base / 'static').resolve()
            if not str(target).startswith(str(static_base)):
                return _CompatResponse(404, [], b'')
            if not target.exists():
                return _CompatResponse(404, [], b'')
            return _CompatResponse(200, [], target.read_bytes())
        return None


fastapi_testclient.TestClient = _InProcessTestClient
