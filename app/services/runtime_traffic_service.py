import json
import re
import shlex
import shutil
import subprocess
import zipfile
from email.parser import Parser
from io import BytesIO
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

from app.models.schemas import (
    CapturedHttpRequest,
    CapturedHttpResponse,
    ReadableAnalysisResult,
    ReadableFinding,
    RuntimeGeneratedPoc,
    RuntimeRequestCorrelation,
    RuntimeTrafficImportResult,
)


SENSITIVE_HEADER_PLACEHOLDERS = {
    'cookie': '<REPLACE_WITH_COOKIE>',
    'authorization': '<REPLACE_WITH_AUTHORIZATION>',
    'proxy-authorization': '<REPLACE_WITH_AUTHORIZATION>',
    'x-auth-token': '<REPLACE_WITH_AUTHORIZATION>',
    'x-csrf-token': '<REPLACE_WITH_CSRF_TOKEN>',
    'x-xsrf-token': '<REPLACE_WITH_CSRF_TOKEN>',
    'set-cookie': '<REDACTED>',
}

CSRF_HEADER_NAMES = {'x-csrf-token', 'x-xsrf-token'}
STATE_CHANGING_METHODS = {'POST', 'PUT', 'PATCH'}
NO_REPLAY_TERMS = ('refund', 'withdraw', 'transfer', 'bulk', 'remove')
SAFE_MUTATION_VALUES = {
    'amount': '1',
    'price': '1',
    'totalamount': '1',
    'usepoints': '1',
    'point': '1',
    'balance': '1',
    'coupon': '1',
    'discount': '1',
}
MANUAL_ID_KEYS = {'userid', 'memberid', 'accountid', 'orderid', 'paymentid', 'itemid'}
ROLE_KEYS = {'status', 'role', 'usertype', 'isadmin'}


def import_runtime_traffic(
    *,
    filename: str | None = None,
    content: bytes | None = None,
    text: str | None = None,
) -> RuntimeTrafficImportResult:
    if text and text.strip():
        return parse_traffic_text(text)
    if content is None:
        return RuntimeTrafficImportResult(
            provided=False,
            notes=['No runtime traffic provided; source-only analysis used.'],
        )
    suffix = Path(filename or '').suffix.lower()
    if suffix == '.har':
        return parse_har(content.decode('utf-8', errors='replace'))
    if suffix == '.saz':
        return parse_saz(content)
    if suffix in {'.pcap', '.pcapng'}:
        return parse_pcap(content, filename=filename)
    return parse_traffic_text(content.decode('utf-8', errors='replace'), filename=filename)


def parse_traffic_text(text: str, filename: str | None = None) -> RuntimeTrafficImportResult:
    stripped = text.strip()
    if not stripped:
        return RuntimeTrafficImportResult(
            provided=False,
            notes=['No runtime traffic provided; source-only analysis used.'],
        )
    if filename and filename.lower().endswith('.har'):
        return parse_har(text)
    if stripped[:1] in {'{', '['}:
        try:
            payload = json.loads(stripped)
        except json.JSONDecodeError:
            payload = None
        if isinstance(payload, dict) and 'log' in payload:
            return _parse_har_payload(payload)
    if stripped.lower().startswith('curl '):
        request = parse_curl_command(stripped, request_index=0)
        return RuntimeTrafficImportResult(
            provided=True,
            source_format='curl',
            request_count=1 if request else 0,
            requests=[request] if request else [],
            limitations=[] if request else ['curl command could not be parsed.'],
        )
    request = parse_raw_http_request(stripped, source_format='raw_http', request_index=0)
    return RuntimeTrafficImportResult(
        provided=True,
        source_format='raw_http',
        request_count=1 if request else 0,
        requests=[request] if request else [],
        limitations=[] if request else ['Raw HTTP request could not be parsed.'],
    )


def parse_har(text: str) -> RuntimeTrafficImportResult:
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return RuntimeTrafficImportResult(
            provided=True,
            source_format='har',
            limitations=['HAR JSON could not be parsed.'],
        )
    if not isinstance(payload, dict):
        return RuntimeTrafficImportResult(
            provided=True,
            source_format='har',
            limitations=['HAR root must be a JSON object.'],
        )
    return _parse_har_payload(payload)


def _parse_har_payload(payload: dict[str, Any]) -> RuntimeTrafficImportResult:
    entries = payload.get('log', {}).get('entries', [])
    requests: list[CapturedHttpRequest] = []
    limitations: list[str] = []
    if not isinstance(entries, list):
        return RuntimeTrafficImportResult(
            provided=True,
            source_format='har',
            limitations=['HAR log.entries must be a list.'],
        )
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            continue
        req = entry.get('request') or {}
        resp = entry.get('response') or {}
        if not isinstance(req, dict):
            continue
        headers = _headers_list_to_dict(req.get('headers'))
        query_params = _query_list_to_dict(req.get('queryString'))
        body_text = None
        post_data = req.get('postData') or {}
        if isinstance(post_data, dict):
            body_text = post_data.get('text') if isinstance(post_data.get('text'), str) else None
            if post_data.get('mimeType') and 'content-type' not in {k.lower() for k in headers}:
                headers['Content-Type'] = str(post_data.get('mimeType'))
        response = None
        if isinstance(resp, dict):
            content = resp.get('content') if isinstance(resp.get('content'), dict) else {}
            response = CapturedHttpResponse(
                status_code=resp.get('status') if isinstance(resp.get('status'), int) else None,
                content_type=str(content.get('mimeType')) if content.get('mimeType') else _get_header(headers, 'content-type'),
                body_preview=_preview(content.get('text')) if isinstance(content.get('text'), str) else None,
                redacted_headers=_redact_headers(_headers_list_to_dict(resp.get('headers'))),
            )
        requests.append(_build_request(
            source_format='har',
            method=str(req.get('method') or 'GET'),
            full_url=str(req.get('url') or ''),
            headers=headers,
            query_params=query_params,
            body_text=body_text,
            request_index=len(requests),
            timestamp=entry.get('startedDateTime') if isinstance(entry.get('startedDateTime'), str) else None,
            response=response,
        ))
    if not requests:
        limitations.append('HAR contained no parseable HTTP requests.')
    return RuntimeTrafficImportResult(
        provided=True,
        source_format='har',
        request_count=len(requests),
        requests=requests,
        limitations=limitations,
    )


def parse_curl_command(command: str, request_index: int = 0) -> CapturedHttpRequest | None:
    try:
        parts = shlex.split(command)
    except ValueError:
        return None
    if not parts or parts[0] != 'curl':
        return None
    method = None
    headers: dict[str, str] = {}
    body_parts: list[str] = []
    url = None
    i = 1
    while i < len(parts):
        part = parts[i]
        if part in {'-X', '--request'} and i + 1 < len(parts):
            method = parts[i + 1].upper()
            i += 2
            continue
        if part.startswith('-X') and len(part) > 2:
            method = part[2:].upper()
            i += 1
            continue
        if part in {'-H', '--header'} and i + 1 < len(parts):
            _add_header_line(headers, parts[i + 1])
            i += 2
            continue
        if part.startswith('-H') and len(part) > 2:
            _add_header_line(headers, part[2:])
            i += 1
            continue
        if part in {'--data', '--data-raw', '--data-binary', '--data-ascii', '-d'} and i + 1 < len(parts):
            body_parts.append(parts[i + 1])
            method = method or 'POST'
            i += 2
            continue
        if part.startswith('http://') or part.startswith('https://'):
            url = part
        i += 1
    if not url:
        return None
    return _build_request(
        source_format='curl',
        method=method or 'GET',
        full_url=url,
        headers=headers,
        body_text='&'.join(body_parts) if len(body_parts) > 1 else (body_parts[0] if body_parts else None),
        request_index=request_index,
    )


def parse_raw_http_request(
    text: str,
    *,
    source_format: str = 'raw_http',
    request_index: int = 0,
    response: CapturedHttpResponse | None = None,
) -> CapturedHttpRequest | None:
    normalized = text.replace('\r\n', '\n')
    head, _, body = normalized.partition('\n\n')
    lines = [line for line in head.split('\n') if line.strip()]
    if not lines:
        return None
    match = re.match(r'^([A-Z]+)\s+(\S+)\s+HTTP/\d(?:\.\d)?$', lines[0].strip(), re.IGNORECASE)
    if not match:
        return None
    method, target = match.group(1).upper(), match.group(2)
    headers = _parse_header_block('\n'.join(lines[1:]))
    host = _get_header(headers, 'host')
    scheme = 'https' if _get_header(headers, 'x-forwarded-proto') == 'https' else 'http'
    if target.startswith(('http://', 'https://')):
        full_url = target
    elif host:
        full_url = f'{scheme}://{host}{target}'
    else:
        full_url = target
    return _build_request(
        source_format=source_format,
        method=method,
        full_url=full_url,
        headers=headers,
        body_text=body if body else None,
        request_index=request_index,
        response=response,
    )


def parse_saz(content: bytes) -> RuntimeTrafficImportResult:
    requests: list[CapturedHttpRequest] = []
    limitations: list[str] = []
    try:
        with zipfile.ZipFile(BytesIO(content)) as zf:
            names = zf.namelist()
            client_files = sorted(n for n in names if re.search(r'_c\.(txt|raw)$', n, re.IGNORECASE))
            server_files = {re.sub(r'_s\.(txt|raw)$', '', n, flags=re.IGNORECASE): n for n in names if re.search(r'_s\.(txt|raw)$', n, re.IGNORECASE)}
            if not client_files:
                return RuntimeTrafficImportResult(
                    provided=True,
                    source_format='saz',
                    limitations=['Unsupported SAZ structure: no raw client request files found.'],
                )
            for client_name in client_files:
                stem = re.sub(r'_c\.(txt|raw)$', '', client_name, flags=re.IGNORECASE)
                response = None
                server_name = server_files.get(stem)
                if server_name:
                    response = _parse_raw_http_response(zf.read(server_name).decode('utf-8', errors='replace'))
                request = parse_raw_http_request(
                    zf.read(client_name).decode('utf-8', errors='replace'),
                    source_format='saz',
                    request_index=len(requests),
                    response=response,
                )
                if request:
                    requests.append(request)
    except zipfile.BadZipFile:
        return RuntimeTrafficImportResult(
            provided=True,
            source_format='saz',
            limitations=['SAZ file is not a readable ZIP archive.'],
        )
    if not requests:
        limitations.append('SAZ archive contained no parseable raw HTTP requests.')
    return RuntimeTrafficImportResult(
        provided=True,
        source_format='saz',
        request_count=len(requests),
        requests=requests,
        limitations=limitations,
    )


def parse_pcap(content: bytes, filename: str | None = None) -> RuntimeTrafficImportResult:
    if shutil.which('tshark') is None:
        return RuntimeTrafficImportResult(
            provided=True,
            source_format='pcap',
            limitations=[
                'PCAP/PCAPNG parsing requires tshark or an exported HTTP stream.',
                'Encrypted HTTPS traffic cannot expose request path/body without TLS decryption keys or decrypted export.',
            ],
        )
    tmp_path = Path('/tmp') / f'sss-traffic-{abs(hash((filename, len(content))))}.pcap'
    tmp_path.write_bytes(content)
    try:
        proc = subprocess.run(
            [
                'tshark',
                '-r',
                str(tmp_path),
                '-Y',
                'http.request',
                '-T',
                'fields',
                '-e',
                'http.request.method',
                '-e',
                'http.host',
                '-e',
                'http.request.uri',
            ],
            check=False,
            text=True,
            capture_output=True,
            timeout=10,
        )
    except Exception:
        return RuntimeTrafficImportResult(
            provided=True,
            source_format='pcap',
            limitations=['PCAP/PCAPNG parsing with tshark failed.'],
        )
    finally:
        tmp_path.unlink(missing_ok=True)
    requests: list[CapturedHttpRequest] = []
    for line in proc.stdout.splitlines():
        cols = line.split('\t')
        if len(cols) < 3 or not cols[0] or not cols[1] or not cols[2]:
            continue
        requests.append(_build_request(
            source_format='pcap',
            method=cols[0],
            full_url=f'http://{cols[1]}{cols[2]}',
            headers={'Host': cols[1]},
            request_index=len(requests),
        ))
    limitations = ['Encrypted HTTPS traffic cannot expose request path/body without TLS decryption keys or decrypted export.']
    if not requests:
        limitations.insert(0, 'No plaintext HTTP requests were extracted from PCAP/PCAPNG.')
    return RuntimeTrafficImportResult(
        provided=True,
        source_format='pcap',
        request_count=len(requests),
        requests=requests,
        limitations=limitations,
    )


def enrich_analysis_with_runtime_traffic(
    readable_analysis: ReadableAnalysisResult | None,
    traffic: RuntimeTrafficImportResult,
) -> RuntimeTrafficImportResult:
    if not readable_analysis or not traffic.requests:
        return traffic
    correlations: list[RuntimeRequestCorrelation] = []
    for finding in readable_analysis.findings:
        best = _best_correlation(finding, traffic.requests)
        if not best:
            continue
        request, score, reasons, endpoint, placeholders, mutable = best
        finding.status = 'runtime_request_correlated_candidate'
        finding.poc_generation_status = 'runtime_assisted'
        if 'Runtime traffic matched this source finding; not confirmed without vulnerable behavior proof.' not in finding.verification_notes:
            finding.verification_notes.append('Runtime traffic matched this source finding; not confirmed without vulnerable behavior proof.')
        correlations.append(RuntimeRequestCorrelation(
            finding_id=finding.id,
            finding_title=finding.title,
            lifecycle_status='runtime_request_correlated_candidate',
            request_index=request.request_index,
            method=request.method,
            source_endpoint=endpoint,
            captured_path=request.path,
            score=score,
            reasons=reasons,
            placeholder_mapping=placeholders,
            mutable_parameters=mutable,
            generated_pocs=_generate_runtime_pocs(request, mutable),
        ))
    profile = readable_analysis.project_profile
    if profile:
        profile.confirmed_findings = 0
    return traffic.model_copy(update={'correlations': correlations})


def _best_correlation(
    finding: ReadableFinding,
    requests: list[CapturedHttpRequest],
) -> tuple[CapturedHttpRequest, int, list[str], str | None, dict[str, str], list[str]] | None:
    method, endpoint, params = _finding_runtime_hints(finding)
    if not endpoint or endpoint == 'UNKNOWN':
        return None
    best: tuple[CapturedHttpRequest, int, list[str], str | None, dict[str, str], list[str]] | None = None
    for request in requests:
        score = 0
        reasons: list[str] = []
        if method and method != 'UNKNOWN' and request.method.upper() == method.upper():
            score += 4
            reasons.append('method')
        elif method and method != 'UNKNOWN':
            score -= 2
        placeholders = _match_path_template(endpoint, request.path)
        if placeholders is not None:
            score += 8
            reasons.append('path_template')
        elif _path_suffix_match(endpoint, request.path):
            score += 5
            reasons.append('endpoint_suffix')
            placeholders = {}
        else:
            placeholders = {}
        request_keys = set(request.body_keys)
        request_keys.update(request.query_params.keys())
        overlap = sorted({p for p in params if p in request_keys})
        if overlap:
            score += 2 * len(overlap)
            reasons.append('parameter_overlap')
        if endpoint and endpoint in (finding.data_flow.api_call_or_sink if finding.data_flow else ''):
            score += 1
            reasons.append('source_data_flow')
        mutable = sorted(request_keys.intersection(set(params)) or _safe_mutable_keys(request_keys))
        candidate = (request, score, reasons, endpoint, placeholders, mutable)
        if score >= 7 and (best is None or score > best[1]):
            best = candidate
    return best


def _finding_runtime_hints(finding: ReadableFinding) -> tuple[str | None, str | None, list[str]]:
    flows = finding.evidence[0].data_flow if finding.evidence else []
    method = next((x[len('method: '):] for x in flows if x.startswith('method: ')), None)
    endpoint = next((x[len('endpoint: '):] for x in flows if x.startswith('endpoint: ')), None)
    params = [x[len('parameter: '):] for x in flows if x.startswith('parameter: ')]
    if finding.data_flow and finding.data_flow.api_call_or_sink:
        match = re.search(r'(GET|POST|PUT|PATCH|DELETE)\s+(\S+)', finding.data_flow.api_call_or_sink)
        if match:
            method = method or match.group(1)
            endpoint = endpoint or match.group(2)
    return method, endpoint, params


def _generate_runtime_pocs(request: CapturedHttpRequest, mutable_parameters: list[str]) -> list[RuntimeGeneratedPoc]:
    if request.method.upper() == 'DELETE' or any(term in request.path.lower() for term in NO_REPLAY_TERMS):
        return [RuntimeGeneratedPoc(
            poc_type='manual_plan',
            title='Replay PoC blocked for safety',
            safety='No replay code generated for destructive or high-risk operation.',
            mutation_guidance=_mutation_guidance(mutable_parameters),
            limitations=['Use manual review with explicit approval and safe test objects.'],
        )]
    return [
        RuntimeGeneratedPoc(
            poc_type='browser_console_fetch',
            title='Browser Console fetch PoC',
            code=_browser_fetch_poc(request),
            safety='Use only in an approved test session. Sensitive headers are placeholders.',
            mutation_guidance=_mutation_guidance(mutable_parameters),
        ),
        RuntimeGeneratedPoc(
            poc_type='curl',
            title='curl PoC',
            code=_curl_poc(request),
            safety='Use only in an approved test environment. Sensitive values are placeholders.',
            mutation_guidance=_mutation_guidance(mutable_parameters),
        ),
        RuntimeGeneratedPoc(
            poc_type='python_requests',
            title='Python requests PoC',
            code=_python_requests_poc(request),
            safety='Prints status code and response preview only. Sensitive values are placeholders.',
            mutation_guidance=_mutation_guidance(mutable_parameters),
        ),
    ]


def _browser_fetch_poc(request: CapturedHttpRequest) -> str:
    url = request.path + (_query_string(request.query_params) if request.query_params else '')
    headers = _headers_for_poc(request, include_cookie=False)
    lines = []
    if request.method.upper() in STATE_CHANGING_METHODS:
        lines.append("if (!confirm('Run this approved test request?')) { throw new Error('Cancelled'); }")
    lines.append(f'fetch({json.dumps(url)}, {{')
    lines.append(f'  method: {json.dumps(request.method.upper())},')
    if request.cookies_present:
        lines.append("  credentials: 'include',")
    if headers:
        lines.append(f'  headers: {json.dumps(headers, indent=2)},')
    if request.body_text is not None:
        lines.append(f'  body: {json.dumps(request.body_text)},')
    lines.append('}).then(async r => ({ status: r.status, preview: (await r.text()).slice(0, 500) }))')
    lines.append('  .then(console.log);')
    return '\n'.join(lines)


def _curl_poc(request: CapturedHttpRequest) -> str:
    parts = ['curl', '-i', '-X', shlex.quote(request.method.upper()), shlex.quote(request.full_url)]
    for key, value in _headers_for_poc(request, include_cookie=True).items():
        parts.extend(['-H', shlex.quote(f'{key}: {value}')])
    if request.body_text is not None:
        parts.extend(['--data-raw', shlex.quote(request.body_text)])
    return ' '.join(parts)


def _python_requests_poc(request: CapturedHttpRequest) -> str:
    headers = _headers_for_poc(request, include_cookie=True)
    return '\n'.join([
        'import requests',
        '',
        'session = requests.Session()',
        f'headers = {json.dumps(headers, indent=2)}',
        f'response = session.request({request.method.upper()!r}, {request.full_url!r}, headers=headers, data={request.body_text!r})',
        'print(response.status_code)',
        'print(response.text[:500])',
    ])


def _build_request(
    *,
    source_format: str,
    method: str,
    full_url: str,
    headers: dict[str, str],
    request_index: int,
    query_params: dict[str, list[str]] | None = None,
    body_text: str | None = None,
    timestamp: str | None = None,
    response: CapturedHttpResponse | None = None,
) -> CapturedHttpRequest:
    split = urlsplit(full_url)
    path = split.path or full_url.split('?', 1)[0] or '/'
    query = query_params if query_params is not None else parse_qs(split.query, keep_blank_values=True)
    redacted = _redact_headers(headers)
    content_type = _get_header(headers, 'content-type')
    body_json, body_form, body_keys = _parse_body(body_text, content_type)
    return CapturedHttpRequest(
        source_format=source_format,
        method=method.upper(),
        full_url=full_url,
        scheme=split.scheme or None,
        host=split.netloc or _get_header(headers, 'host'),
        path=path,
        query_params=query,
        headers=redacted,
        redacted_headers=redacted,
        cookies_present=_get_header(headers, 'cookie') is not None,
        authorization_present=any(_get_header(headers, h) is not None for h in ('authorization', 'proxy-authorization', 'x-auth-token')),
        csrf_token_present=any(_get_header(headers, h) is not None for h in CSRF_HEADER_NAMES),
        content_type=content_type,
        body_text=body_text,
        body_json=body_json,
        body_form=body_form,
        body_keys=body_keys,
        request_index=request_index,
        timestamp=timestamp,
        response=response,
    )


def _parse_body(body_text: str | None, content_type: str | None) -> tuple[Any | None, dict[str, list[str]], list[str]]:
    if not body_text:
        return None, {}, []
    low_type = (content_type or '').lower()
    if 'json' in low_type:
        try:
            payload = json.loads(body_text)
        except json.JSONDecodeError:
            return None, {}, []
        keys = sorted(payload.keys()) if isinstance(payload, dict) else []
        return payload, {}, keys
    if 'x-www-form-urlencoded' in low_type or '=' in body_text:
        form = parse_qs(body_text, keep_blank_values=True)
        return None, form, sorted(form.keys())
    return None, {}, []


def _redact_headers(headers: dict[str, str]) -> dict[str, str]:
    redacted: dict[str, str] = {}
    for key, value in headers.items():
        placeholder = SENSITIVE_HEADER_PLACEHOLDERS.get(key.lower())
        redacted[key] = placeholder if placeholder else value
    return redacted


def _headers_for_poc(request: CapturedHttpRequest, *, include_cookie: bool) -> dict[str, str]:
    headers: dict[str, str] = {}
    for key, value in request.redacted_headers.items():
        low = key.lower()
        if low in {'host', 'content-length'}:
            continue
        if low == 'cookie' and not include_cookie:
            continue
        headers[key] = value
    return headers


def _headers_list_to_dict(headers: Any) -> dict[str, str]:
    result: dict[str, str] = {}
    if isinstance(headers, list):
        for item in headers:
            if isinstance(item, dict) and item.get('name') is not None:
                result[str(item.get('name'))] = str(item.get('value') or '')
    return result


def _query_list_to_dict(query: Any) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    if isinstance(query, list):
        for item in query:
            if isinstance(item, dict) and item.get('name') is not None:
                result.setdefault(str(item.get('name')), []).append(str(item.get('value') or ''))
    return result


def _parse_header_block(block: str) -> dict[str, str]:
    headers = Parser().parsestr(block)
    return {key: value for key, value in headers.items()}


def _parse_raw_http_response(text: str) -> CapturedHttpResponse | None:
    normalized = text.replace('\r\n', '\n')
    head, _, body = normalized.partition('\n\n')
    lines = [line for line in head.split('\n') if line.strip()]
    if not lines:
        return None
    match = re.match(r'^HTTP/\d(?:\.\d)?\s+(\d{3})', lines[0])
    status = int(match.group(1)) if match else None
    headers = _parse_header_block('\n'.join(lines[1:]))
    return CapturedHttpResponse(
        status_code=status,
        content_type=_get_header(headers, 'content-type'),
        body_preview=_preview(body) if body else None,
        redacted_headers=_redact_headers(headers),
    )


def _get_header(headers: dict[str, str], name: str) -> str | None:
    for key, value in headers.items():
        if key.lower() == name.lower():
            return value
    return None


def _add_header_line(headers: dict[str, str], line: str) -> None:
    if ':' not in line:
        return
    key, value = line.split(':', 1)
    headers[key.strip()] = value.strip()


def _preview(value: str, limit: int = 500) -> str:
    return value[:limit]


def _query_string(params: dict[str, list[str]]) -> str:
    parts: list[str] = []
    for key, values in params.items():
        for value in values:
            parts.append(f'{key}={value}')
    return '?' + '&'.join(parts) if parts else ''


def _path_suffix_match(template: str, path: str) -> bool:
    template_parts = [p for p in _normalize_path(template).split('/') if p]
    path_parts = [p for p in _normalize_path(path).split('/') if p]
    if not template_parts or not path_parts or len(path_parts) < len(template_parts):
        return False
    tail = path_parts[-len(template_parts):]
    for left, right in zip(template_parts, tail):
        if _is_placeholder(left):
            continue
        if left != right:
            return False
    return True


def _match_path_template(template: str, path: str) -> dict[str, str] | None:
    template_parts = [p for p in _normalize_path(template).split('/') if p]
    path_parts = [p for p in _normalize_path(path).split('/') if p]
    if len(template_parts) != len(path_parts):
        return None
    mapping: dict[str, str] = {}
    for t_part, p_part in zip(template_parts, path_parts):
        if _is_placeholder(t_part):
            mapping[_placeholder_label(t_part.strip('{}:'))] = p_part
        elif t_part != p_part:
            return None
    return mapping


def _normalize_path(value: str) -> str:
    if value.startswith(('http://', 'https://')):
        value = urlsplit(value).path
    value = re.sub(r'^\{api_base_url\}', '', value, flags=re.IGNORECASE)
    value = re.sub(r'^\{api_base\}', '', value, flags=re.IGNORECASE)
    return value.split('?', 1)[0].rstrip('/') or '/'


def _is_placeholder(part: str) -> bool:
    return (part.startswith('{') and part.endswith('}')) or part.startswith(':')


def _placeholder_label(name: str) -> str:
    clean = re.sub(r'^(current|target|selected)', '', name, flags=re.IGNORECASE) or name
    clean = re.sub(r'([a-z0-9])([A-Z])', r'\1_\2', clean)
    clean = clean.replace('-', '_').upper()
    if clean in {'USERID', 'USER_ID'}:
        return 'USER_ID'
    return clean


def _safe_mutable_keys(keys: set[str]) -> list[str]:
    lowered = {k.lower(): k for k in keys}
    selected = []
    for key in SAFE_MUTATION_VALUES:
        if key in lowered:
            selected.append(lowered[key])
    return sorted(selected)


def _mutation_guidance(keys: list[str]) -> list[str]:
    guidance: list[str] = []
    for key in keys:
        low = key.lower()
        compact = re.sub(r'[^a-z0-9]', '', low)
        if compact in SAFE_MUTATION_VALUES:
            guidance.append(f'{key}: safe test mutation -> {SAFE_MUTATION_VALUES[compact]}')
        elif compact in ROLE_KEYS:
            guidance.append(f'{key}: TEST_VALUE only with clear authorization context; otherwise manual review')
        elif compact in MANUAL_ID_KEYS:
            guidance.append(f'{key}: requires approved second test account/object')
        elif 'code' in compact or 'token' in compact:
            guidance.append(f'{key}: manual plan unless rate-limit/token-binding test plan exists')
    return guidance
