import re

from app.models.schemas import ApiCallCandidate, CandidateExtractionResult, FileContent

_METHODS = ['get', 'post', 'put', 'delete', 'patch']


def _normalize_endpoint(raw: str) -> tuple[str, list[str]]:
    notes: list[str] = []
    value = raw.strip()
    value = re.sub(r'\$\{([^}]+)\}', r'{\1}', value)
    value = re.sub(r'^\{?[A-Za-z_][A-Za-z0-9_]*\}?\s*\+\s*', '', value)
    value = re.sub(r'^\{apiBase\}', '', value, flags=re.IGNORECASE)
    if '/api/' in value:
        value = value[value.index('/api/'):]
    elif '/v1/' in value:
        value = value[value.index('/v1/'):]
    if value.startswith(('/', '{')) and (' ' not in value):
        return value, notes
    notes.append('endpoint variable requires manual review')
    return 'UNKNOWN', notes


def _snippet(lines: list[str], line_idx: int, context: int = 6) -> tuple[int, int, str]:
    start = max(0, line_idx - context)
    end = min(len(lines) - 1, line_idx + context)
    return start + 1, end + 1, '\n'.join(lines[start:end + 1])


def _extract_parameters(snippet: str) -> tuple[list[str], list[str]]:
    params = set()
    notes = []
    for m in re.finditer(r'\{\s*([A-Za-z_][A-Za-z0-9_]*)\s*(?::[^,}]*)?(?:,|})', snippet):
        params.add(m.group(1))
    for block in re.findall(r'\{([^{}]+)\}', snippet):
        for token in block.split(','):
            t = token.strip()
            if not t:
                continue
            k = re.match(r'([A-Za-z_][A-Za-z0-9_]*)', t)
            if k:
                params.add(k.group(1))
    for m in re.finditer(r'JSON\.stringify\(\s*\{([^}]*)\}', snippet):
        for km in re.finditer(r'([A-Za-z_][A-Za-z0-9_]*)\s*(?::|,|$)', m.group(1)):
            params.add(km.group(1))
    for m in re.finditer(r'FormData\.append\(\s*["\']([^"\']+)', snippet):
        params.add(m.group(1))
    for m in re.finditer(r'URLSearchParams\(\s*\{([^}]*)\}', snippet):
        for km in re.finditer(r'([A-Za-z_][A-Za-z0-9_]*)\s*:', m.group(1)):
            params.add(km.group(1))
    out = sorted(params)
    if len(out) > 20:
        notes.append('parameter list truncated')
        out = out[:20]
    return out, notes


def _extract_object_style_request(snip: str, sink: str) -> tuple[str, str]:
    mm = re.search(r'method\s*:\s*["\']([A-Za-z]+)["\']', snip)
    method = mm.group(1).upper() if mm else 'UNKNOWN'
    um = re.search(r'url\s*:\s*(["\'`])(.+?)\1', snip)
    if um:
        endpoint, _ = _normalize_endpoint(um.group(2))
        return method, endpoint
    return method, 'UNKNOWN'


def extract_api_call_candidates(files: list[FileContent]) -> CandidateExtractionResult:
    candidates: list[ApiCallCandidate] = []
    patterns = [
        (r'(axios)\.(get|post|put|delete|patch)\(', 'axios.{method}'),
        (r'(apiClient|request|httpClient|client)\.(get|post|put|delete|patch)\(', '{sink}.{method}'),
        (r'(fetch)\(', 'fetch'),
        (r'(\$\.ajax|jQuery\.ajax)\(', '$.ajax'),
        (r'(apiClient)\.request\(', 'apiClient.request'),
        (r'\b(request)\(', 'request'),
    ]

    for file in files:
        lines = file.content.splitlines() or ['']
        for i, line in enumerate(lines):
            stripped = line.strip()
            for pat, sink_tpl in patterns:
                m = re.search(pat, stripped)
                if not m:
                    continue
                sink_name = m.group(1)
                method = (m.group(2).upper() if len(m.groups()) > 1 and m.group(2) else 'UNKNOWN')
                sink = sink_tpl.format(sink=sink_name, method=m.group(2) if len(m.groups()) > 1 and m.group(2) else '').replace('..', '.')
                start_line, end_line, snip = _snippet(lines, i, context=0)
                notes = ['server-side authorization cannot be confirmed from frontend source only']

                endpoint = 'UNKNOWN'
                tail = stripped[m.start():]
                epm = re.search(r'\(\s*(["\'`])(.+?)\1', tail)
                if epm:
                    endpoint, epnotes = _normalize_endpoint(epm.group(2))
                    notes.extend(epnotes)
                elif 'url:' in snip:
                    um = re.search(r'url\s*:\s*(["\'`])(.+?)\1', snip)
                    if um:
                        endpoint, epnotes = _normalize_endpoint(um.group(2))
                        notes.extend(epnotes)
                    else:
                        notes.append('endpoint variable requires manual review')
                else:
                    notes.append('endpoint variable requires manual review')

                if sink_name == 'fetch':
                    mm = re.search(r'method\s*:\s*["\']([A-Za-z]+)["\']', snip)
                    method = mm.group(1).upper() if mm else 'GET'
                if sink_name in ('$.ajax', 'jQuery.ajax'):
                    mm = re.search(r'(?:type|method)\s*:\s*["\']([A-Za-z]+)["\']', snip)
                    method = mm.group(1).upper() if mm else 'UNKNOWN'
                if sink_name == 'request' or 'request(' in stripped:
                    method, endpoint = _extract_object_style_request(snip, sink)
                    if endpoint == 'UNKNOWN':
                        notes.append('endpoint variable requires manual review')

                params, pnotes = _extract_parameters(snip)
                notes.extend(pnotes)
                if method == 'UNKNOWN':
                    notes.append('method could not be determined')
                confidence = 'high' if endpoint != 'UNKNOWN' and method != 'UNKNOWN' and params else ('medium' if endpoint != 'UNKNOWN' and method != 'UNKNOWN' else 'low')

                candidates.append(ApiCallCandidate(source_path=file.path, method=method, endpoint=endpoint, parameters=params, start_line=start_line, end_line=end_line, snippet=snip, sink=sink, confidence=confidence, notes=sorted(set(notes))))

            fn = re.search(r'([A-Za-z_][A-Za-z0-9_]*)\(([^)]*)\)', stripped)
            sensitive_verbs = ('update', 'charge', 'complete', 'pay', 'save', 'submit', 'create', 'modify', 'change', 'approve', 'cancel', 'refund', 'register', 'remove', 'delete', 'bid', 'order', 'payment', 'point', 'role', 'status')
            sensitive_tokens = ('amount', 'userid', 'orderid', 'status', 'role', 'price', 'payment', 'point', 'payload', 'data', 'form')
            fn_name = fn.group(1) if fn else ''
            token_sensitive = any(x in stripped.lower() for x in sensitive_tokens)
            if fn and fn_name not in {'if', 'for', 'while', 'switch', 'fetch'} and (
                any(x in fn_name.lower() for x in sensitive_verbs) or (token_sensitive and not fn_name.lower().startswith('calculate'))
            ):
                start_line, end_line, snip = _snippet(lines, i, context=0)
                args = [a.strip() for a in fn.group(2).split(',') if a.strip()]
                candidates.append(ApiCallCandidate(source_path=file.path, method='UNKNOWN', endpoint='UNKNOWN', parameters=args[:20], start_line=start_line, end_line=end_line, snippet=snip, sink='function_call', confidence='low', notes=['wrapper/service function call requires implementation review', 'endpoint variable requires manual review']))

    return CandidateExtractionResult(total_candidates=len(candidates), candidates=candidates)
