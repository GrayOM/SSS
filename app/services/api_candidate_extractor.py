import re

from app.models.schemas import ApiCallCandidate, CandidateExtractionResult, FileContent

_METHODS = ['get', 'post', 'put', 'delete', 'patch']
_META_KEYS = {'method', 'url', 'data', 'body', 'headers', 'credentials', 'withCredentials', 'mode', 'cache', 'expr'}
_RESPONSE_NOISE_KEYS = {
    'data', 'response', 'result', 'winnerData', 'paymentResult', 'productResponse',
    'chargeData', 'verifyRes', 'transactionData', 'walletData', 'existingOrderData',
}

_RESPONSE_VAR_RE = re.compile(r'\b([A-Za-z_][A-Za-z0-9_]*(?:Response|Result|Data|Res))\b')


def _normalize_endpoint(raw: str) -> tuple[str, list[str]]:
    notes: list[str] = []
    value = raw.strip()
    value = re.sub(r'\$\{([^}]+)\}', r'{\1}', value)
    has_base_variable = bool(re.match(r'^\{?(API_BASE|BASE_URL|apiBase)\}?', value))
    if has_base_variable:
        notes.append('base URL variable requires manual review')
        if re.match(r'^\{?(API_BASE|BASE_URL)\}?', value) and ' ' not in value:
            return value, notes
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


def _collect_call_block(lines: list[str], start_idx: int, max_lines: int = 40) -> tuple[int, int, str]:
    start = start_idx
    depth = 0
    end = start_idx
    saw_open = False
    for idx in range(start_idx, min(len(lines), start_idx + max_lines)):
        line = lines[idx]
        depth += line.count('(')
        if line.count('(') > 0:
            saw_open = True
        depth -= line.count(')')
        end = idx
        if saw_open and depth <= 0:
            break
    return start + 1, end + 1, '\n'.join(lines[start:end + 1])


def _extract_parameters(snippet: str, method: str) -> tuple[list[str], list[str]]:
    snippet = re.sub(r'\$\{[^}]+\}', '{expr}', snippet)
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
    allowed = set(params)
    m_upper = method.upper()
    if m_upper == 'GET':
        # GET: only query/params/urlsearchparams context
        allowed = set()
        for qm in re.finditer(r'[?&]([A-Za-z_][A-Za-z0-9_]*)=', snippet):
            allowed.add(qm.group(1))
        for pm in re.finditer(r'params\s*:\s*\{([^}]*)\}', snippet, re.DOTALL):
            for km in re.finditer(r'([A-Za-z_][A-Za-z0-9_]*)\s*(?::|,|$)', pm.group(1)):
                allowed.add(km.group(1))
        for um in re.finditer(r'URLSearchParams\(\s*\{([^}]*)\}', snippet, re.DOTALL):
            for km in re.finditer(r'([A-Za-z_][A-Za-z0-9_]*)\s*(?::|,|$)', um.group(1)):
                allowed.add(km.group(1))
    response_vars = set()
    for m in re.finditer(r'const\s+\{\s*data\s*:\s*([A-Za-z_][A-Za-z0-9_]*)\s*\}\s*=\s*await\s+(?:axios|fetch|\$\.ajax|jQuery\.ajax)', snippet):
        response_vars.add(m.group(1))
    for m in re.finditer(r'const\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*await\s+(?:axios|fetch|\$\.ajax|jQuery\.ajax)', snippet):
        response_vars.add(m.group(1))
    for m in _RESPONSE_VAR_RE.finditer(snippet):
        response_vars.add(m.group(1))

    out = sorted(
        k for k in allowed
        if k not in _META_KEYS
        and k.lower() not in {'expr', 'sessiondata'}
        and k not in _RESPONSE_NOISE_KEYS
        and k.lower() not in {x.lower() for x in _RESPONSE_NOISE_KEYS}
        and k not in response_vars
        and k.lower() not in {x.lower() for x in response_vars}
    )
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


def _extract_concat_endpoint(snip: str) -> tuple[str, list[str]] | None:
    m = re.search(r'\(\s*[A-Za-z_][A-Za-z0-9_]*\s*\+\s*(["\'`])(.+?)\1', snip)
    if not m:
        return None
    return _normalize_endpoint(m.group(2))


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
            line_has_api_candidate = False
            for pat, sink_tpl in patterns:
                matches = list(re.finditer(pat, stripped))
                if not matches:
                    continue
                for m in matches:
                    sink_name = m.group(1)
                    method = (m.group(2).upper() if len(m.groups()) > 1 and m.group(2) else 'UNKNOWN')
                    sink = sink_tpl.format(sink=sink_name, method=m.group(2) if len(m.groups()) > 1 and m.group(2) else '').replace('..', '.')
                    start_line, end_line, snip = _collect_call_block(lines, i)
                    notes = ['server-side authorization cannot be confirmed from frontend source only']

                    endpoint = 'UNKNOWN'
                    tail = snip[m.start():]
                    epm = re.search(r'\(\s*(["\'`])(.+?)\1', tail, re.DOTALL)
                    if epm:
                        endpoint, epnotes = _normalize_endpoint(epm.group(2))
                        notes.extend(epnotes)
                    elif _extract_concat_endpoint(tail):
                        endpoint, epnotes = _extract_concat_endpoint(tail)  # type: ignore
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
                        if re.search(r'url\s*:\s*([A-Za-z_][A-Za-z0-9_]*)\b', snip) and endpoint == 'UNKNOWN':
                            notes.append('generic ajax wrapper requires callsite tracing')
                    if sink == 'apiClient.request' or sink == 'request':
                        method, endpoint = _extract_object_style_request(snip, sink)
                        if endpoint == 'UNKNOWN':
                            notes.append('endpoint variable requires manual review')

                    params, pnotes = _extract_parameters(snip, method)
                    response_vars = set()
                    for rm in re.finditer(r'const\s+\{\s*data\s*:\s*([A-Za-z_][A-Za-z0-9_]*)\s*\}\s*=\s*await\s+(?:axios|fetch|\$\.ajax|jQuery\.ajax)', snip):
                        response_vars.add(rm.group(1).lower())
                    for rm in re.finditer(r'const\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*await\s+(?:axios|fetch|\$\.ajax|jQuery\.ajax)', snip):
                        response_vars.add(rm.group(1).lower())
                    for key in ('data', 'body', 'params'):
                        pv = re.search(rf'{key}\s*:\s*([A-Za-z_][A-Za-z0-9_]*)', snip)
                        if pv and method != 'GET' and pv.group(1).lower() not in {'undefined', 'null', 'expr'}:
                            params.append(pv.group(1))
                            notes.append('payload object requires manual review')
                    if method != 'GET':
                        near_start = max(0, i - 10)
                        near = '\n'.join(lines[near_start:i + 1])
                        for mfd in re.finditer(r'(?:FormData|[A-Za-z_][A-Za-z0-9_]*)\.append\(\s*["\']([^"\']+)', near):
                            params.append(mfd.group(1))
                    params = sorted({p for p in params if p.lower() not in {'expr', 'sessiondata'} and p.lower() not in response_vars})
                    notes.extend(pnotes)
                    if method == 'UNKNOWN':
                        notes.append('method could not be determined')
                    confidence = 'high' if endpoint != 'UNKNOWN' and method != 'UNKNOWN' and params else ('medium' if endpoint != 'UNKNOWN' and method != 'UNKNOWN' else 'low')
                    candidates.append(ApiCallCandidate(source_path=file.path, method=method, endpoint=endpoint, parameters=params, start_line=start_line, end_line=end_line, snippet=snip, sink=sink, confidence=confidence, notes=sorted(set(notes))))
                    line_has_api_candidate = True

            fn = re.search(r'([A-Za-z_][A-Za-z0-9_]*)\(([^)]*)\)', stripped)
            sensitive_verbs = ('update', 'charge', 'complete', 'pay', 'save', 'submit', 'create', 'modify', 'change', 'approve', 'cancel', 'refund', 'register', 'remove', 'delete', 'bid', 'order', 'payment', 'point', 'role', 'status')
            sensitive_tokens = ('amount', 'userid', 'orderid', 'status', 'role', 'price', 'payment', 'point', 'payload', 'data', 'form')
            fn_name = fn.group(1) if fn else ''
            token_sensitive = any(x in stripped.lower() for x in sensitive_tokens)
            excluded_fn = {'if', 'for', 'while', 'switch', 'fetch', 'get', 'post', 'put', 'delete', 'patch', 'request', 'ajax'}
            before_char = stripped[fn.start(1) - 1] if fn and fn.start(1) > 0 else ''
            if fn and fn_name not in excluded_fn and before_char != '.' and not line_has_api_candidate and (
                any(x in fn_name.lower() for x in sensitive_verbs) or (token_sensitive and not fn_name.lower().startswith('calculate'))
            ):
                start_line, end_line, snip = _snippet(lines, i, context=0)
                args = [a.strip() for a in fn.group(2).split(',') if a.strip()]
                candidates.append(ApiCallCandidate(source_path=file.path, method='UNKNOWN', endpoint='UNKNOWN', parameters=args[:20], start_line=start_line, end_line=end_line, snippet=snip, sink='function_call', confidence='low', notes=['wrapper/service function call requires implementation review', 'endpoint variable requires manual review']))

    return CandidateExtractionResult(total_candidates=len(candidates), candidates=candidates)
