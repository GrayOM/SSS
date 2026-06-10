import re

from app.models.schemas import ApiCallCandidate, CandidateExtractionResult, FileContent
from app.services.poc_templates import normalize_endpoint

_METHODS = ['get', 'post', 'put', 'delete', 'patch']
_META_KEYS = {'method', 'url', 'data', 'body', 'headers', 'credentials', 'withCredentials', 'mode', 'cache', 'expr', 'baseURL', 'baseUrl'}
_RESPONSE_NOISE_KEYS = {
    'data', 'response', 'result', 'winnerData', 'paymentResult', 'productResponse',
    'chargeData', 'verifyRes', 'transactionData', 'walletData', 'existingOrderData',
}

_RESPONSE_VAR_RE = re.compile(r'\b([A-Za-z_][A-Za-z0-9_]*(?:Response|Result|Data|Res))\b')
_BASE_URL_VAR_RE = re.compile(
    r'^(?:API_BASE_URL|API_BASE|API_URL|BASE_URL|REACT_APP_API_URL|VITE_API_URL|'
    r'[A-Za-z_][A-Za-z0-9_]*(?:_URL|_BASE|_BASEURL|_BASE_URL)|apiBase)$',
    re.IGNORECASE,
)


def _normalize_endpoint(raw: str) -> tuple[str, list[str]]:
    notes: list[str] = []
    value = raw.strip()
    value = re.sub(r'\$\{([^}]+)\}', r'{\1}', value)
    leading_var = re.match(r'^\{?([A-Za-z_][A-Za-z0-9_]*)\}?', value)
    has_base_variable = bool(leading_var and _BASE_URL_VAR_RE.match(leading_var.group(1)))
    if has_base_variable:
        normalized = normalize_endpoint(value)
        if normalized.startswith('/') and normalized != '/UNKNOWN_PATH':
            return normalized, notes
        notes.append('base URL variable requires manual review')
    value = re.sub(
        r'^\{?([A-Za-z_][A-Za-z0-9_]*)\}?\s*\+\s*',
        lambda m: '' if _BASE_URL_VAR_RE.match(m.group(1)) else m.group(0),
        value,
    )
    value = re.sub(r'^\{(apiBase|API_BASE_URL|API_BASE|API_URL|BASE_URL|REACT_APP_API_URL|VITE_API_URL)\}', '', value, flags=re.IGNORECASE)
    if '/api/' in value:
        if not value.startswith('{'):
            value = value[value.index('/api/'):]
    elif '/v1/' in value:
        if not value.startswith('{'):
            value = value[value.index('/v1/'):]
    # Strip any unrecognized base-URL variable in template-literal form:
    # e.g. {API_URL}/login -> /login, {REACT_APP_API_URL}/users -> /users
    _tl_m = re.match(r'^\{([A-Za-z_][A-Za-z0-9_]*)\}(/\S+)', value)
    if _tl_m and _BASE_URL_VAR_RE.match(_tl_m.group(1)):
        return _tl_m.group(2), notes
    if value.startswith(('/', '{')) and (' ' not in value):
        return value, notes
    notes.append('endpoint variable requires manual review')
    return 'UNKNOWN', notes


def _endpoint_aliases(lines: list[str]) -> dict[str, str]:
    aliases: dict[str, str] = {}
    assign_re = re.compile(
        r'(?:private\s+readonly\s+|readonly\s+|public\s+|private\s+|protected\s+|const\s+|let\s+|var\s+)?'
        r'(?:this\.)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+)'
    )
    for line in lines:
        m = assign_re.search(line.strip().rstrip(';'))
        if not m:
            continue
        name, expr = m.group(1), m.group(2)
        quoted = [q.group(2) for q in re.finditer(r'(["\'`])(.+?)\1', expr)]
        if not quoted:
            continue
        raw = ''.join(part for part in quoted if part.startswith(('/', '{')) or '/api/' in part or '/rest/' in part or '/v1/' in part)
        if not raw:
            continue
        endpoint, _ = _normalize_endpoint(raw)
        if endpoint != 'UNKNOWN':
            aliases[name] = endpoint.rstrip('/')
    return aliases


def _resolve_endpoint_raw(raw: str, aliases: dict[str, str]) -> tuple[str, list[str]]:
    value = raw
    for name, endpoint in aliases.items():
        value = value.replace(f'${{this.{name}}}', endpoint)
        value = value.replace(f'${{{name}}}', endpoint)
        value = value.replace(f'{{this.{name}}}', endpoint)
        value = value.replace(f'{{{name}}}', endpoint)
    return _normalize_endpoint(value)


def _resolve_endpoint_identifier(expr: str, aliases: dict[str, str]) -> tuple[str, list[str]] | None:
    ident = expr.strip()
    m = re.match(r'(?:this\.)?([A-Za-z_][A-Za-z0-9_]*)\b', ident)
    if not m:
        return None
    endpoint = aliases.get(m.group(1))
    if not endpoint:
        return None
    return endpoint, []


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
    url_param_vars = set(re.findall(r'(?:const|let|var)\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*new\s+URLSearchParams\b', snippet))
    for up in re.finditer(r'([A-Za-z_][A-Za-z0-9_]*)\.(?:append|set)\(\s*["\']([^"\']+)', snippet):
        if up.group(1) in url_param_vars:
            params.add(up.group(2))
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


def _extract_payload_keys_nearby(lines: list[str], call_idx: int, var_name: str) -> list[str]:
    start = max(0, call_idx - 40)
    window = "\n".join(lines[start:call_idx + 1])
    m = re.search(rf'(?:const|let|var)\s+{re.escape(var_name)}\s*=\s*\{{([^}}]+)\}}', window, re.DOTALL)
    if not m:
        return []
    return sorted(set(k.group(1) for k in re.finditer(r'([A-Za-z_][A-Za-z0-9_]*)\s*(?::|,|$)', m.group(1))))


def _detect_payload_style(snip: str, method: str, lines: list[str], call_idx: int) -> str:
    """Return json, formdata, urlencoded, unknown, or none for GET."""
    if method.upper() == 'GET':
        return 'none'
    near_start = max(0, call_idx - 20)
    near = '\n'.join(lines[near_start:call_idx + 1])
    blob = near + '\n' + snip

    formdata_vars = set(re.findall(r'(?:const|let|var)\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*new\s+FormData\b', blob))
    url_vars = set(re.findall(r'(?:const|let|var)\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*new\s+URLSearchParams\b', blob))

    used_vars = set()
    for m in re.finditer(r'\(\s*["\'`][^"\'`]+["\'`]\s*,\s*([A-Za-z_][A-Za-z0-9_]*)\b', snip, re.DOTALL):
        used_vars.add(m.group(1))
    for m in re.finditer(r'\b(?:data|body)\s*:\s*([A-Za-z_][A-Za-z0-9_]*)\b', snip):
        used_vars.add(m.group(1))
    for var in formdata_vars | url_vars:
        if re.search(rf'[\{{,]\s*{re.escape(var)}\s*[\}},]', snip):
            used_vars.add(var)

    if used_vars & url_vars:
        return 'urlencoded'
    if used_vars & formdata_vars:
        return 'formdata'

    if 'new URLSearchParams' in snip or any(re.search(rf'\b{re.escape(var)}\.(?:append|set)\s*\(', snip) for var in url_vars):
        return 'urlencoded'
    if re.search(r'Content-Type[\'"]?\s*:\s*[\'"]application/x-www-form-urlencoded', blob, re.IGNORECASE):
        return 'urlencoded'

    if 'new FormData' in snip or any(re.search(rf'\b{re.escape(var)}\.append\s*\(', snip) for var in formdata_vars):
        return 'formdata'

    if 'JSON.stringify' in blob or re.search(r'Content-Type[\'"]?\s*:\s*[\'"]application/json', blob, re.IGNORECASE):
        return 'json'
    if re.search(r'\(\s*["\'`][^"\'`]+["\'`]\s*,\s*\{', snip, re.DOTALL):
        return 'json'
    if re.search(r',\s*\{', snip):
        return 'json'
    if re.search(r'\b(?:data|body)\s*:\s*\{', snip, re.DOTALL):
        return 'json'
    return 'unknown'


def _extract_concat_endpoint(snip: str) -> tuple[str, list[str]] | None:
    m = re.search(r'\(\s*[A-Za-z_][A-Za-z0-9_]*\s*\+\s*(["\'`])(.+?)\1', snip)
    if not m:
        return None
    return _normalize_endpoint(m.group(2))


def extract_api_call_candidates(files: list[FileContent]) -> CandidateExtractionResult:
    candidates: list[ApiCallCandidate] = []
    patterns = [
        (r'(axios\.create\s*\([^)]*\))\.(get|post|put|delete|patch)\(', 'axios.create.{method}'),
        (r'(axios)\.(get|post|put|delete|patch)\(', 'axios.{method}'),
        (r'(this\.http|http|httpClient|api|apiClient|request|client)\.(get|post|put|delete|patch)\(', '{sink}.{method}'),
        (r'(fetch)\(', 'fetch'),
        (r'(\$\.ajax|jQuery\.ajax)\(', '$.ajax'),
        (r'(apiClient)\.request\(', 'apiClient.request'),
        (r'\b(request)\(', 'request'),
    ]

    for file in files:
        lines = file.content.splitlines() or ['']
        aliases = _endpoint_aliases(lines)
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
                        endpoint, epnotes = _resolve_endpoint_raw(epm.group(2), aliases)
                        notes.extend(epnotes)
                    elif _extract_concat_endpoint(tail):
                        endpoint, epnotes = _extract_concat_endpoint(tail)  # type: ignore
                        notes.extend(epnotes)
                    else:
                        arg = re.search(r'\(\s*([^,\)\n]+)', tail, re.DOTALL)
                        resolved = _resolve_endpoint_identifier(arg.group(1), aliases) if arg else None
                        if resolved:
                            endpoint, epnotes = resolved
                            notes.extend(epnotes)
                        elif 'url:' in snip:
                            um = re.search(r'url\s*:\s*(["\'`])(.+?)\1', snip)
                            if um:
                                endpoint, epnotes = _resolve_endpoint_raw(um.group(2), aliases)
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
                        um2 = re.search(r'url\s*:\s*(["\'`])(.+?)\1', snip, re.DOTALL)
                        if um2:
                            endpoint, epnotes2 = _resolve_endpoint_raw(um2.group(2), aliases)
                            notes.extend(epnotes2)
                        if re.search(r'url\s*:\s*([A-Za-z_][A-Za-z0-9_]*)\b', snip) and endpoint == 'UNKNOWN':
                            notes.append('generic ajax wrapper requires callsite tracing')
                    if sink == 'apiClient.request' or sink == 'request':
                        method, endpoint = _extract_object_style_request(snip, sink)
                        if endpoint == 'UNKNOWN':
                            notes.append('endpoint variable requires manual review')

                    params, pnotes = _extract_parameters(snip, method)
                    payload_style = _detect_payload_style(snip, method, lines, i)
                    response_vars = set()
                    for rm in re.finditer(r'const\s+\{\s*data\s*:\s*([A-Za-z_][A-Za-z0-9_]*)\s*\}\s*=\s*await\s+(?:axios|fetch|\$\.ajax|jQuery\.ajax)', snip):
                        response_vars.add(rm.group(1).lower())
                    for rm in re.finditer(r'const\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*await\s+(?:axios|fetch|\$\.ajax|jQuery\.ajax)', snip):
                        response_vars.add(rm.group(1).lower())
                    for key in ('data', 'body', 'params'):
                        pv = re.search(rf'{key}\s*:\s*([A-Za-z_][A-Za-z0-9_]*)', snip)
                        if pv and method != 'GET' and pv.group(1).lower() not in {'undefined', 'null', 'expr', 'json', 'object', 'array', 'formdata', 'promise', 'math', 'date'}:
                            if payload_style not in {'formdata', 'urlencoded'}:
                                params.append(pv.group(1))
                                notes.append('payload object requires manual review')
                            params.extend(_extract_payload_keys_nearby(lines, i, pv.group(1)))
                    if method != 'GET':
                        payload_pos = re.search(r'\(\s*([\'"`]).+?\1\s*,\s*([A-Za-z_][A-Za-z0-9_]*)\s*(?:,|\))', tail, re.DOTALL)
                        if payload_pos:
                            payload_var = payload_pos.group(2)
                            if payload_var.lower() not in {'undefined', 'null', 'expr'}:
                                params.append(payload_var)
                                params.extend(_extract_payload_keys_nearby(lines, i, payload_var))
                                notes.append('payload object requires manual review')
                    if method != 'GET':
                        near_start = max(0, i - 10)
                        near = '\n'.join(lines[near_start:i + 1])
                        for mfd in re.finditer(r'(?:FormData|[A-Za-z_][A-Za-z0-9_]*)\.append\(\s*["\']([^"\']+)', near):
                            params.append(mfd.group(1))
                        url_param_vars = set(re.findall(r'(?:const|let|var)\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*new\s+URLSearchParams\b', near))
                        for up in re.finditer(r'([A-Za-z_][A-Za-z0-9_]*)\.(?:append|set)\(\s*["\']([^"\']+)', near):
                            if up.group(1) in url_param_vars:
                                params.append(up.group(2))
                    if method == 'GET':
                        near_start = max(0, i - 10)
                        near = '\n'.join(lines[near_start:i + 1])
                        url_param_vars = set(re.findall(r'(?:const|let|var)\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*new\s+URLSearchParams\b', near))
                        for up in re.finditer(r'([A-Za-z_][A-Za-z0-9_]*)\.(?:append|set)\(\s*["\']([^"\']+)', near):
                            if up.group(1) in url_param_vars:
                                params.append(up.group(2))
                    params = sorted({p for p in params if p.lower() not in {'expr', 'sessiondata'} and p.lower() not in response_vars})
                    notes.extend(pnotes)
                    if method == 'UNKNOWN':
                        notes.append('method could not be determined')
                    if endpoint != 'UNKNOWN':
                        notes = [n for n in notes if n != 'endpoint variable requires manual review']
                    confidence = 'high' if endpoint != 'UNKNOWN' and method != 'UNKNOWN' and params else ('medium' if endpoint != 'UNKNOWN' and method != 'UNKNOWN' else 'low')
                    candidates.append(ApiCallCandidate(source_path=file.path, method=method, endpoint=endpoint, parameters=params, payload_style=payload_style, start_line=start_line, end_line=end_line, snippet=snip, sink=sink, confidence=confidence, notes=sorted(set(notes))))
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

        for m in re.finditer(r'<form\b([^>]*)>(.*?)</form>', file.content, re.IGNORECASE | re.DOTALL):
            attrs, body = m.group(1), m.group(2)
            action_m = re.search(r'\baction\s*=\s*["\']([^"\']+)["\']', attrs, re.IGNORECASE)
            if not action_m:
                continue
            method_m = re.search(r'\bmethod\s*=\s*["\']([^"\']+)["\']', attrs, re.IGNORECASE)
            method = method_m.group(1).upper() if method_m else 'GET'
            endpoint, epnotes = _normalize_endpoint(action_m.group(1))
            start_line = file.content.count('\n', 0, m.start()) + 1
            end_line = file.content.count('\n', 0, m.end()) + 1
            params = sorted(set(re.findall(r'\bname\s*=\s*["\']([^"\']+)["\']', body, flags=re.IGNORECASE)))
            notes = ['html form action submission', 'server-side authorization cannot be confirmed from frontend source only']
            notes.extend(epnotes)
            candidates.append(ApiCallCandidate(
                source_path=file.path,
                method=method,
                endpoint=endpoint,
                parameters=params[:20],
                payload_style=('none' if method == 'GET' else 'urlencoded'),
                start_line=start_line,
                end_line=end_line,
                snippet=file.content.splitlines()[start_line - 1].strip() if file.content.splitlines() else '',
                sink='html.form',
                confidence='high' if endpoint != 'UNKNOWN' else 'low',
                notes=sorted(set(notes)),
            ))

    return CandidateExtractionResult(total_candidates=len(candidates), candidates=candidates)


def extract_ui_handler_candidates(files: list[FileContent]) -> list[dict]:
    out: list[dict] = []
    react_ev_re = re.compile(r'on(Click|Submit|Change)\s*=\s*\{\s*([A-Za-z_][A-Za-z0-9_]*)\s*\}')
    vue_ev_re = re.compile(r'@(?:click|submit(?:\.prevent)?)\s*=\s*"([A-Za-z_][A-Za-z0-9_]*)"|v-on:(?:click|submit(?:\.prevent)?)\s*=\s*"([A-Za-z_][A-Za-z0-9_]*)"')
    dis_re = re.compile(r'(?:disabled\s*=\s*\{([^}]+)\}|:disabled\s*=\s*"([^"]+)")')
    html_onclick_re = re.compile(r'onclick\s*=\s*"([A-Za-z_][A-Za-z0-9_]*)\(')
    jq_on_re = re.compile(r'(\$\([^)]+\)|[\'"][#.][^\'"]+[\'"])?\s*\.on\(\s*[\'"](click|submit|change)[\'"]\s*,\s*([A-Za-z_][A-Za-z0-9_]*)')
    jq_on_inline_re = re.compile(r'(\$\([^)]+\)|[\'"][#.][^\'"]+[\'"])?\s*\.on\(\s*[\'"](click|submit|change)[\'"]\s*,\s*function\s*\(')
    jq_click_re = re.compile(r'(\$\([^)]+\)|[\'"][#.][^\'"]+[\'"])?\s*\.click\(\s*([A-Za-z_][A-Za-z0-9_]*)')
    jq_submit_re = re.compile(r'(\$\([^)]+\)|[\'"][#.][^\'"]+[\'"])?\s*\.submit\(\s*([A-Za-z_][A-Za-z0-9_]*)')
    add_ev_re = re.compile(r'addEventListener\(\s*[\'"](click|submit|change)[\'"]\s*,\s*([A-Za-z_][A-Za-z0-9_]*)')
    btn_text_re = re.compile(r'<button[^>]*>([^<]{1,80})</button>|<(?:input)[^>]*value="([^"]{1,80})"', re.IGNORECASE)
    title_re = re.compile(r'<h[1-3][^>]*>([^<]{1,120})</h[1-3]>', re.IGNORECASE)
    fn_hint = re.compile(r'\b((?:handle|submit|process|do|pay|checkout|place|verify|confirm|validate|reset|change|send|request)[A-Za-z0-9_]*)\b')
    def selector_text(all_lines: list[str], selector_expr: str | None) -> str | None:
        if not selector_expr:
            return None
        m = re.search(r'[\'"]([#.][^\'"]+)[\'"]', selector_expr)
        if not m:
            return None
        sel = m.group(1)
        if sel.startswith('#'):
            attr, val = 'id', re.escape(sel[1:])
        elif sel.startswith('.'):
            attr, val = 'class', re.escape(sel[1:])
        else:
            return None
        blob = '\n'.join(all_lines)
        pat = re.compile(
            rf'<(?:button|a)[^>]*\b{attr}\s*=\s*["\'][^"\']*\b{val}\b[^"\']*["\'][^>]*>\s*([^<]{{1,120}})\s*</(?:button|a)>'
            rf'|<(?:input)[^>]*\b{attr}\s*=\s*["\'][^"\']*\b{val}\b[^"\']*["\'][^>]*\bvalue="([^"]{{1,120}})"',
            re.IGNORECASE | re.DOTALL,
        )
        mm = pat.search(blob)
        if mm:
            return (mm.group(1) or mm.group(2) or '').strip() or None
        return None
    def nearby_button_text(all_lines: list[str], idx0: int) -> str | None:
        s = max(0, idx0 - 5)
        e = min(len(all_lines) - 1, idx0 + 5)
        buf = '\n'.join(all_lines[s:e + 1])
        m = re.search(r'<button[^>]*>\s*([^<]{1,80})\s*</button>', buf, re.IGNORECASE | re.DOTALL)
        if m:
            return m.group(1).strip()
        return None
    for file in files:
        lines = file.content.splitlines() or ['']
        for i, line in enumerate(lines, start=1):
            title_m = title_re.search(line)
            title_text = title_m.group(1).strip() if title_m else None
            tm_line = btn_text_re.search(line)
            line_text = ((tm_line.group(1) or tm_line.group(2)).strip() if tm_line else None)
            for m in react_ev_re.finditer(line):
                et = line_text or nearby_button_text(lines, i - 1)
                out.append({
                    'handler_name': m.group(2),
                    'ui_event': f"on{m.group(1)}",
                    'disabled_expression': None,
                    'element_text': et,
                    'nearby_title': title_text,
                    'source_path': file.path,
                    'start_line': i,
                    'end_line': i,
                    'snippet': line.strip(),
                })
            for m in vue_ev_re.finditer(line):
                handler = m.group(1) or m.group(2)
                if handler:
                    et = line_text or nearby_button_text(lines, i - 1)
                    out.append({
                        'handler_name': handler,
                        'ui_event': 'onClick',
                        'disabled_expression': None,
                        'element_text': et,
                        'nearby_title': title_text,
                        'source_path': file.path,
                        'start_line': i,
                        'end_line': i,
                        'snippet': line.strip(),
                    })
            hm = html_onclick_re.search(line)
            if hm:
                et = line_text or nearby_button_text(lines, i - 1)
                out.append({
                    'handler_name': hm.group(1),
                    'ui_event': 'onClick',
                    'disabled_expression': None,
                    'element_text': et,
                    'nearby_title': title_text,
                    'source_path': file.path,
                    'start_line': i,
                    'end_line': i,
                    'snippet': line.strip(),
                })
            m = jq_on_re.search(line)
            if m:
                selector = m.group(1)
                et = line_text or selector_text(lines, selector) or nearby_button_text(lines, i - 1)
                out.append({
                    'handler_name': m.group(3),
                    'ui_event': f"on{m.group(2).capitalize()}",
                    'disabled_expression': None,
                    'element_text': et,
                    'selector': selector,
                    'nearby_title': title_text,
                    'source_path': file.path,
                    'start_line': i,
                    'end_line': i,
                    'snippet': line.strip(),
                })
            m_inline = jq_on_inline_re.search(line)
            if m_inline:
                selector = m_inline.group(1)
                et = line_text or selector_text(lines, selector) or nearby_button_text(lines, i - 1)
                out.append({
                    'handler_name': None,
                    'ui_event': f"on{m_inline.group(2).capitalize()}",
                    'disabled_expression': None,
                    'element_text': et,
                    'selector': selector,
                    'nearby_title': title_text,
                    'source_path': file.path,
                    'start_line': i,
                    'end_line': i,
                    'snippet': line.strip(),
                })
            for rg, evt in ((jq_click_re, 'Click'), (jq_submit_re, 'Submit')):
                m2 = rg.search(line)
                if m2:
                    selector = m2.group(1)
                    et = line_text or selector_text(lines, selector) or nearby_button_text(lines, i - 1)
                    out.append({
                        'handler_name': m2.group(2),
                        'ui_event': f"on{evt}",
                        'disabled_expression': None,
                        'element_text': et,
                        'selector': selector,
                        'nearby_title': title_text,
                        'source_path': file.path,
                        'start_line': i,
                        'end_line': i,
                        'snippet': line.strip(),
                    })
            m = add_ev_re.search(line)
            if m:
                out.append({
                    'handler_name': m.group(2),
                    'ui_event': f"on{m.group(1).capitalize()}",
                    'disabled_expression': None,
                    'element_text': line_text or nearby_button_text(lines, i - 1),
                    'nearby_title': title_text,
                    'source_path': file.path,
                    'start_line': i,
                    'end_line': i,
                    'snippet': line.strip(),
                })
            dm = dis_re.search(line)
            if dm:
                out.append({
                    'handler_name': None,
                    'ui_event': 'disabled',
                    'disabled_expression': (dm.group(1) or dm.group(2) or '').strip(),
                    'element_text': None,
                    'nearby_title': title_text,
                    'source_path': file.path,
                    'start_line': i,
                    'end_line': i,
                    'snippet': line.strip(),
                })
            tm = btn_text_re.search(line)
            if tm:
                txt = (tm.group(1) or tm.group(2) or '').strip()
                if txt:
                    out.append({
                        'handler_name': None,
                        'ui_event': 'element_text',
                        'disabled_expression': None,
                        'element_text': txt,
                        'nearby_title': title_text,
                        'source_path': file.path,
                        'start_line': i,
                        'end_line': i,
                        'snippet': line.strip(),
                    })
            fm = fn_hint.search(line)
            if fm:
                out.append({
                    'handler_name': fm.group(1),
                    'ui_event': 'function_hint',
                    'disabled_expression': None,
                    'element_text': None,
                    'nearby_title': title_text,
                    'source_path': file.path,
                    'start_line': i,
                    'end_line': i,
                    'snippet': line.strip(),
                })
    return out
