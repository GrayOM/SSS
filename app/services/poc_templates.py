"""
poc_templates.py -- short, typed, self-contained PoC builders.

Each builder returns pure JavaScript that can be pasted directly into a
browser DevTools Console without any prior setup (no common_console_helper
required).

All output is ASCII-only and passes _is_allowed_guarded_poc_code().
Destructive or unresolvable inputs return None; callers must fall back to the
interceptor-based discovery aid.
"""

import json
import re

MAX_POC_LINES = 12

# Signatures that mark a global hook installer -- must never appear in output.
INTERCEPTOR_SIGS: tuple[str, ...] = (
    'window.fetch = async function',
    'XMLHttpRequest.prototype.open',
    'axios.interceptors.request.use',
    'SSS_REVIEW_POC_STATE',
    'TARGET_ENDPOINT =',
)

_DESTRUCTIVE_KEYWORDS = (
    'delete', 'remove', 'transfer', 'withdraw', 'refund', 'bulk',
    'cancel-all', 'admin/delete',
)

_BASE_URL_NAMES = ('API_BASE_URL', 'API_BASE', 'BASE_URL', 'apiBase')
_BASE_URL_EXPR_RE = re.compile(
    r'^(?:'
    r'\$\{\s*(?:API_BASE_URL|API_BASE|BASE_URL|apiBase)\s*\}'
    r'|\{\s*(?:API_BASE_URL|API_BASE|BASE_URL|apiBase)\s*\}'
    r'|(?:API_BASE_URL|API_BASE|BASE_URL|apiBase)'
    r')',
    re.IGNORECASE,
)

# Path-param replacement map: (regex, js-const-name, placeholder-label)
_PATH_PARAM_SUBS: list[tuple[re.Pattern, str, str]] = [
    (re.compile(r'\{item\.id\}', re.I),              'ITEM_ID',    'REPLACE_WITH_ITEM_ID'),
    (re.compile(r'\{itemId\}', re.I),                 'ITEM_ID',    'REPLACE_WITH_ITEM_ID'),
    (re.compile(r'\{productId\}', re.I),              'PRODUCT_ID', 'REPLACE_WITH_PRODUCT_ID'),
    (re.compile(r'\{userId|currentUserId|memberId|accountId\}', re.I), 'USER_ID', 'REPLACE_WITH_USER_ID'),
    (re.compile(r'\{orderId|orderNo\}', re.I),        'ORDER_ID',   'REPLACE_WITH_ORDER_ID'),
    (re.compile(r'\{auctionItem\.orderId\}', re.I),   'ORDER_ID',   'REPLACE_WITH_ORDER_ID'),
    (re.compile(r'\{paymentId\}', re.I),              'PAYMENT_ID', 'REPLACE_WITH_PAYMENT_ID'),
    (re.compile(r'\{sessionData\.userId\}', re.I),    'USER_ID',    'REPLACE_WITH_USER_ID'),
    (re.compile(r'\{[^}]+\}'),                         'PARAM',      'REPLACE_WITH_PARAM'),
]


def normalize_endpoint(endpoint: str) -> str:
    """Strip a leading base-URL variable, leaving only the path portion.

    Examples:
      '{API_BASE_URL}/login'      -> '/login'
      "API_BASE_URL + '/login'"   -> '/login'
      '/api/order/{orderId}/pay'  -> '/api/order/{orderId}/pay'  (path params kept)
    """
    path = endpoint.strip()
    path = path.strip("'\"` ")
    path = _BASE_URL_EXPR_RE.sub('', path).strip()
    path = re.sub(r'^\s*\+\s*', '', path).strip()
    path = path.strip("'\"` ")
    if path and not path.startswith('/'):
        path = '/' + path
    return path if path else endpoint


def _is_safe_endpoint(endpoint: str) -> bool:
    """False for UNKNOWN, truly unresolvable, or destructive endpoints.

    Base-URL prefixes are stripped first; remaining path params {x} are
    allowed -- the PoC builder will substitute REPLACE_WITH_* constants.
    """
    if not endpoint or endpoint == 'UNKNOWN':
        return False
    norm = normalize_endpoint(endpoint)
    if not norm or norm == 'UNKNOWN':
        return False
    # After normalization must start with '/' or be a plain path
    if not norm.startswith('/'):
        return False
    low = norm.lower()
    if any(token in low for token in ('unknown_path', '{unknown}', '/unknown')):
        return False
    return not any(k in low for k in _DESTRUCTIVE_KEYWORDS)


def build_dom_xss_poc(source_expr: str = 'location.hash', sink_expr: str = 'innerHTML') -> str:
    """
    1-2 line PoC for DOM XSS.

    Injects a non-destructive test payload into the identified source so that
    the sink receives it on the next page load.  Always returns a string.
    """
    src = source_expr.lower()
    if 'postmessage' in src or 'event.data' in src:
        return "window.postMessage('<img src=x onerror=console.log(1)>', '*');"
    if 'search' in src or 'location.search' in src:
        return (
            "history.replaceState(null, '', location.pathname + "
            "'?x=<img src=x onerror=console.log(1)>'); location.reload();"
        )
    # Default: hash-based (most common DOM XSS source)
    return "location.hash = '<img src=x onerror=console.log(1)>'; location.reload();"


def build_storage_auth_poc(
    storage: str = 'sessionStorage',
    key: str = 'user',
    field: str = 'userType',
    value: str = 'ADMIN',
) -> str:
    """
    1-line storage manipulation + reload.

    Writes a test auth value and reloads so the app re-reads the modified
    value.  Always returns a string.
    """
    payload = json.dumps({field: value})
    key_js = json.dumps(key)
    return f"{storage}.setItem({key_js}, JSON.stringify({payload})); location.reload();"


def build_request_replay_poc(
    method: str,
    endpoint: str,
    field: str = '',
    test_value: 'str | int | None' = None,
    fields: 'list[str] | None' = None,
) -> 'str | None':
    """CONFIRM-guarded direct fetch replay, <= MAX_POC_LINES lines.

    Returns None when endpoint is destructive or truly UNKNOWN.
    Base-URL prefixes are stripped; path params become labeled REPLACE_WITH_*
    constants so the tester can fill them in before running.

    For GET: no CONFIRM guard (read-only).
    For POST/PUT/PATCH: browser confirm() guard gives the tester a clear
    one-paste approval prompt while remaining non-destructive by default.
    """
    if not _is_safe_endpoint(endpoint):
        return None
    m = method.upper()
    if m not in ('GET', 'POST', 'PUT', 'PATCH'):
        return None

    # Normalize: strip leading base-URL variable
    norm = normalize_endpoint(endpoint)

    # Replace path params {x} with REPLACE_WITH_* JS constants -- single pass.
    # We find each {token} once, pick the right constant name, then substitute all
    # at once so already-inserted ${CONST} strings are never re-scanned.
    const_decls: list[str] = []
    used: set[str] = set()
    url_template = norm

    def _const_for(token: str) -> str:
        tl = token.lower()
        if any(k in tl for k in ('item.id', 'itemid', 'productid', 'id')):
            return 'TEST_ID'
        if any(k in tl for k in ('userid', 'currentuserid', 'memberid', 'accountid', 'sessiondata.userid')):
            return 'USER_ID'
        if any(k in tl for k in ('orderid', 'orderno', 'auctionitem.orderid')):
            return 'ORDER_ID'
        if 'paymentid' in tl:
            return 'PAYMENT_ID'
        return tl.upper().replace('.', '_').replace('-', '_') or 'PARAM'

    def _replacer(m: re.Match) -> str:
        inner = m.group(1)
        const_name = _const_for(inner)
        label = f'REPLACE_WITH_{const_name}'
        if const_name not in used:
            const_decls.append(f'  const {const_name} = "{label}";')
            used.add(const_name)
        return f'${{{const_name}}}'

    url_template = re.sub(r'\{([^}]+)\}', _replacer, norm)

    # Build the URL expression
    if const_decls:
        url_expr = f'`{url_template}`'   # template literal
    else:
        url_expr = json.dumps(norm)       # plain string

    if m == 'GET':
        lines = ['(async () => {'] + const_decls + [
            f'  const r = await fetch({url_expr});',
            "  console.log('[SSS PoC]', r.status, await r.text().catch(() => ''));",
            '})();',
        ]
        return '\n'.join(lines)

    # Mutation request -- browser confirmation guard required.
    body_fields = list(fields or [])
    if field and field not in body_fields:
        body_fields.insert(0, field)

    const_decls.extend(_body_const_decls(body_fields, used))
    body_js = _body_json_expr(body_fields, field, test_value)

    lines = (
        ['(async () => {',
         f'  if (!confirm("[SSS PoC] Run approved {m} {norm}?")) return;']
        + const_decls
        + [f'  const r = await fetch({url_expr}, {{',
           f'    method: {json.dumps(m)}, credentials: "include",',
           "    headers: { 'Content-Type': 'application/json' },",
           f'    body: {body_js},',
           '  });',
           "  console.log('[SSS PoC]', r.status, r.headers.get('content-type'), (await r.text()).slice(0, 500));",
           '})();']
    )
    return '\n'.join(lines)


def _body_const_decls(fields: list[str], used: set[str]) -> list[str]:
    decls: list[str] = []
    for name in fields:
        const_name = _body_const_name(name)
        if not const_name or const_name in used:
            continue
        label = f'REPLACE_WITH_{const_name}'
        decls.append(f'  const {const_name} = "{label}";')
        used.add(const_name)
    return decls


def _body_json_expr(fields: list[str], field: str, test_value: 'str | int | None') -> str:
    safe_fields = [f for f in fields if _safe_body_key(f)]
    if not safe_fields and field and test_value is not None:
        safe_fields = [field]
    if not safe_fields:
        return 'JSON.stringify({})'
    parts: list[str] = []
    for name in safe_fields[:8]:
        key_js = json.dumps(name)
        const_name = _body_const_name(name)
        if const_name:
            value_js = const_name
        elif name.lower() in {'amount', 'price', 'totalamount', 'usepoints', 'quantity', 'qty', 'count', 'a', 'b'}:
            value_js = '1'
        elif name == field and test_value is not None:
            value_js = json.dumps(test_value)
        else:
            value_js = json.dumps('TEST_VALUE')
        parts.append(f'{key_js}: {value_js}')
    return 'JSON.stringify({ ' + ', '.join(parts) + ' })'


def _safe_body_key(name: str) -> bool:
    if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,60}', name or ''):
        return False
    low = name.lower()
    return low not in {'method', 'url', 'headers', 'credentials', 'withcredentials', 'body', 'data', 'payload', 'options', 'config'}


def _body_const_name(name: str) -> str | None:
    low = name.lower()
    if 'order' in low and 'id' in low:
        return 'TEST_ORDER_ID'
    if 'product' in low and 'id' in low:
        return 'TEST_PRODUCT_ID'
    if 'user' in low and 'id' in low:
        return 'TEST_USER_ID'
    if 'item' in low and 'id' in low:
        return 'TEST_ITEM_ID'
    if 'payment' in low and 'id' in low:
        return 'TEST_PAYMENT_ID'
    if 'token' in low:
        return 'TEST_TOKEN'
    if low in {'imp_uid', 'merchant_uid'}:
        return 'TEST_PAYMENT_UID'
    if low in {'code', 'authcode', 'verifycode', 'verificationcode'}:
        return 'TEST_CODE'
    return None


def is_interceptor_free(code: str) -> bool:
    """True when code contains none of the global-hook installer signatures."""
    return not any(sig in code for sig in INTERCEPTOR_SIGS)
