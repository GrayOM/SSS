"""
poc_templates.py -- short, typed, self-contained PoC builders.

Each builder returns pure JavaScript that can be pasted directly into a
browser DevTools Console without any prior setup (no common_console_helper
required).

All output is ASCII-only and passes _is_allowed_guarded_poc_code().
Destructive or unresolvable inputs return None; callers must fall back to
manual review or clearly separated runtime discovery.
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
    'window.SSS_POC.find(',
    'window.SSS_POC.replay(',
    'window.SSS_POC.list(',
    'window.SSS_POC.armMutation(',
)

_DESTRUCTIVE_KEYWORDS = (
    'delete', 'remove', 'transfer', 'withdraw', 'refund', 'bulk',
    'cancel-all', 'admin/delete',
)

_BASE_URL_NAMES = ('API_BASE_URL', 'API_BASE', 'BASE_URL', 'apiBase')
# Matches known base-URL variable prefixes and any brace-enclosed token
# whose name ends in _URL, _BASE, _BASEURL or _BASE_URL (e.g. {API_URL},
# {REACT_APP_API_URL}).  The prefix is stripped so that only the path
# portion of the endpoint is returned by normalize_endpoint().
_BASE_URL_EXPR_RE = re.compile(
    r'^(?:'
    r'\$\{\s*(?:[A-Za-z_][A-Za-z0-9_]*(?:_URL|_BASE|_BASEURL|_BASE_URL))\s*\}'
    r'|\{\s*(?:[A-Za-z_][A-Za-z0-9_]*(?:_URL|_BASE|_BASEURL|_BASE_URL))\s*\}'
    r'|\$\{\s*(?:API_BASE_URL|API_BASE|BASE_URL|apiBase)\s*\}'
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
    allowed -- the PoC builder will derive runtime values with
    REPLACE_WITH_* as a final fallback.
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
    payload_style: str = 'json',
) -> 'str | None':
    """CONFIRM-guarded direct fetch replay, <= MAX_POC_LINES lines.

    Returns None when endpoint is destructive or truly UNKNOWN.
    Base-URL prefixes are stripped; path params prefer runtime/page-derived
    values and keep REPLACE_WITH_* only as a final fallback.

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

    const_decls: list[str] = []
    used: set[str] = set()
    url_template = norm

    def _replacer(m: re.Match) -> str:
        inner = m.group(1)
        var_name = _declare_runtime_value(inner, const_decls, used)
        return f'${{{var_name}}}'

    url_template = re.sub(r'\{([^}]+)\}', _replacer, norm)

    # Build the URL expression
    if const_decls:
        url_expr = f'`{url_template}`'   # template literal
    else:
        url_expr = json.dumps(norm)       # plain string

    if m == 'GET':
        lines = ['(async () => {'] + const_decls + [
            f'  const r = await fetch({url_expr}, {{ credentials: "include" }});',
            "  console.log('[SSS PoC]', r.status, r.headers.get('content-type'), (await r.text()).slice(0, 500));",
            '})();',
        ]
        return '\n'.join(lines)

    # Mutation request -- browser confirmation guard required.
    body_fields = list(fields or [])
    if field and field not in body_fields:
        body_fields.insert(0, field)

    for body_field in body_fields:
        if _runtime_var_name(body_field):
            _declare_runtime_value(body_field, const_decls, used)
    style = (payload_style or 'json').lower()
    if style not in {'json', 'formdata', 'urlencoded'}:
        if not body_fields:
            return None
        style = 'json'

    # Const declarations come first so the confirm dialog can use a backtick
    # template literal that shows the resolved URL (e.g. ${itemId}) rather
    # than the raw source placeholder ({item.id}).  A tester can rely on
    # runtime/page-derived values or fill the fallback before pasting.
    lines = ['(async () => {'] + const_decls
    if style == 'formdata':
        lines.extend(_formdata_lines(body_fields, field, test_value))
        body_expr = 'fd'
        header_expr: str | None = None
    elif style == 'urlencoded':
        lines.extend(_urlencoded_lines(body_fields, field, test_value))
        body_expr = 'body.toString()'
        header_expr = "headers: { 'Content-Type': 'application/x-www-form-urlencoded' }"
    else:
        body_expr = _body_json_expr(body_fields, field, test_value)
        header_expr = "headers: { 'Content-Type': 'application/json' }"
    option_parts = [f'method: {json.dumps(m)}', 'credentials: "include"']
    if header_expr:
        option_parts.append(header_expr)
    option_parts.append(f'body: {body_expr}')
    options = '{ ' + ', '.join(option_parts) + ' }'
    if used:
        guard_vars = ', '.join(sorted(used))
        lines.append(f'  if ([{guard_vars}].some(v => String(v).startsWith("REPLACE_WITH_"))) {{ console.warn("[SSS PoC] Fill required runtime values before sending."); return; }}')
    lines.extend([
        f'  if (!confirm(`[SSS PoC] Run approved {m} {url_template}?`)) return;',
        f'  const r = await fetch({url_expr}, {options});',
        "  console.log('[SSS PoC]', r.status, r.headers.get('content-type'), (await r.text()).slice(0, 500));",
        '})();',
    ])
    return '\n'.join(lines)


def _declare_runtime_value(name: str, decls: list[str], used: set[str]) -> str:
    var_name = _runtime_var_name(name) or 'testValue'
    if var_name not in used:
        decls.append(f'  const {var_name} = {_runtime_value_expr(name)};')
        used.add(var_name)
    return var_name


def _body_json_expr(fields: list[str], field: str, test_value: 'str | int | None') -> str:
    safe_fields = [f for f in fields if _safe_body_key(f)]
    if not safe_fields and field and test_value is not None:
        safe_fields = [field]
    if not safe_fields:
        return 'JSON.stringify({})'
    parts: list[str] = []
    for name in safe_fields[:8]:
        key_js = json.dumps(name)
        var_name = _runtime_var_name(name)
        if var_name:
            value_js = var_name
        elif name.lower() in {'amount', 'price', 'totalamount', 'usepoints', 'quantity', 'qty', 'count', 'a', 'b'}:
            value_js = '1'
        elif name == field and test_value is not None:
            value_js = json.dumps(test_value)
        else:
            value_js = json.dumps('TEST_VALUE')
        parts.append(f'{key_js}: {value_js}')
    return 'JSON.stringify({ ' + ', '.join(parts) + ' })'


def _body_value_expr(name: str, field: str, test_value: 'str | int | None') -> str:
    var_name = _runtime_var_name(name)
    if var_name:
        return var_name
    low = name.lower()
    if low in {'amount', 'price', 'totalamount', 'usepoints', 'quantity', 'qty', 'count', 'a', 'b'}:
        return '1'
    if name == field and test_value is not None:
        return json.dumps(test_value)
    return json.dumps('TEST_VALUE')


def _formdata_lines(fields: list[str], field: str, test_value: 'str | int | None') -> list[str]:
    safe_fields = [f for f in fields if _safe_body_key(f)]
    if not safe_fields and field and test_value is not None:
        safe_fields = [field]
    lines = ['  const fd = new FormData();']
    for name in safe_fields[:6]:
        lines.append(f'  fd.append({json.dumps(name)}, {_body_value_expr(name, field, test_value)});')
    return lines


def _urlencoded_lines(fields: list[str], field: str, test_value: 'str | int | None') -> list[str]:
    safe_fields = [f for f in fields if _safe_body_key(f)]
    if not safe_fields and field and test_value is not None:
        safe_fields = [field]
    lines = ['  const body = new URLSearchParams();']
    for name in safe_fields[:6]:
        lines.append(f'  body.set({json.dumps(name)}, {_body_value_expr(name, field, test_value)});')
    return lines


def _safe_body_key(name: str) -> bool:
    if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,60}', name or ''):
        return False
    low = name.lower()
    return low not in {'method', 'url', 'headers', 'credentials', 'withcredentials', 'body', 'data', 'payload', 'options', 'config'}


def _runtime_var_name(name: str) -> str | None:
    low = (name or '').lower().replace('.', '')
    if 'order' in low and 'id' in low:
        return 'orderId'
    if 'product' in low and 'id' in low:
        return 'productId'
    if any(token in low for token in ('memberid', 'accountid')):
        return 'userId'
    if 'user' in low and 'id' in low:
        return 'userId'
    if 'item' in low and 'id' in low:
        return 'itemId'
    if low in {'id', 'testid'}:
        return 'itemId'
    if 'payment' in low and 'id' in low:
        return 'paymentId'
    if 'transaction' in low and 'id' in low:
        return 'transactionId'
    if low in {'imp_uid', 'impuid'}:
        return 'impUid'
    if low in {'merchant_uid', 'merchantuid'}:
        return 'merchantUid'
    if low in {'email', 'emailaddress', 'useremail'}:
        return 'email'
    if low in {'phone', 'phonenumber', 'tel', 'mobile', 'mobilephone'}:
        return 'phone'
    if 'token' in low:
        return 'token'
    if low in {'code', 'authcode', 'verifycode', 'verificationcode'}:
        return 'code'
    return None


def _runtime_value_expr(name: str) -> str:
    var_name = _runtime_var_name(name) or 'value'
    placeholder = {
        'orderId': 'REPLACE_WITH_ORDER_ID',
        'productId': 'REPLACE_WITH_PRODUCT_ID',
        'userId': 'REPLACE_WITH_USER_ID',
        'itemId': 'REPLACE_WITH_ITEM_ID',
        'paymentId': 'REPLACE_WITH_PAYMENT_ID',
        'transactionId': 'REPLACE_WITH_TRANSACTION_ID',
        'impUid': 'REPLACE_WITH_IMP_UID',
        'merchantUid': 'REPLACE_WITH_MERCHANT_UID',
        'email': 'REPLACE_WITH_EMAIL',
        'phone': 'REPLACE_WITH_PHONE',
        'token': 'REPLACE_WITH_TOKEN',
        'code': 'REPLACE_WITH_CODE',
    }.get(var_name, 'REPLACE_WITH_VALUE')
    query_key = {
        'impUid': 'imp_uid',
        'merchantUid': 'merchant_uid',
    }.get(var_name, var_name)
    data_attr = re.sub(r'([A-Z])', r'-\1', var_name).lower()
    route_prefix = {
        'orderId': 'orders?',
        'productId': 'products?',
        'itemId': '(?:items?|auction)',
        'paymentId': 'payments?',
        'userId': 'users?',
    }.get(var_name, '[^/]+')
    if var_name in {'paymentId', 'transactionId', 'impUid', 'merchantUid'}:
        return (
            f'new URLSearchParams(location.search).get({json.dumps(query_key)}) || '
            f'document.querySelector("[data-{data_attr}]")?.dataset.{var_name} || '
            f'document.querySelector("[name=\'{query_key}\']")?.value || '
            f'window.__INITIAL_STATE__?.{var_name} || '
            f'{json.dumps(placeholder)}'
        )
    if var_name == 'userId':
        storage = '((s)=>s.userId||s.id)(JSON.parse(sessionStorage.getItem("user")||localStorage.getItem("user")||"{}"))'
        return (
            f'{storage} || new URLSearchParams(location.search).get("userId") || '
            'document.querySelector("[data-user-id]")?.dataset.userId || '
            'document.querySelector("[name=\'userId\']")?.value || '
            'window.__INITIAL_STATE__?.user?.id || '
            f'{json.dumps(placeholder)}'
        )
    if var_name == 'token':
        return (
            'new URLSearchParams(location.search).get("token") || '
            'document.querySelector("[name=\'token\']")?.value || '
            'sessionStorage.getItem("token") || localStorage.getItem("token") || '
            f'{json.dumps(placeholder)}'
        )
    if var_name == 'email':
        storage = '((s)=>s.email||s.userEmail)(JSON.parse(sessionStorage.getItem("user")||localStorage.getItem("user")||"{}"))'
        return (
            'new URLSearchParams(location.search).get("email") || '
            'document.querySelector("[name=\'email\']")?.value || '
            'document.querySelector("[type=\'email\']")?.value || '
            f'{storage} || window.__INITIAL_STATE__?.user?.email || '
            f'{json.dumps(placeholder)}'
        )
    if var_name == 'phone':
        storage = '((s)=>s.phone||s.phoneNumber||s.mobile)(JSON.parse(sessionStorage.getItem("user")||localStorage.getItem("user")||"{}"))'
        return (
            'new URLSearchParams(location.search).get("phone") || '
            'document.querySelector("[name=\'phone\']")?.value || '
            'document.querySelector("[name=\'phoneNumber\']")?.value || '
            'document.querySelector("[type=\'tel\']")?.value || '
            f'{storage} || window.__INITIAL_STATE__?.user?.phone || '
            f'{json.dumps(placeholder)}'
        )
    if var_name == 'code':
        return (
            'new URLSearchParams(location.search).get("code") || '
            'new URLSearchParams(location.search).get("verifyCode") || '
            'document.querySelector("[name=\'code\']")?.value || '
            'document.querySelector("[name=\'verifyCode\']")?.value || '
            'document.querySelector("[data-code]")?.dataset.code || '
            'window.__INITIAL_STATE__?.code || '
            f'{json.dumps(placeholder)}'
        )
    route_match = f'location.pathname.match(/(?:{route_prefix})\\/([^/?#]+)/)?.[1]'
    return (
        f'new URLSearchParams(location.search).get({json.dumps(query_key)}) || '
        f'{route_match} || '
        f'document.querySelector("[data-{data_attr}]")?.dataset.{var_name} || '
        f'document.querySelector("[name=\'{query_key}\']")?.value || '
        f'window.__INITIAL_STATE__?.{var_name} || '
        f'{json.dumps(placeholder)}'
    )


def is_interceptor_free(code: str) -> bool:
    """True when code contains none of the global-hook installer signatures."""
    return not any(sig in code for sig in INTERCEPTOR_SIGS)
