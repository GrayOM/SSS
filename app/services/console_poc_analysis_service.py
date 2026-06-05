import hashlib
import json
import re
from abc import ABC, abstractmethod

from app.core.config import settings
from app.models.schemas import AiAnalysisDebug, AnalysisDebugDropReason, ApiCallCandidate, BreakpointHint, BreakpointPlan, ConsoleSafePoc, ConsoleVerificationPlaybook, ConsoleVerificationPlaybookSummary, FileContent, FindingDataFlow, PocInjectionPlan, ProjectProfile, ReadableAnalysisResult, ReadableEvidence, ReadableFinding
from app.services.ai_clients import GeminiClient, GeminiClientProtocol
from app.services.api_candidate_extractor import extract_api_call_candidates, extract_ui_handler_candidates
from app.services.json_utils import extract_json_payload
from app.services.poc_templates import (
    MAX_POC_LINES, INTERCEPTOR_SIGS,
    build_dom_xss_poc, build_storage_auth_poc, build_request_replay_poc, is_interceptor_free,
    normalize_endpoint,
)
from app.services.prompt_builder import build_candidate_analysis_prompt, build_console_poc_analysis_prompt
from app.services.source_intelligence import build_project_understanding, _detect_api_clients, _detect_project_type, _is_vendor_or_minified

KEYWORDS = [
    'login', 'auth', 'session', 'token', 'jwt', 'cookie', 'localStorage', 'sessionStorage', 'userType', 'role',
    'admin', 'isAdmin', 'requireAuth', 'ProtectedRoute', 'PrivateRoute', 'navigate', 'withCredentials',
    'Authorization', 'innerHTML', 'outerHTML', 'insertAdjacentHTML', 'document.write', 'eval', 'Function',
    'location', 'document.URL', 'postMessage', 'input.value', 'price', 'amount', 'status', 'productId',
    'userId', 'payment', 'order', 'auction',
]
ALLOWED_SEVERITIES = {'low', 'medium', 'high', 'critical'}
ALLOWED_CONFIDENCES = {'low', 'medium', 'high'}
ALLOWED_POC_TYPES = {'browser_console', 'manual_check'}
DANGEROUS_POC_PATTERNS = (
    'delete', 'remove', 'transfer', 'withdraw', 'refund', 'bulk', 'axios.delete',
    'document.cookie=', 'child_process', 'eval(',
)
AUTH_SNIPPET_KEYS = ['requireAuth', 'checkSession', 'userInfo.userType', 'userType', 'role', 'isAdmin', 'ADMIN', 'navigate']
DOM_SNIPPET_KEYS = ['innerHTML', 'outerHTML', 'insertAdjacentHTML', 'document.write', 'location', 'document.URL', 'postMessage', 'input.value']
VALIDATION_SNIPPET_KEYS = ['axios.post', 'axios.put', 'fetch', 'FormData', 'amount', 'price', 'status', 'productId', 'userId', 'orderId', 'totalAmount', 'usePoints']
VALIDATION_PARAMETERS = ['amount', 'price', 'status', 'productId', 'userId', 'orderId', 'totalAmount', 'usePoints', 'paymentMethod', 'merchant_uid', 'imp_uid']
PROMOTION_SCORE_THRESHOLD = 5
MAX_PLAYBOOK_COUNT = 7
GENERIC_HINT_ACTION_KIND = 'generic_action_hint'
GENERIC_HINT_PAGE_KIND = 'generic_page_hint'
UNRESOLVED_POC_PLACEHOLDERS = (
    '{API_BASE_URL}',
    '{UNKNOWN_PATH}',
    '{userId}',
    '{sessionData.userId}',
    '{auctionItem.orderId}',
    'test_user_id',
    'test_order_id',
    'UNKNOWN',
)


_VULN_TYPE_TO_CATEGORY: dict[str, str] = {
    'DOM XSS': 'XSS',
    'Client-side Authorization Bypass': 'Admin/Role/Permission Bypass',
    'Client-side Validation Bypass': 'Business Logic Manipulation',
    'Payment/Point Manipulation Candidate': 'Payment/Price/Point/Coupon Manipulation',
    'IDOR / Unauthorized Data Access Candidate': 'IDOR/BOLA',
    'State/Status Manipulation Candidate': 'Business Logic Manipulation',
    'Account Recovery Flow Abuse Candidate': 'Account Recovery Weakness',
    'Identity Verification / Action Authorization Bypass Candidate': 'Authentication/Session Weakness',
    'Generic API Review Candidate': 'Business Logic Manipulation',
}

# Internal category codes used by playbook helper functions.
_INTERNAL_CATEGORY_MAP: dict[str, str] = {
    'DOM XSS': 'xss',
    'Client-side Authorization Bypass': 'authorization',
    'Client-side Validation Bypass': 'client_side_validation',
    'Payment/Point Manipulation Candidate': 'payment_or_value_mutation',
    'IDOR / Unauthorized Data Access Candidate': 'idor_bola',
    'State/Status Manipulation Candidate': 'role_or_state_mutation',
    'Account Recovery Flow Abuse Candidate': 'account_recovery',
    'Identity Verification / Action Authorization Bypass Candidate': 'authorization',
    'Generic API Review Candidate': 'generic',
}

# Categories that keep low-confidence findings in the promotion-eligible pool.
_HIGH_PRIORITY_CATEGORIES = frozenset({
    'Payment/Price/Point/Coupon Manipulation',
    'Account Recovery Weakness',
    'IDOR/BOLA',
    'Admin/Role/Permission Bypass',
    # Identity Verification / Action Authorization Bypass maps here; keep it
    # promotion-eligible at low confidence to match the old 'Authorization'-
    # substring behavior it replaced.
    'Authentication/Session Weakness',
})


def _category_for(vuln_type: str) -> str:
    """Return an internal category code for *vuln_type*.

    Tries exact lookup first so canonical mock-emitted types always resolve
    correctly.  Falls back to strict multi-word keyword matching for
    Gemini-generated free-form strings.

    'access' alone does NOT imply idor_bola.
    'account' alone does NOT imply account_recovery.
    """
    exact = _INTERNAL_CATEGORY_MAP.get(vuln_type)
    if exact:
        return exact
    vt = vuln_type.lower()
    if 'xss' in vt or 'cross-site scripting' in vt:
        return 'xss'
    # Use word-boundary for 'point/points' so 'endpoint' does not match.
    # Narrow 'amount' and 'balance' to compound phrases to avoid false positives
    # like 'Excessive Amount of Data' or 'Load Balance Misconfiguration'.
    if (any(k in vt for k in ('payment', 'price', 'coupon', 'discount', 'order total'))
            or re.search(r'\bpoints?\b', vt)
            or 'account balance' in vt or 'payment amount' in vt):
        return 'payment_or_value_mutation'
    # Require 'idor', 'bola', or a specific multi-word phrase — never classify on
    # 'access' or 'unauthorized' alone, which appear in many unrelated types.
    if ('idor' in vt or 'bola' in vt
            or 'object-level authorization' in vt
            or 'unauthorized data access' in vt
            or 'object access' in vt):
        return 'idor_bola'
    # Require a specific phrase for recovery — 'account' alone is too broad.
    if any(k in vt for k in ('account recovery', 'password reset', 'verification code', 'recovery token', 'reset password')):
        return 'account_recovery'
    if any(k in vt for k in ('state manipulation', 'status manipulation', 'role manipulation', 'role tamper', 'privilege escalation', 'state/status')):
        return 'role_or_state_mutation'
    if any(k in vt for k in ('validation bypass', 'client-side validation', 'client side validation')):
        return 'client_side_validation'
    if any(k in vt for k in ('authorization bypass', 'auth bypass', 'access control bypass', 'broken access control')):
        return 'authorization'
    return 'generic'


def _normalize_runtime_hint(value: str | None) -> str:
    return re.sub(r'\s+', ' ', str(value or '').strip()).casefold()


def _default_runtime_hint(kind: str) -> str:
    page_hint, action_hint, _ = _infer_page_action_hints('__sss_unknown__', '', None)
    if kind == GENERIC_HINT_ACTION_KIND:
        return action_hint
    return page_hint


def _is_generic_action_hint(action_hint: str | None) -> bool:
    normalized = _normalize_runtime_hint(action_hint)
    return not normalized or normalized == _normalize_runtime_hint(_default_runtime_hint(GENERIC_HINT_ACTION_KIND))


def _is_generic_page_hint(page_hint: str | None) -> bool:
    normalized = _normalize_runtime_hint(page_hint)
    return not normalized or normalized == _normalize_runtime_hint(_default_runtime_hint(GENERIC_HINT_PAGE_KIND))


def _auth_bypass_severity(content: str) -> str:
    content_lower = content.lower()
    if 'navigate' in content_lower and 'requireauth' not in content_lower and 'axios.' not in content_lower and 'fetch(' not in content_lower:
        return 'low'
    return 'high'


def _add_unique(target: list[str], value: str) -> None:
    if value not in target:
        target.append(value)


def select_console_relevant_files(files: list[FileContent]) -> list[FileContent]:
    scored: list[tuple[int, FileContent]] = []
    for f in files:
        fname = f.path.lower()
        content_lower = f.content.lower()
        score = sum(2 for k in KEYWORDS if k.lower() in fname)
        score += sum(1 for k in KEYWORDS if k.lower() in content_lower)
        if score > 0:
            scored.append((score, f))
    scored.sort(key=lambda x: x[0], reverse=True)
    return [f for _, f in scored[:20]]


def detect_missing_dependencies(files: list[FileContent]) -> list[str]:
    existing = {f.path for f in files}
    missing: list[str] = []
    for f in files:
        for line in f.content.splitlines():
            if 'requireAuth' in line or 'checkSession' in line:
                if 'sessionUtils' in line and not any('sessionutils' in p.lower() for p in existing):
                    missing.append('../utils/sessionUtils')
    return sorted(set(missing))


def _extract_endpoint(content: str) -> str | None:
    m = re.search(r'(?:axios\.(?:post|put)|fetch)\(\s*([\'"`])(.+?)\1', content, re.IGNORECASE)
    if not m:
        return None
    endpoint = re.sub(r'\$\{([^}]+)\}', r'{\1}', m.group(2))
    endpoint = re.sub(r'^\{apiBase\}', '', endpoint, flags=re.IGNORECASE)
    if '/api/' in endpoint:
        endpoint = endpoint[endpoint.index('/api/'):]
    return endpoint



def _extract_relevant_snippet(content: str, keywords: list[str], context_lines: int = 4) -> tuple[int, int, str]:
    lines = content.splitlines() or ['']
    lowered = [line.lower() for line in lines]
    keyword_l = [k.lower() for k in keywords]

    hit_idx = None
    for idx, line in enumerate(lowered):
        if any(k in line for k in keyword_l):
            hit_idx = idx
            break

    if hit_idx is None:
        end = min(len(lines), 20)
        return 1, end, '\n'.join(lines[:end])

    start = max(0, hit_idx - context_lines)
    end = min(len(lines) - 1, hit_idx + context_lines)
    return start + 1, end + 1, '\n'.join(lines[start:end + 1])


def _extract_auth_branch_snippet(content: str) -> tuple[int, int, str]:
    lines = content.splitlines() or ['']
    lowered = [line.lower() for line in lines]

    def is_import_line(idx: int) -> bool:
        return lowered[idx].lstrip().startswith('import ')

    presentation_noise = (
        'getrolebadgecolor', 'badge', 'color', 'notificationrole', 'shouldshownotification',
        '알림 표시', '역할별 뱃지', '역할별 알림', "return ['admin'", "return 'var(",
    )

    def context_window(idx: int) -> str:
        s = max(0, idx - 3)
        e = min(len(lines) - 1, idx + 3)
        return '\n'.join(lowered[s:e + 1])

    def has_auth_flow_nearby(idx: int) -> bool:
        ctx = context_window(idx)
        return bool(re.search(r'(requireauth|checkauthstatus)\s*\(', ctx) or re.search(r'\bnavigate\s*\(', ctx))

    def is_presentation_only(idx: int) -> bool:
        ctx = context_window(idx)
        if any(k in ctx for k in presentation_noise):
            return not has_auth_flow_nearby(idx)
        return False

    tier1_patterns = [
        r'(requireauth|checkauthstatus)\s*\(',
        r'(userinfo\.(usertype|role)|user\?\.(usertype|role)|\buserType\b|\brole\b|\bisadmin\b).*(===|!==|==|!=|>|<)',
    ]
    tier2_patterns = [
        r'\bif\b[^{\n]*\b(usertype|role|isadmin)\b[^{\n]*\b(admin)\b',
        r'\bif\b[^{\n]*\b(admin)\b.*\bnavigate\s*\(',
        r'\bif\b[^{\n]*\b(admin)\b.*\breturn\b',
        # Generic: role/userType compared to any uppercase constant (e.g. 'MANAGER', 'SUPERUSER')
        r'\bif\b[^{\n]*\b(usertype|role)\b[^{\n]*["\'][A-Z][A-Z_]{1,}["\']',
    ]
    tier3_patterns = [r'(protectedroute|privateroute)']

    hit_idx = None
    for pattern in (tier1_patterns + tier2_patterns + tier3_patterns + [r'\bnavigate\s*\(']):
        for idx, line in enumerate(lowered):
            if is_import_line(idx):
                continue
            if is_presentation_only(idx):
                continue
            if re.search(pattern, line):
                hit_idx = idx
                break
        if hit_idx is not None:
            break

    if hit_idx is None:
        end = min(len(lines), 20)
        return 1, end, '\n'.join(lines[:end])

    start = max(0, hit_idx - 6)
    end = min(len(lines) - 1, hit_idx + 6)
    while start < hit_idx and is_presentation_only(start):
        start += 1
    while start < end and is_import_line(start):
        start += 1
    while end > start and is_import_line(end):
        end -= 1
    return start + 1, end + 1, '\n'.join(lines[start:end + 1])


def _extract_validation_parameters(content: str) -> list[str]:
    found: list[str] = []
    lower = content.lower()
    for key in VALIDATION_PARAMETERS:
        if key.lower() in lower:
            found.append(key)
    return sorted(set(found), key=lambda x: x.lower())


def _find_dom_xss_flow(content: str) -> tuple[int, int, str] | None:
    lines = content.splitlines() or ['']
    sinks = ('innerhtml', 'outerhtml', 'insertadjacenthtml', 'document.write', 'dangerouslysetinnerhtml')
    sources = ('location.hash', 'location.search', 'document.url', 'document.location', 'event.data', 'input.value', 'urlsearchparams', 'window.name')
    for idx, line in enumerate(lines):
        low = line.lower()
        if not any(s in low for s in sinks):
            continue
        if any(x in low for x in ("innerhtml = ''", 'innerhtml = ""', 'testelement.innerhtml')):
            continue
        if re.search(r'innerhtml\s*=\s*[\'"][^\'"]*[\'"]\s*;?', low):
            continue
        start = max(0, idx - 6)
        end = min(len(lines) - 1, idx + 6)
        window = '\n'.join(lines[start:end + 1]).lower()
        if any(src in window for src in sources):
            return start + 1, end + 1, '\n'.join(lines[start:end + 1])
    return None




def _is_build_or_third_party_path(path: str, content: str = "") -> bool:
    path_l = path.lower()
    name = path_l.rsplit('/', 1)[-1]
    if name in {'jquery-ui.js', 'jquery.fullpage.js', 'jquery.selectbox.js'}:
        return True
    if any(seg in path_l for seg in ('/vendor/', '/vendors/', '/node_modules/', '/lib/', '/libs/', '/plugins/')):
        return True
    patterns = (
        r'^(app|commons|framework|webpack-runtime|runtime|polyfill|polyfills|vendors?|component---.+)-[a-f0-9]{8,}\.js$',
        r'^[0-9]+-[a-f0-9]{8,}\.js$',
        r'^[a-f0-9]{8,}-[a-f0-9]{8,}\.js$',
        r'^.+-[a-f0-9]{12,}\.js$',
    )
    if any(re.match(p, name) for p in patterns):
        return True
    head = content[:8192].lower()
    return any(sig in head for sig in ('webpackchunk', '__webpack_require__', '.license.txt', 'sourcemappingurl'))

def _dedup_findings(findings: list[ReadableFinding]) -> list[ReadableFinding]:
    grouped: dict[tuple[str, str, tuple[str, ...], str], ReadableFinding] = {}
    for f in findings:
        endpoint = ''
        method = ''
        sink = ''
        parameters: tuple[str, ...] = tuple()
        api_types = {
            'Client-side Validation Bypass',
            'Payment/Point Manipulation Candidate',
            'IDOR / Unauthorized Data Access Candidate',
            'State/Status Manipulation Candidate',
            'Account Recovery Flow Abuse Candidate',
            'Generic API Review Candidate',
        }
        if f.vulnerability_type in api_types and f.evidence:
            flows = f.evidence[0].data_flow
            source_path = f.evidence[0].source_path
            endpoint = next((x.replace('endpoint: ', '') for x in flows if x.startswith('endpoint: ')), '')
            method = next((x.replace('method: ', '') for x in flows if x.startswith('method: ')), '')
            sink = next((x.replace('sink: ', '') for x in flows if x.startswith('sink: ')), '')
            parameters = tuple(sorted([x.replace('parameter: ', '') for x in flows if x.startswith('parameter: ')]))
            function_name = next((x.replace('function: ', '') for x in flows if x.startswith('function: ')), '')
        else:
            source_path = ''
            function_name = ''
        disabled_marker = ''
        if f.verification_playbook and f.verification_playbook.strategy == 'disabled_button_bypass':
            disabled_marker = ','.join(sorted(f.affected_files))
        key = (f.vulnerability_type, source_path, function_name, method, endpoint, parameters, sink, f.root_cause, disabled_marker)
        if key not in grouped:
            grouped[key] = f
            continue
        g = grouped[key]
        g.affected_files = sorted(set(g.affected_files + f.affected_files))
        g.evidence = (g.evidence + f.evidence)[:5]
    return list(grouped.values())


def _is_allowed_guarded_poc_code(code: str) -> bool:
    low = code.lower()
    network_sink_re = re.compile(
        r'(fetch\s*\(|axios\.(get|post|put|patch|delete|request)\s*\(|new\s+xmlhttprequest\s*\(|xmlhttprequest\s*\(|navigator\.sendbeacon\s*\()',
        re.IGNORECASE,
    )
    if not network_sink_re.search(low):
        if re.search(r'\b(exec|execsync|execfile)\s*\(', low):
            return False
        return True

    if re.search(r'\b(exec|execsync|execfile)\s*\(', low):
        return False
    if 'navigator.sendbeacon' in low:
        return False

    has_legacy_guard = 'confirm_authorized_test = false' in low and 'if (!confirm_authorized_test)' in low
    has_browser_confirm_guard = (
        'confirm(' in low
        and re.search(r'if\s*\(\s*!\s*confirm\s*\(', low)
        and 'fetch(' in low
        and 'xmlhttprequest' not in low
        and 'window.sss_poc' not in low
        and 'window.sss_review_poc' not in low
        and 'interceptors.request.use' not in low
    )
    has_sss_poc_guard = all(x in low for x in ('sss_poc_state', 'mutationarmed', 'armmutation', 'disarm'))
    has_sss_review_poc_guard = all(x in low for x in ('sss_review_poc_state', 'mutationarmed', 'armmutation', 'disarm'))
    has_high_risk_observer_guard = all(x in low for x in ('blocked_replay', 'replay blocked: high-risk endpoint', 'captured'))
    is_sss_hook = 'window.sss_poc' in low and ('window.fetch = async function' in low or 'xmlhttprequest.prototype.send' in low or 'axios.interceptors.request.use' in low)
    is_sss_review_hook = 'window.sss_review_poc' in low and ('window.fetch = async function' in low or 'xmlhttprequest.prototype.send' in low or 'axios.interceptors.request.use' in low)

    if is_sss_hook and (has_sss_poc_guard or has_high_risk_observer_guard):
        return True
    if is_sss_review_hook and (has_sss_review_poc_guard or has_high_risk_observer_guard):
        return True

    if re.search(r'axios\.delete\s*\(', low):
        return False
    if re.search(r"method\s*:\s*['\"]delete['\"]", low):
        return False
    if any(x in low for x in ('refund', 'transfer', 'withdraw', 'delete', 'remove', 'bulk')):
        return False

    is_mutation = bool(
        re.search(r"method\s*:\s*['\"](post|put|patch)['\"]", low)
        or re.search(r'axios\.(post|put|patch)\s*\(', low)
        or re.search(r'\.open\s*\(\s*[\'"](post|put|patch)[\'"]', low)
    )
    if is_mutation:
        return has_legacy_guard or has_sss_poc_guard or has_browser_confirm_guard
    return True


def _has_storage_auth_evidence(files: list[FileContent], primary_file: FileContent) -> bool:
    storage_read_re = re.compile(r'(sessionStorage|localStorage)\.getItem\s*\(|document\.cookie', re.IGNORECASE)
    auth_key_re = re.compile(r'(userType|role|isAdmin)', re.IGNORECASE)
    admin_branch_re = re.compile(r'\b(ADMIN|SUPERUSER|SUPER_ADMIN|ADMINISTRATOR)\b|isAdmin\s*[=!]=', re.IGNORECASE)

    related_files = [primary_file]
    base = primary_file.path.rsplit('/', 1)[0] if '/' in primary_file.path else ''
    for file in files:
        if file.path == primary_file.path:
            continue
        if base and file.path.startswith(base):
            related_files.append(file)

    combined = '\n'.join(file.content for file in related_files)
    return bool(storage_read_re.search(combined) and auth_key_re.search(combined) and admin_branch_re.search(combined))


def _build_disabled_console_code() -> str:
    return """window.SSS_DISABLED = {
  list() {
    const candidates = [...document.querySelectorAll('button[disabled], input[disabled]')];
    console.table(candidates.map((el, i) => ({
      index: i,
      text: el.innerText || el.value,
      disabled: el.disabled
    })));
    return candidates;
  },
  enable(index) {
    const target = this.list()[index];
    if (!target) return console.warn('[SSS DISABLED] invalid index');
    target.disabled = false;
    target.removeAttribute('disabled');
    return target;
  },
  click(index) {
    const target = this.list()[index];
    if (!target) return console.warn('[SSS DISABLED] invalid index');
    target.click();
  }
};
console.log('window.SSS_DISABLED.list()로 후보를 확인하고, 승인된 테스트에서만 enable(index)/click(index)를 실행하세요.');
"""


def _build_common_console_helper() -> str:
    return """(() => {
  if (window.SSS_POC && window.SSS_POC.__installed) {
    console.log('[SSS PoC] common helper already installed.');
    console.log('[SSS PoC] undefined after install is normal JavaScript console output.');
    return;
  }

  const captured = [];
  const state = {
    mutationArmed: false,
    originalFetch: window.fetch,
    originalXHROpen: XMLHttpRequest.prototype.open,
    originalXHRSend: XMLHttpRequest.prototype.send,
    originalJQueryAjax: window.jQuery && window.jQuery.ajax
  };

  const preview = (value) => {
    if (value === undefined || value === null) return null;
    try {
      return typeof value === 'string' ? value.slice(0, 500) : JSON.stringify(value).slice(0, 500);
    } catch (err) {
      return String(value).slice(0, 500);
    }
  };

  const parseBody = (body) => {
    if (!body || typeof body !== 'string') return null;
    try { return JSON.parse(body); } catch (err) { return null; }
  };

  const pushCapture = (item) => {
    const entry = Object.assign({ index: captured.length, timestamp: new Date().toISOString() }, item);
    captured.push(entry);
    console.group('[SSS PoC] request captured');
    console.log('index:', entry.index);
    console.log('transport:', entry.transport);
    console.log('method:', entry.method);
    console.log('url:', entry.url);
    console.log('body:', entry.bodyPreview || null);
    console.groupEnd();
    return entry;
  };

  window.SSS_POC = {
    __installed: true,
    captured,
    armMutation() {
      state.mutationArmed = true;
      console.warn('[SSS PoC] mutation/replay armed. Use only in an approved test environment.');
      console.warn('[SSS PoC] armMutation does not change live traffic by itself; it allows replay(index, overrides) for mutating requests.');
    },
    disarm() {
      state.mutationArmed = false;
      console.log('[SSS PoC] disarmed.');
    },
    list() {
      console.table(captured.map((x) => ({ index: x.index, transport: x.transport, method: x.method, url: x.url, status: x.responseStatus || '' })));
      return captured;
    },
    find(criteria = {}) {
      const urlIncludes = criteria.urlIncludes ? String(criteria.urlIncludes) : '';
      const method = criteria.method ? String(criteria.method).toUpperCase() : '';
      const transport = criteria.transport ? String(criteria.transport).toLowerCase() : '';
      return captured.find((item) => {
        const itemUrl = String(item.url || '');
        const itemMethod = String(item.method || '').toUpperCase();
        const itemTransport = String(item.transport || '').toLowerCase();
        if (urlIncludes && !itemUrl.includes(urlIncludes)) return false;
        if (method && itemMethod !== method) return false;
        if (transport && itemTransport !== transport) return false;
        return true;
      }) || null;
    },
    get(index) {
      return captured[index] || null;
    },
    async replay(index, overrides = {}) {
      const item = captured[index];
      if (!item) {
        console.warn('[SSS PoC] invalid capture index');
        return null;
      }
      const method = String(overrides.method || item.method || 'GET').toUpperCase();
      if (method !== 'GET' && !state.mutationArmed) {
        console.warn('[SSS PoC] replay blocked. Run window.SSS_POC.armMutation() first for non-GET requests.');
        return null;
      }
      if (item.transport === 'xhr') {
        console.warn('[SSS PoC] xhr replay is not automatic. Reproduce the UI action manually or rebuild the request in an approved API client.');
        console.log('[SSS PoC] xhr captured request:', item);
        return null;
      }
      const headers = Object.assign({}, item.headers || {}, overrides.headers || {});
      if (item.transport === 'axios') {
        if (!window.axios || typeof window.axios !== 'function') {
          console.warn('[SSS PoC] axios replay unavailable: window.axios is not callable.');
          return null;
        }
        const config = Object.assign({}, item.config || {}, overrides || {});
        config.method = method;
        config.url = overrides.url || item.url || config.url;
        config.headers = headers;
        if (overrides.body !== undefined) {
          config.data = overrides.body;
        }
        console.warn('[SSS PoC] replaying captured axios request:', method, config.url);
        const resp = await window.axios(config);
        console.log('[SSS PoC] axios replay response:', resp);
        return resp;
      }
      if (item.transport === 'jquery.ajax') {
        if (!window.jQuery || !window.jQuery.ajax) {
          console.warn('[SSS PoC] jQuery replay unavailable: window.jQuery.ajax is missing.');
          return null;
        }
        const config = Object.assign({}, item.config || {}, overrides || {});
        config.type = method;
        config.method = method;
        config.url = overrides.url || item.url || config.url;
        config.headers = headers;
        if (overrides.body !== undefined) {
          config.data = overrides.body;
        }
        console.warn('[SSS PoC] replaying captured jQuery.ajax request:', method, config.url);
        return window.jQuery.ajax(config);
      }
      const url = overrides.url || item.url;
      const init = Object.assign({}, item.init || {}, overrides);
      init.method = method;
      if (overrides.body !== undefined) {
        init.body = typeof overrides.body === 'string' ? overrides.body : JSON.stringify(overrides.body);
      } else if (item.body !== undefined && item.body !== null) {
        init.body = item.body;
      }
      init.headers = headers;
      console.warn('[SSS PoC] replaying captured fetch request:', method, url);
      const resp = await state.originalFetch.call(window, url, init);
      console.log('[SSS PoC] fetch replay response status:', resp.status);
      console.log('[SSS PoC] fetch replay response preview:', (await resp.clone().text().catch(() => '')).slice(0, 500));
      return resp;
    }
  };

  if (state.originalFetch) {
    window.fetch = async function(input, init = {}) {
      const url = typeof input === 'string' ? input : (input && input.url) || String(input);
      const method = String(init && init.method || 'GET').toUpperCase();
      const entry = pushCapture({
        transport: 'fetch',
        method,
        url,
        init: Object.assign({}, init),
        headers: init && init.headers || {},
        body: init && init.body || null,
        bodyPreview: preview(init && init.body),
        parsedPayload: parseBody(init && init.body)
      });
      const resp = await state.originalFetch.call(this, input, init);
      entry.responseStatus = resp.status;
      entry.responseContentType = resp.headers && resp.headers.get ? resp.headers.get('content-type') : '';
      entry.responsePreview = (await resp.clone().text().catch(() => '')).slice(0, 500);
      return resp;
    };
  }

  XMLHttpRequest.prototype.open = function(method, url) {
    this.__sss_poc_method = String(method || 'GET').toUpperCase();
    this.__sss_poc_url = String(url || '');
    return state.originalXHROpen.apply(this, arguments);
  };
  XMLHttpRequest.prototype.send = function(body) {
    pushCapture({
      transport: 'xhr',
      method: this.__sss_poc_method || 'GET',
      url: this.__sss_poc_url || '',
      body: body || null,
      bodyPreview: preview(body),
      parsedPayload: parseBody(body)
    });
    return state.originalXHRSend.call(this, body);
  };

  if (window.axios && window.axios.interceptors && window.axios.interceptors.request) {
    window.axios.interceptors.request.use((config) => {
      pushCapture({
        transport: 'axios',
        method: String(config && config.method || 'GET').toUpperCase(),
        url: String(config && config.url || ''),
        config,
        headers: config && config.headers || {},
        body: config && config.data || null,
        bodyPreview: preview(config && config.data),
        parsedPayload: typeof (config && config.data) === 'object' ? config.data : parseBody(config && config.data)
      });
      return config;
    });
  }

  if (window.jQuery && window.jQuery.ajax) {
    window.jQuery.ajax = function(urlOrOptions, maybeOptions) {
      const options = typeof urlOrOptions === 'string' ? Object.assign({}, maybeOptions || {}, { url: urlOrOptions }) : Object.assign({}, urlOrOptions || {});
      pushCapture({
        transport: 'jquery.ajax',
        method: String(options.type || options.method || 'GET').toUpperCase(),
        url: String(options.url || ''),
        config: options,
        headers: options.headers || {},
        body: options.data || null,
        bodyPreview: preview(options.data),
        parsedPayload: typeof options.data === 'object' ? options.data : parseBody(options.data)
      });
      return state.originalJQueryAjax.apply(this, arguments);
    };
  }

  console.group('[SSS PoC] common helper installed');
  console.log('1. If the console prints undefined after install, that is normal JavaScript completion output.');
  console.log('2. Confirm window.SSS_POC exists:', !!window.SSS_POC);
  console.log('3. Go to the target page and perform the playbook user action.');
  console.log('4. Run window.SSS_POC.list() to inspect captured requests.');
  console.log('5. Use window.SSS_POC.find({ urlIncludes, method, transport }) to get the first matching request.');
  console.log('6. Use window.SSS_POC.get(index) to inspect one request.');
  console.log('7. Use window.SSS_POC.armMutation() only before replaying non-GET requests with approved test data.');
  console.log('8. Use window.SSS_POC.disarm() after verification.');
  console.groupEnd();
})();"""


def _build_short_console_verification_code(
    endpoint: str,
    method: str,
    page_hint: str,
    action_hint: str,
    parameters: list[str] | None = None,
) -> str:
    """9-line pasteable console snippet. Requires common_console_helper installed first."""
    endpoint_js = json.dumps(endpoint or '')
    method_js = json.dumps((method or '').upper())
    override_examples: list[str] = []
    for p in (parameters or []):
        if not p or not re.fullmatch(r'[A-Za-z_$][A-Za-z0-9_$]*', p):
            continue
        low = p.lower()
        if low in {'amount', 'price', 'totalamount', 'usepoints', 'point', 'points', 'balance'}:
            override_examples.append(f'{p}: 1')
        elif low == 'status':
            override_examples.append(f'{p}: "TEST_STATUS"')
        elif low in {'code', 'verificationcode'}:
            override_examples.append(f'{p}: "000000"')
    if override_examples:
        replay_args = f', {{ body: {{ {", ".join(override_examples[:4])} }} }}'
    else:
        replay_args = ''
    if (method or '').upper() != 'GET':
        action_hint_line = (
            f'  // Approved mutation only: window.SSS_POC.armMutation();'
            f' window.SSS_POC.replay(match.index{replay_args}); window.SSS_POC.disarm();'
        )
    else:
        action_hint_line = f'  // Read-only: window.SSS_POC.replay(match.index);'
    return '\n'.join([
        '(async () => {',
        f'  if (!window.SSS_POC?.find) {{ console.warn("[SSS PoC] Install common_console_helper first."); return; }}',
        f'  // Page: {page_hint} | Action: {action_hint} | Target: {method or "UNKNOWN"} {endpoint or "UNKNOWN"}',
        '  window.SSS_POC.list();',
        f'  const match = window.SSS_POC.find({{ urlIncludes: {endpoint_js}, method: {method_js} }});',
        f'  if (!match) {{ console.warn("[SSS PoC] No match yet - perform the UI action, then run again."); return; }}',
        '  console.log("[SSS PoC] Captured:", match);',
        action_hint_line,
        '})();',
    ])


def _english_review_hint(value: str | None, fallback: str) -> str:
    text = str(value or '').strip()
    if not text or not text.isascii():
        return fallback
    return text


def _review_page_step(page_hint: str | None) -> str:
    return f"Open page: {_english_review_hint(page_hint, 'target page')}"


def _build_network_hook_mutation_poc(endpoint: str, page_hint: str = 'target page', action_hint: str = 'target action') -> str:
    endpoint_js = json.dumps(endpoint)
    page_js = json.dumps(_english_review_hint(page_hint, 'target page'))
    action_js = json.dumps(_english_review_hint(action_hint, 'target action'))
    return f"""(() => {{
  const TARGET_ENDPOINT = {endpoint_js};
  const PAGE_HINT = {page_js};
  const ACTION_HINT = {action_js};
  const SSS_REVIEW_POC_STATE = {{ mutationArmed: false, replayArmed: false }};
  const BLOCKED_REPLAY = /(delete|refund|withdraw|transfer|bulk)/i.test(TARGET_ENDPOINT);
  const captured = [];

  const isHtmlFallback = (contentType, text) => {{
    const ct = String(contentType || '').toLowerCase();
    const body = String(text || '').trim().toLowerCase();
    return ct.includes('text/html') || body.startsWith('<!doctype html') || body.startsWith('<html') || body.includes('id="root"') || body.includes('create-react-app');
  }};

  const logCapturedResponse = async (resp) => {{
    const ct = resp.headers?.get?.('content-type') || '';
    const body = await resp.clone().text().catch(() => '');
    console.log('response status:', resp.status);
    console.log('response content-type:', ct || '(none)');
    console.log('response body preview:', String(body).slice(0, 300));
    if (isHtmlFallback(ct, body)) {{
      console.warn('[SSS Review PoC] The response looks like HTML instead of API JSON. This may be a frontend routing fallback.');
      console.warn('[SSS Review PoC] Capture the real UI request instead of relying on a direct endpoint call.');
    }}
  }};

  window.SSS_REVIEW_POC = {{
    captured,
    armMutation() {{
      SSS_REVIEW_POC_STATE.mutationArmed = true;
      console.warn('[SSS Review PoC] mutation mode armed. Use only in an approved test environment.');
    }},
    armReplay() {{
      if (BLOCKED_REPLAY) {{
        console.warn('[SSS PoC] replay blocked: high-risk endpoint');
        return;
      }}
      SSS_REVIEW_POC_STATE.replayArmed = true;
      console.warn('[SSS Review PoC] replay mode armed. Use only in an approved test environment.');
    }},
    disarm() {{
      SSS_REVIEW_POC_STATE.mutationArmed = false;
      SSS_REVIEW_POC_STATE.replayArmed = false;
      console.log('[SSS Review PoC] disarmed.');
    }},
    list() {{
      console.table(captured.map((x, i) => ({{ index: i, method: x.method, url: x.url }})));
    }},
    async replay(index, overrides = {{}}) {{
      if (BLOCKED_REPLAY) {{
        console.warn('[SSS PoC] replay blocked: high-risk endpoint');
        return null;
      }}
      if (!SSS_REVIEW_POC_STATE.replayArmed) {{
        console.warn('[SSS Review PoC] replayArmed=false. Run window.SSS_REVIEW_POC.armReplay() first.');
        return null;
      }}
      const item = captured[index];
      if (!item) {{
        console.warn('[SSS PoC] invalid capture index');
        return null;
      }}
      if (item.transport === 'axios') {{
        if (window.axios && typeof axios === 'function') {{
          const cfg = Object.assign({{}}, item.config || {{}}, overrides || {{}});
          return axios(cfg);
        }}
        console.warn('[SSS Review PoC] axios replay unavailable: window.axios is not callable.');
        return null;
      }}
      if (item.transport === 'xhr') {{
        console.warn('[SSS Review PoC] xhr replay is not automatic. Use manual verification.');
        return null;
      }}
      const init = Object.assign({{}}, item.init || {{}}, overrides || {{}});
      const resp = await originalFetch(item.url, init);
      await logCapturedResponse(resp);
      return resp;
    }},
  }};

  const printNextStepChecklist = () => {{
    console.group('[SSS Review PoC] Next-step checklist');
    console.log('1. If the final Console evaluation result is "undefined", that is normal when these install logs appeared.');
    console.log('2. Confirm window.SSS_REVIEW_POC exists:', Boolean(window.SSS_REVIEW_POC));
    console.log('3. Move to the exact page_hint:', PAGE_HINT);
    console.log('4. Perform the required_user_action if known:', ACTION_HINT);
    console.log('5. Run window.SSS_REVIEW_POC.list() after the action to inspect captured requests.');
    console.log('6. If no request is captured, likely causes: wrong page, wrong button/action, placeholder endpoint, endpoint generated from API_BASE_URL and not resolved, request uses a different transport/path.');
    console.log('7. Use window.SSS_REVIEW_POC.armMutation() only after the baseline request is captured and you have approval to test mutation. Do not arm mutation for first observation, placeholder endpoints, wrong page/action, or high-risk endpoints.');
    console.groupEnd();
  }};

  if (/\\{{[^}}]+\\}}|placeholder/i.test(TARGET_ENDPOINT)) {{
    console.warn('[SSS Review PoC] The endpoint contains a placeholder. Capture the real UI request before relying on this PoC.');
  }}
  if (/[{{}}]|API_BASE_URL|UNKNOWN/i.test(TARGET_ENDPOINT)) {{
    console.warn('[SSS Review PoC] Target endpoint contains an unresolved placeholder. Resolve endpoint/page/action before relying on this PoC.');
  }}
  const originalFetch = window.fetch;
  window.fetch = async function(input, init = {{}}) {{
    const url = String(input);
    if (url.includes(TARGET_ENDPOINT)) {{
      const method = String(init?.method || 'GET').toUpperCase();
      let parsed = null;
      if (init?.body) {{
        try {{ parsed = JSON.parse(init.body); }} catch (e) {{}}
      }}
      if (SSS_REVIEW_POC_STATE.mutationArmed && parsed && !BLOCKED_REPLAY) {{
        if ('amount' in parsed) parsed.amount = 1;
        if ('status' in parsed) parsed.status = 'TEST_STATUS';
        init.body = JSON.stringify(parsed);
      }}
      captured.push({{ transport: 'fetch', method, url, init, body: init?.body || null, parsedPayload: parsed }});
      console.group('[SSS Review PoC] request captured');
      console.log('url:', url);
      console.log('method:', method);
      console.log('request body:', init?.body || null);
      console.log('parsed payload:', parsed);
      console.groupEnd();
    }}
    const response = await originalFetch.call(this, input, init);
    if (url.includes(TARGET_ENDPOINT)) await logCapturedResponse(response);
    return response;
  }};
  const originalXHROpen = XMLHttpRequest.prototype.open;
  const originalXHRSend = XMLHttpRequest.prototype.send;
  XMLHttpRequest.prototype.open = function(method, url) {{
    this.__poc_method = String(method || 'GET').toUpperCase();
    this.__poc_url = String(url || '');
    return originalXHROpen.apply(this, arguments);
  }};
  XMLHttpRequest.prototype.send = function(body) {{
    if ((this.__poc_url || '').includes(TARGET_ENDPOINT)) {{
      let parsed = null;
      if (body) {{
        try {{ parsed = JSON.parse(body); }} catch (e) {{}}
      }}
      captured.push({{
        transport: 'xhr',
        method: this.__poc_method || 'GET',
        url: this.__poc_url || '',
        body: body || null,
        parsedPayload: parsed
      }});
      if (SSS_REVIEW_POC_STATE.mutationArmed && !BLOCKED_REPLAY && parsed) {{
        if ('amount' in parsed) parsed.amount = 1;
        if ('status' in parsed) parsed.status = 'TEST_STATUS';
        body = JSON.stringify(parsed);
      }}
    }}
    return originalXHRSend.call(this, body);
  }};
  if (window.axios && axios.interceptors && axios.interceptors.request) {{
    axios.interceptors.request.use((config) => {{
      if (String(config?.url || '').includes(TARGET_ENDPOINT)) {{
        if (SSS_REVIEW_POC_STATE.mutationArmed && config?.data && typeof config.data === 'object' && !BLOCKED_REPLAY) {{
          if ('amount' in config.data) config.data.amount = 1;
          if ('status' in config.data) config.data.status = 'TEST_STATUS';
        }}
        captured.push({{ transport: 'axios', method: String(config?.method || 'GET').toUpperCase(), url: String(config?.url || ''), config }});
      }}
      return config;
    }});
  }}
  console.group('[SSS Review PoC] installed');
  console.log('mode:', 'observe');
  console.log('target:', TARGET_ENDPOINT);
  console.log('undefined output is normal if this install log appeared.');
  console.log('confirm window.SSS_REVIEW_POC exists:', Boolean(window.SSS_REVIEW_POC));
  console.log('Next step: perform the documented user action.');
  console.log('When a request is captured, URL/method/payload/status will be logged.');
  console.log('For mutation verification, run window.SSS_REVIEW_POC.armMutation() after approval, then repeat the user action.');
  console.log('For replay verification, run window.SSS_REVIEW_POC.armReplay(), then window.SSS_REVIEW_POC.replay(index, overrides).');
  console.groupEnd();
  printNextStepChecklist();
  console.group('[SSS Review PoC] verification guidance');
  console.log('Page:', PAGE_HINT);
  console.log('User action:', ACTION_HINT);
  console.log('Target API:', TARGET_ENDPOINT);
  console.log('Current mode: observe');
  console.log('1) Open this page:', PAGE_HINT);
  console.log('2) Confirm the install log is visible in Console.');
  console.log('3) Perform this user action:', ACTION_HINT);
  console.log('4) Run window.SSS_REVIEW_POC.list() to inspect captured requests.');
  console.log('5) For mutation verification, run window.SSS_REVIEW_POC.armMutation() after approval, then repeat the same action.');
  console.log('6) Finish with window.SSS_REVIEW_POC.disarm().');
  if (ACTION_HINT === 'target action') {{
    console.warn('The exact button/page was not inferred. Confirm manually using source_path and function_name.');
  }}
  console.groupEnd();
}})();"""



def _find_enclosing_function_block(content: str, line_number: int) -> tuple[str | None, int, int, str] | None:
    lines = content.splitlines() or ['']
    idx = max(1, min(line_number, len(lines))) - 1
    start = max(0, idx - 120)
    end = min(len(lines) - 1, idx + 120)
    pats = [
        re.compile(r'\basync\s+function\s+([A-Za-z_][A-Za-z0-9_]*)\s*\('),
        re.compile(r'\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)\s*\('),
        re.compile(r'\bconst\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*async\s*\([^)]*\)\s*=>\s*\{'),
        re.compile(r'\bconst\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*\([^)]*\)\s*=>\s*\{'),
    ]
    for s in range(idx, start - 1, -1):
        m = next((p.search(lines[s]) for p in pats if p.search(lines[s])), None)
        if not m:
            continue
        depth = 0
        opened = False
        for e in range(s, end + 1):
            depth += lines[e].count('{')
            if lines[e].count('{') > 0:
                opened = True
            depth -= lines[e].count('}')
            if opened and depth <= 0 and e >= idx:
                return (m.group(1) if m.groups() else None, s + 1, e + 1, '\n'.join(lines[s:e + 1]))
    return None


def _infer_page_action_hints(path: str, snippet: str, function_name: str | None = None) -> tuple[str, str, str | None]:
    p = path.lower()
    s = snippet.lower()
    page_map = [
        ('paymentpage', 'payment page'), ('purchasepage', 'purchase page'),
        ('auctionpage', 'auction/bid page'),
        ('findpassword', 'password recovery page'), ('loginpage', 'login page'),
        ('signuppage', 'signup page'), ('itemdetailpage', 'item detail/bid page'),
        ('usermypage', 'mypage/management page'), ('adminmypage', 'admin/management page'),
    ]
    page_hint = next((v for k, v in page_map if k in p), 'target feature page')
    fn = function_name
    if not fn:
        m = re.search(r'(handle[A-Za-z0-9_]+|loadDashboardData|fetchDashboard)', snippet)
        if m:
            fn = m.group(1)
    action = 'target action'
    f = (fn or '').lower()
    if 'handlepay' in f or 'handlepayment' in f or 'handleretrypayment' in f:
        action = 'click payment/complete button'
    elif 'handlestripecheckout' in f:
        action = 'click Stripe payment button'
    elif 'requestiamportpay' in f:
        action = 'click Iamport payment button'
    elif 'handleiamportquick' in f:
        action = 'click quick payment/charge button'
    elif 'handlepointcharge' in f:
        action = 'click point charge button'
    elif 'handlecharge' in f:
        action = 'click point charge button'
    elif 'sendverificationcode' in f:
        action = 'click send code button'
    elif 'verifycode' in f:
        action = 'click verify code button'
    elif 'resetpassword' in f:
        action = 'click reset password button'
    elif 'handleverify' in f:
        action = 'click verify code button'
    elif 'handleresetpassword' in f:
        action = 'click reset password button'
    elif 'handlesubmit' in f:
        action = 'click submit form button'
    elif 'handlebid' in f:
        action = 'click bid button'
    elif 'handlepurchase' in f:
        action = 'click purchase button'
    return page_hint, action, fn

def _format_page_step(page_hint: str) -> str:
    return f'Navigate to {page_hint}'


def infer_interaction_context(source_path: str, function_name: str | None, snippet: str, endpoint: str, method: str, parameters: list[str], surrounding_block: str = '', ui_candidates: list[dict] | None = None) -> tuple[str, str, str, list[str]]:
    low_endpoint = (endpoint or '').lower()
    low_text = ' '.join(filter(None, [snippet, surrounding_block] + [c.get('element_text', '') for c in (ui_candidates or [])])).lower()
    low_fn = (function_name or '').lower()
    reasons: list[str] = []
    page_hint = 'target feature page'
    action_hint = 'target action'
    confidence = 'low'
    if any(k in low_endpoint for k in ('payment', 'order', 'checkout', 'pay', 'billing')):
        page_hint, reasons = 'payment/order page', reasons + ['endpoint category: payment/order']
    elif any(k in low_endpoint for k in ('auction', 'bid')):
        page_hint, reasons = 'auction/bid page', reasons + ['endpoint category: auction/bid']
    elif any(k in low_endpoint for k in ('password', 'reset', 'verify-code', 'send-verification', 'verify', 'chkmobi', 'chgmobi', 'mobile', 'sms', 'cert', 'authno')):
        page_hint, reasons = 'account recovery page', reasons + ['endpoint category: recovery/verify']
    elif any(k in low_endpoint for k in ('wallet', 'point', 'charge')):
        page_hint, reasons = 'wallet/point page', reasons + ['endpoint category: wallet/point']
    elif any(k in low_endpoint for k in ('iamport',)):
        page_hint, reasons = 'payment/order page', reasons + ['endpoint category: iamport payment']
    elif any(k in low_endpoint for k in ('login', 'auth/token')):
        page_hint, reasons = 'login/auth page', reasons + ['endpoint category: login/auth']
    if any(k in low_text for k in ('pay now', 'checkout', '결제하기', '결제 완료')):
        action_hint = 'click payment button'; reasons.append('ui text indicates payment')
    elif any(k in low_text for k in ('입찰', 'bid')):
        action_hint = 'click bid button'; reasons.append('ui text indicates bid')
    elif any(k in low_text for k in ('인증번호 발송', 'send code')):
        action_hint = 'click send code button'; reasons.append('ui text indicates send code')
    elif any(k in low_text for k in ('인증 확인', 'verify')):
        action_hint = 'click verify code button'; reasons.append('ui text indicates verify')
    elif any(k in low_text for k in ('reset password', '비밀번호 재설정')):
        action_hint = 'click reset password button'; reasons.append('ui text indicates reset')
    elif any(k in low_endpoint for k in ('verify-code', 'authno', 'verify')):
        action_hint = 'click verify code button'; reasons.append('endpoint indicates verify-code')
    elif any(k in low_endpoint for k in ('reset-password',)):
        action_hint = 'click reset password button'; reasons.append('endpoint indicates reset-password')
    elif any(k in low_endpoint for k in ('send-verification', 'chkmobisendajax', 'chgmobisendajax', 'sendsms', 'sms')):
        action_hint = 'click send code button'; reasons.append('endpoint indicates send-verification')
    elif 'create-checkout-session' in low_endpoint:
        action_hint = 'click Stripe payment button'; reasons.append('endpoint indicates stripe checkout session')
    elif any(k in low_endpoint for k in ('iamport/prepare', 'iamport/verify')):
        action_hint = 'click payment approval button'; reasons.append('endpoint indicates iamport verification')
    elif any(k in low_endpoint for k in ('wallet/charge', '/charge')):
        action_hint = 'click point charge button'; reasons.append('endpoint indicates charge')
    elif any(k in low_fn for k in ('payment', 'checkout', 'pay', 'submitorder', 'process')):
        action_hint = 'click payment button'; reasons.append('function fallback indicates payment')
    elif any(k in low_fn for k in ('bid', 'placebid')):
        action_hint = 'click bid button'; reasons.append('function fallback indicates bid')
    elif any(k in low_fn for k in ('verifycode', 'confirmcode', 'validatecode')):
        action_hint = 'click verify code button'; reasons.append('function fallback indicates verify')
    elif any(k in low_fn for k in ('resetpassword', 'changepassword')):
        action_hint = 'click reset password button'; reasons.append('function fallback indicates reset')
    elif any(k in low_fn for k in ('sendverificationcode', 'requestcode')):
        action_hint = 'click send code button'; reasons.append('function fallback indicates send-code')
    if action_hint != 'target action' and page_hint != 'target feature page':
        confidence = 'high'
    elif action_hint != 'target action' or page_hint != 'target feature page':
        confidence = 'medium'
    return page_hint, action_hint, confidence, reasons


def _build_playbook(f: FileContent, candidate: ApiCallCandidate | None = None, auth: bool = False, disabled: bool = False, page_hint: str | None = None, action_hint: str | None = None, function_name: str | None = None) -> ConsoleVerificationPlaybook:
    if auth:
        return ConsoleVerificationPlaybook(
            strategy='auth_route_guard',
            breakpoints=[BreakpointHint(source_path=f.path, start_line=1, end_line=max(1, len(f.content.splitlines())), reason='check auth branch condition', watch_variables=['userInfo', 'user', 'role', 'userType', 'isAdmin'])],
            console_steps=['set breakpoint on auth branch', 'access protected page after login', 'check userType/role in Scope', 'confirm if client-only or also server validation'],
            expected_observation='confirm auth branch is client-only',
        )
    if disabled:
        bps = []
        if candidate is not None:
            bps.append(BreakpointHint(source_path=f.path, start_line=candidate.start_line, end_line=candidate.end_line, reason='check payload before API call', watch_variables=['payload'] + (candidate.parameters or [])))
        return ConsoleVerificationPlaybook(
            strategy='disabled_button_bypass',
            breakpoints=bps,
            console_steps=['list disabled buttons', 'enable target button', 'confirm handler/request fires after click'],
            console_code=_build_disabled_console_code(),
            expected_observation='confirm request fires after removing disabled attribute',
            limitations=['React/Vue state-based validation may require more than removing DOM disabled', 'check breakpoint at validation return inside handler'],
        )
    endpoint = (candidate.endpoint if candidate else '/api') or '/api'
    method = (candidate.method if candidate else 'POST') or 'POST'
    params = (candidate.parameters if candidate else [])
    validation_bps = _find_validation_return_breakpoints(f, candidate)
    vars_from_validation = {w for bp in validation_bps for w in bp.watch_variables}
    vars_from_endpoint = set(re.findall(r'\{([^}]+)\}', (candidate.endpoint if candidate else '') or ''))
    watch = ['payload'] + ((candidate.parameters or []) if candidate else []) + list(vars_from_validation) + list(vars_from_endpoint)
    breakpoints = list(validation_bps)
    breakpoints.append(BreakpointHint(source_path=f.path, start_line=(candidate.start_line if candidate else 1), end_line=(candidate.end_line if candidate else 1), reason='check payload before API call', watch_variables=sorted(set(watch))))
    short_code = (_build_short_console_verification_code(endpoint, method, page_hint or 'target feature page', action_hint or 'target action', params) if endpoint != 'UNKNOWN' else None)
    return ConsoleVerificationPlaybook(
        strategy='breakpoint_payload_mutation',
        breakpoints=breakpoints,
        console_steps=['set breakpoint in DevTools Sources', 'click the normal UI button', 'check payload value in Scope', 'change to test value', 'check server response after Resume'],
        console_code=short_code,
        expected_observation='payload mutation before request is reflected in the body',
        limitations=(['endpoint is UNKNOWN: auto hook code not generated'] if endpoint == 'UNKNOWN' else []),
    )




def _build_safe_network_poc(endpoint: str, page_hint: str, action_hint: str, method: str = '') -> ConsoleSafePoc:
    """Short capture-hint PoC for promoted findings that lack self-contained code.
    Requires common_console_helper installed first."""
    code = _build_short_console_verification_code(
        endpoint, method or 'UNKNOWN', page_hint or 'target page', action_hint or 'target action'
    )
    return ConsoleSafePoc(
        poc_type='browser_console',
        description='Capture-hint PoC (requires common_console_helper). Install helper once, then use window.SSS_POC.*.',
        preconditions=['common_console_helper installed in DevTools Console', 'Approved test environment'],
        steps=[
            'Install common_console_helper once (see common_console_helper field)',
            _review_page_step(page_hint),
            f"Perform action: {_english_review_hint(action_hint, 'target action')}",
            'Run window.SSS_POC.list() to inspect captured requests',
        ],
        code=code,
        expected_result=f'Request for {method or "UNKNOWN"} {endpoint} is captured in window.SSS_POC.captured.',
        safety='Uses common_console_helper API only. Does not reinstall transport hooks.',
    )


def _build_capture_hint(endpoint: str, method: str, page_hint: str, action_hint: str) -> str:
    """Short 5-line comment for review candidates. References common_console_helper only."""
    return '\n'.join([
        '// Capture hint - install common_console_helper once first, then:',
        f'// 1. {_review_page_step(page_hint)}',
        f'// 2. Perform: {action_hint}',
        '// 3. window.SSS_POC.list()',
        f'// 4. window.SSS_POC.find({{ urlIncludes: {json.dumps(endpoint)}, method: {json.dumps(method)} }})',
    ])


def _is_external_or_static_endpoint(endpoint: str) -> bool:
    ep = (endpoint or '').lower().strip()
    if not ep:
        return False
    if ep.startswith(('http://', 'https://')) and not any(h in ep for h in ('localhost', '127.0.0.1')):
        return True
    return any(k in ep for k in ('analytics', 'google-analytics', 'gtag', 'doubleclick', '/static/', '/assets/', '.js', '.css', '.png', '.jpg', '.gif', '.svg'))

def _build_manual_poc_plan(source_path: str, function_name: str | None, endpoint: str, method: str) -> list[str]:
    return [
        f'File: {source_path}',
        f'Function: {function_name or "UNKNOWN"}',
        f'Request: {method or "UNKNOWN"} {endpoint or "UNKNOWN"}',
        'reconfirm data_flow (method/endpoint/function/sink) from evidence',
        'set breakpoint at payload variable / validation branch before request',
        'check URL/method/payload/status/response in browser Network tab',
        'confirm Console hook applicability (UNKNOWN endpoint or compressed/library code may limit this)',
        'record reason for PoC limitation in review notes',
    ]


def _extend_manual_poc_plan_for_placeholders(plan: list[str], placeholders: list[str]) -> list[str]:
    if not placeholders:
        return plan
    resolved = list(plan)
    resolved.append(f'Unresolved placeholder blocks promotion: {", ".join(placeholders)}')
    for placeholder in placeholders:
        if placeholder == '{API_BASE_URL}':
            resolved.append('Resolve {API_BASE_URL} to the real origin/base URL before confirming the endpoint')
        elif placeholder in {'{userId}', 'test_user_id'}:
            resolved.append('Resolve userId from the authenticated session, captured Network request, or approved test account')
        elif placeholder == '{sessionData.userId}':
            resolved.append('Resolve sessionData.userId from the runtime session object or captured request payload')
        elif placeholder in {'{auctionItem.orderId}', 'test_order_id'}:
            resolved.append('Resolve orderId from the approved test order or auction item')
        elif placeholder == 'UNKNOWN':
            resolved.append('Resolve UNKNOWN endpoint/method/action from source evidence and the browser Network tab')
    return resolved


def _mark_review_candidate(finding: ReadableFinding) -> None:
    finding.verification_notes = [note for note in finding.verification_notes if note != 'Selected as runtime verification candidate']
    if not finding.title.startswith('Manual review candidate:'):
        finding.title = f'Manual review candidate: {finding.title}'
    prefix = 'Manual review candidate - Not yet verified by runtime evidence. Resolve endpoint/page/action before using PoC.'
    if prefix not in finding.summary:
        finding.summary = f'{prefix} {finding.summary}'
    _add_unique(finding.verification_notes, 'Manual review candidate')
    _add_unique(finding.verification_notes, 'Not yet verified by runtime evidence')
    _add_unique(finding.verification_notes, 'Resolve endpoint/page/action before using PoC')
    _add_unique(finding.verification_notes, 'Needs runtime capture before proof')
    if finding.observational_poc:
        if not finding.observational_poc.description.startswith('Manual review candidate'):
            finding.observational_poc.description = f'Manual review candidate (runtime evidence needed): {finding.observational_poc.description}'
        precondition = 'Endpoint/page/action manually confirmed before use'
        if precondition not in finding.observational_poc.preconditions:
            finding.observational_poc.preconditions.insert(0, precondition)
        step = 'Manually confirm endpoint/page/action before using observational PoC'
        if step not in finding.observational_poc.steps:
            finding.observational_poc.steps.insert(0, step)


def _first_evidence_location(finding: ReadableFinding) -> tuple[str, int, int, str]:
    if finding.evidence:
        ev = finding.evidence[0]
        return ev.source_path, ev.start_line, ev.end_line, ev.snippet
    source_path = finding.affected_files[0] if finding.affected_files else 'UNKNOWN'
    return source_path, 1, 1, ''


def _api_call_or_sink(method: str, endpoint: str, sink: str) -> str:
    if endpoint and endpoint != 'UNKNOWN':
        return f'{method} {endpoint}'.strip()
    if sink:
        return sink
    return 'UNKNOWN'


def _build_contract_fields(
    finding: ReadableFinding,
    method: str,
    endpoint: str,
    sink: str,
    function_name: str | None,
    page_hint: str,
    action_hint: str,
    api_match: ApiCallCandidate | None,
) -> dict:
    source_path, start_line, end_line, snippet = _first_evidence_location(finding)
    target = _api_call_or_sink(method, endpoint, sink)
    parameters = api_match.parameters if api_match else []
    is_dom = method == 'DOM' or 'DOM sink:' in endpoint or finding.vulnerability_type == 'DOM XSS'
    missing_guard = (
        'user input may reach DOM sink without encoding/sanitization'
        if is_dom
        else 'server-side validation cannot be confirmed from frontend source; client request values can be modified in DevTools'
    )
    why = (
        f'User-controlled DOM input reaches {target} via a source-to-sink flow in the code.'
        if is_dom
        else f'In the browser, {target} request payload/parameters can be observed before dispatch, and {", ".join(parameters) or "request values"} validation relies on client-side code.'
    )
    check = (
        f'value delivered to {target} and DOM reflection'
        if is_dom
        else f'{target} request payload/query/status/response' + (f" including parameter({', '.join(parameters)})" if parameters else '')
    )
    return {
        'vulnerability_title': finding.title,
        'source_path': source_path,
        'start_line': start_line,
        'end_line': end_line,
        'function_name': function_name or None,
        'vulnerable_code_summary': f'{source_path}:{start_line}-{end_line}: {target} flow identified',
        'why_exploitable': why,
        'data_flow': FindingDataFlow(
            user_action=action_hint,
            handler=function_name or None,
            api_call_or_sink=target,
            missing_guard_or_validation=missing_guard,
        ),
        'breakpoint_plan': BreakpointPlan(
            file=source_path,
            line=(api_match.start_line if api_match else start_line),
            function=function_name or None,
            when_to_pause='pause just before the request/DOM sink after installing PoC and triggering the vulnerable UI action',
            what_variable_or_request_to_check=check,
        ),
        'poc_injection_plan': PocInjectionPlan(
            when_to_run=(
                'before the page reads the DOM input or before refreshing the vulnerable page'
                if is_dom
                else 'before clicking the vulnerable UI action or before triggering the request'
            ),
            required_user_action=action_hint,
        ),
    }


def _apply_v1_contract(
    finding: ReadableFinding,
    method: str,
    endpoint: str,
    sink: str,
    function_name: str | None,
    page_hint: str,
    action_hint: str,
    api_match: ApiCallCandidate | None,
) -> dict:
    fields = _build_contract_fields(finding, method, endpoint, sink, function_name, page_hint, action_hint, api_match)
    for key, value in fields.items():
        setattr(finding, key, value)
    return fields


def _proof_steps(method: str, page_hint: str, action_hint: str) -> list[str]:
    if method == 'DOM':
        return ['paste PoC into Console', _format_page_step(page_hint), 'execute PoC code or reload page', 'confirm DOM sink executes']
    if method in {'POST', 'PUT', 'PATCH'}:
        return [
            _format_page_step(page_hint),
            'paste the PoC into Console',
            'approve the browser confirmation guard only in an authorized test session',
            'observe response status, content-type, and body preview in Console',
            'compare with the normal request in the Network tab',
        ]
    return [
        _format_page_step(page_hint),
        'paste the PoC into Console',
        'observe response status, content-type, and body preview in Console',
        'compare with the normal request in the Network tab',
    ]


def _success_criteria(method: str, vuln_type: str = '') -> list[str]:
    if method == 'DOM':
        return [
            'controlled input reaches the DOM sink and script executes (console.log fires) or clear DOM mutation is observed',
            'OR sanitizer/encoding blocks execution and DOM output is safely escaped',
        ]
    cat = _category_for(vuln_type)
    if cat == 'payment_or_value_mutation':
        return [
            'mutated amount/price/quantity/point value is reflected in server-side result, balance, order record, or transaction state',
            'OR server explicitly rejects the mutation with a clear validation or authorization error (not just a generic 5xx)',
        ]
    if cat == 'idor_bola':
        return [
            'server returns object/user/order data belonging to another user or session',
            'OR server rejects with 401/403 or an explicit object-ownership validation error',
        ]
    if cat == 'account_recovery':
        return [
            'invalid, reused, or brute-forced verification code is accepted by the server',
            'OR reset token is not bound to the requesting user/session/action',
            'OR server rejects invalid flow with rate-limit or token-binding evidence',
        ]
    if cat in ('role_or_state_mutation', 'authorization'):
        return [
            'mutated role/status/state value is accepted or persisted by the server',
            'OR server rejects the change with an explicit authorization or state-transition validation error',
        ]
    if cat == 'client_side_validation':
        return [
            'server accepts the request with a manipulated parameter value that should have been rejected client-side',
            'OR server enforces the constraint and rejects with a clear validation error',
        ]
    return [
        'server response to the manipulated request differs meaningfully from the normal request (different data, status, or behavior)',
        'OR server enforces expected access control and rejects the manipulation with an authorization/validation error',
    ]


def _failure_criteria(method: str, vuln_type: str = '') -> list[str]:
    if method == 'DOM':
        return [
            'input is safely encoded before reaching the sink and script does not execute',
            'DOM sink is not invoked by the controlled source',
            'sanitizer strips the payload before assignment',
        ]
    cat = _category_for(vuln_type)
    if cat == 'payment_or_value_mutation':
        return [
            'server validates the amount/price server-side and rejects the manipulated value',
            'response shows the original server-enforced value, not the client-supplied one',
        ]
    if cat == 'idor_bola':
        return [
            'server rejects with 403 and an explicit ownership or authorization error',
            'response contains only data belonging to the requesting user/session',
        ]
    if cat == 'account_recovery':
        return [
            'server rejects invalid/reused verification codes with rate-limiting or an explicit binding error',
            'reset token is scoped to the requesting user/session and cannot be replayed',
        ]
    if cat in ('role_or_state_mutation', 'authorization'):
        return [
            'server enforces the role/state transition server-side and rejects the unauthorized change',
            'client-side guard removal does not grant access to the protected resource',
        ]
    if cat == 'client_side_validation':
        return [
            'server enforces the same constraint server-side and rejects the manipulated parameter',
            'response shows a clear validation error, not a success status',
        ]
    return [
        'server rejects with 400/401/403 and a clear validation or authorization error',
        'payload mutation is ignored or normalized before server-side processing',
        'endpoint is not reachable from the tested context',
        'HTML fallback/redirect is returned (not the expected API response)',
    ]


def _evidence_to_capture(method: str, vuln_type: str = '') -> list[str]:
    if method == 'DOM':
        return [
            'Sources tab: breakpoint location in the file where input reaches the sink',
            'Console: PoC execution log or screenshot of DOM change / script execution',
            'Screenshot: DOM mutation or alert proving payload reached the sink',
            'Call Stack: trace showing the input flowing to the sink without encoding',
        ]
    cat = _category_for(vuln_type)
    if cat == 'payment_or_value_mutation':
        return [
            'Network tab: original request (normal flow) showing expected amount/price',
            'Network tab or Console: manipulated request body showing altered amount/price',
            'Server response: showing reflected value, transaction record, or rejection message',
        ]
    if cat == 'idor_bola':
        return [
            'Network tab: request with another user/object identifier substituted',
            'Server response: showing data that should not be accessible to the current session',
            'OR server rejection with 403 and ownership-validation message',
        ]
    if cat == 'account_recovery':
        return [
            'Network tab: recovery/verification request with manipulated code or token',
            'Server response: showing acceptance or rejection of invalid/reused token',
            'Screenshot: rate-limit response or token-binding validation error',
        ]
    if cat in ('role_or_state_mutation', 'authorization'):
        return [
            'Network tab: request with manipulated role/status/state parameter',
            'Server response: showing accepted or rejected mutation with authorization details',
            'Screenshot: UI state after bypass attempt (access granted or denied)',
        ]
    if cat == 'client_side_validation':
        return [
            'Network tab: request with parameter value that violates client-side validation',
            'Server response: showing validation accepted or rejected server-side',
            'Console: PoC execution log showing the manipulated request was sent',
        ]
    return [
        'Network tab: normal request URL/method/payload for comparison baseline',
        'Console or Network tab: manipulated request payload and server response status',
        'Server response body: showing accepted manipulation or explicit rejection message',
    ]


def _find_validation_return_breakpoints(f: FileContent, candidate: ApiCallCandidate | None = None) -> list[BreakpointHint]:
    keys = ('amount', 'price', 'status', 'userid', 'orderid', 'code', 'email', 'password', 'role', 'usertype')
    hints: list[BreakpointHint] = []
    lines = f.content.splitlines() or ['']
    if candidate is not None:
        block = _find_enclosing_function_block(f.content, candidate.start_line)
        if block:
            _, begin, finish, _ = block
        else:
            begin = max(1, candidate.start_line - 80)
            finish = min(len(lines), candidate.start_line + 80)
    else:
        begin, finish = 1, len(lines)
    for idx in range(begin, finish + 1):
        line = lines[idx - 1]
        low = line.lower()
        if not any(k in low for k in keys):
            continue
        has_return_guard = bool(re.search(r'if\s*\(.*\)\s*return\b', low) or re.search(r'if\s*\(.*\)\s*\{\s*return;?\s*\}', low))
        has_alert_return = 'alert(' in low and 'return' in low
        has_throw_or_seterror = ('throw new error' in low or 'seterror' in low) and 'return' in low
        if has_return_guard or has_alert_return or has_throw_or_seterror:
            vars_found = sorted({k for k in keys if k in low})
            hints.append(BreakpointHint(
                source_path=f.path,
                start_line=idx,
                end_line=idx,
                reason='check client-side validation branch',
                watch_variables=vars_found,
            ))
    return hints


class ConsolePocAnalyzer(ABC):
    @abstractmethod
    def analyze(self, files: list[FileContent], project_map=None) -> list[ReadableFinding]:
        raise NotImplementedError


class MockConsolePocAnalyzer(ConsolePocAnalyzer):
    """Pattern-based fallback for tests and offline validation only.

    Production-quality reasoning should use GeminiConsolePocAnalyzer with
    structured API candidates.
    """
    def analyze(self, files: list[FileContent], project_map=None) -> list[ReadableFinding]:
        findings: list[ReadableFinding] = []
        missing_deps = detect_missing_dependencies(files)
        handler_candidates = extract_ui_handler_candidates(files)
        api_candidates_all = extract_api_call_candidates(files).candidates
        for f in files:
            c = f.content
            if _is_build_or_third_party_path(f.path, c):
                continue
            c_lower = c.lower()
            file_handlers = [h for h in handler_candidates if h.get('source_path') == f.path]
            has_disabled_expr = any(h.get('ui_event') == 'disabled' and h.get('disabled_expression') for h in file_handlers)
            has_ui_event_handler = any(h.get('ui_event') in {'onClick', 'onSubmit'} and h.get('handler_name') for h in file_handlers)
            file_api_candidates = [c for c in api_candidates_all if c.source_path == f.path]
            if has_disabled_expr and has_ui_event_handler and bool(file_api_candidates):
                disabled_item = next((h for h in file_handlers if h.get('ui_event') == 'disabled' and h.get('disabled_expression')), None)
                event_item = next((h for h in file_handlers if h.get('ui_event') in {'onClick', 'onSubmit'} and h.get('handler_name')), None)
                endpoint_item = file_api_candidates[0]
                findings.append(ReadableFinding(
                    id=self._id(f.path + 'd'),
                    title='disabled UI bypass verification required',
                    vulnerability_type='Client-side Validation Bypass',
                    severity='low',
                    confidence='low',
                    affected_files=[f.path],
                    summary='disabled UI restriction may be bypassed via Console/DevTools; manual verification required',
                    evidence=[ReadableEvidence(source_path=f.path, start_line=1, end_line=min(20, len(c.splitlines()) or 1), snippet='\n'.join((c.splitlines() or [''])[:20]), reason='disabled UI condition detected', data_flow=[
                        'source -> state/storage -> sink',
                        f"ui_event: {event_item.get('ui_event') if event_item else 'unknown'}",
                        f"disabled_expression: {disabled_item.get('disabled_expression') if disabled_item else ''}",
                        f"handler: {event_item.get('handler_name') if event_item else ''}",
                        f"endpoint: {endpoint_item.endpoint}",
                    ])],
                    attack_scenario=['remove disabled attribute and click'],
                    impact='client-side constraint bypass possible',
                    root_cause='UI attribute-based restriction',
                    remediation='enforce server-side validation',
                    verification_notes=['confirm whether removing disabled attribute alone is sufficient to bypass'],
                    verification_playbook=_build_playbook(f, candidate=endpoint_item, disabled=True),
                ))
            if (
                any(x in c_lower for x in ('usertype', 'role', 'isadmin'))
                and 'admin' in c_lower
                and any(x in c_lower for x in ('navigate', '관리자 권한', 'requireauth'))
            ):
                findings.append(self._mk_auth_bypass(f, files, missing_deps))
            if 'innerhtml' in c_lower and any(x in c_lower for x in ('location', 'document.url', 'input.value', 'postmessage')):
                dom = self._mk_dom_xss(f)
                if dom is not None:
                    findings.append(dom)
            if any(x in c_lower for x in ('axios.', 'fetch(', 'apiclient.', 'request.', 'httpclient.', 'client.', '$.ajax', 'jquery.ajax', 'formdata')):
                for cand in extract_api_call_candidates([f]).candidates:
                    if cand.sink.startswith(('axios', 'fetch', '$.ajax', 'apiClient', 'request', 'httpClient', 'client')):
                        finding = self._mk_validation_bypass(f, candidate=cand)
                        if finding is not None:
                            findings.append(finding)
        findings = _dedup_findings(findings)
        self.last_debug = AiAnalysisDebug(
            backend='mock',
            configured=True,
            called=True,
            call_count=1,
            candidate_count=len(files),
            raw_item_count=len(findings),
            accepted_item_count=len(findings),
            dropped_item_count=0,
        )
        return findings

    def _id(self, seed: str) -> str:
        return hashlib.sha256(seed.encode()).hexdigest()[:12]



    def _replace_endpoint_placeholders(self, endpoint: str) -> str:
        if self._is_base_variable_endpoint(endpoint):
            return endpoint
        return self._replace_path_placeholders(endpoint)

    def _replace_path_placeholders(self, endpoint: str) -> str:
        endpoint = re.sub(r'\{(?:userId|currentUserId|sessionData\.userId)\}', 'TEST_USER_ID', endpoint, flags=re.IGNORECASE)
        endpoint = re.sub(r'\{(?:orderId|orderNo|auctionItem\.orderId)\}', 'TEST_ORDER_ID', endpoint, flags=re.IGNORECASE)
        endpoint = re.sub(r'\{(?:item\.id|itemId|productId)\}', 'TEST_ITEM_ID', endpoint, flags=re.IGNORECASE)
        endpoint = re.sub(r'\{paymentId\}', 'TEST_PAYMENT_ID', endpoint, flags=re.IGNORECASE)
        endpoint = re.sub(r'\{[^}]+\}', 'TEST_VALUE', endpoint)
        return endpoint

    def _is_base_variable_endpoint(self, endpoint: str) -> bool:
        return bool(re.match(r'^\{?(API_BASE|BASE_URL|apiBase)\}?', endpoint))

    def _strip_base_variable(self, endpoint: str) -> str:
        value = re.sub(r'^\{?(API_BASE|BASE_URL|apiBase)\}?', '', endpoint)
        value = self._replace_path_placeholders(value)
        return value if value.startswith('/') else f"/{value.lstrip('/')}"

    def _build_payload_from_parameters(self, parameters: list[str]) -> dict:
        payload = {}
        for key in parameters:
            kl = key.lower()
            if kl in {'amount', 'price', 'totalamount', 'usepoints', 'point', 'points', 'balance'}:
                payload[key] = 1
            elif kl in {'userid', 'currentuserid', 'memberid', 'accountid'}:
                payload[key] = 'TEST_USER_ID'
            elif kl in {'orderid', 'orderno'}:
                payload[key] = 'TEST_ORDER_ID'
            elif kl in {'productid', 'itemid'}:
                payload[key] = 'TEST_ITEM_ID'
            elif kl == 'paymentid':
                payload[key] = 'TEST_PAYMENT_ID'
            elif kl == 'merchant_uid':
                payload[key] = 'TEST_MERCHANT_UID'
            elif kl == 'imp_uid':
                payload[key] = 'TEST_IMP_UID'
            elif kl == 'status':
                payload[key] = 'TEST_STATUS'
            elif kl in {'role', 'usertype'}:
                payload[key] = 'TEST_ROLE'
            elif kl == 'email':
                payload[key] = 'test@example.com'
            elif kl in {'verificationcode', 'code'}:
                payload[key] = 'TEST_CODE'
            else:
                payload[key] = 'TEST_VALUE'
        return payload

    def _is_irreversible_or_high_risk(self, method: str, endpoint: str, parameters: list[str]) -> bool:
        if method.upper() == 'DELETE':
            return True
        hay = f"{endpoint.lower()} {' '.join(p.lower() for p in parameters)}"
        return any(k in hay for k in ('delete', 'remove', 'withdraw', 'transfer', 'refund', 'bulk', 'cancel-all', 'admin/delete'))

    def _ev(self, f: FileContent, reason: str) -> list[ReadableEvidence]:
        if 'auth' in reason.lower():
            start_line, end_line, snippet = _extract_auth_branch_snippet(f.content)
        else:
            start_line, end_line, snippet = _extract_relevant_snippet(f.content, AUTH_SNIPPET_KEYS)
        return [
            ReadableEvidence(
                source_path=f.path,
                start_line=start_line,
                end_line=end_line,
                snippet=snippet,
                reason=reason,
                data_flow=['source -> state/storage -> sink'],
            )
        ]

    def _mk_auth_bypass(self, f: FileContent, all_files: list[FileContent], missing_deps: list[str]) -> ReadableFinding:
        has_storage_evidence = _has_storage_auth_evidence(all_files, f)
        needs_manual_validation = bool(missing_deps) or not has_storage_evidence
        poc_code: str | None = None
        if has_storage_evidence and not missing_deps:
            # Detect the actual storage key and pattern from the source.
            content_low = f.content.lower()
            storage = 'localStorage' if ('localstorage' in content_low and 'sessionstorage' not in content_low) else 'sessionStorage'

            # Look for getItem('key') to determine the storage key.
            key_m = re.search(
                r'(?:sessionStorage|localStorage)\.getItem\s*\([\'"]([^\'"]+)[\'"]',
                f.content, re.IGNORECASE,
            )
            detected_key = key_m.group(1) if key_m else None

            if detected_key and detected_key.lower() in {'user', 'userinfo', 'authuser', 'currentuser'}:
                # JSON-object key: the value is JSON.parse'd and has a field like userType.
                poc_code = build_storage_auth_poc(storage, detected_key, 'userType', 'ADMIN')
            elif detected_key and detected_key.lower() in {'usertype', 'user_type', 'role', 'user_role'}:
                # Plain-string key: the value is a raw string like 'ADMIN'.
                val_js = json.dumps('ADMIN')
                poc_code = f"{storage}.setItem({json.dumps(detected_key)}, {val_js}); location.reload();"
            else:
                # Key unknown or ambiguous: do not generate a potentially wrong PoC.
                poc_code = None
        verification_notes = []
        if needs_manual_validation:
            verification_notes.extend([
                'auth value storage/read location not confirmed: Console PoC not generated',
                'requireAuth/checkSession implementation file needs manual confirmation',
                'sessionStorage/localStorage manipulation PoC is not confirmed by current code evidence',
            ])
        verification_notes.extend([f'{d} implementation file missing from ZIP; requireAuth behavior cannot be confirmed' for d in missing_deps])

        if needs_manual_validation:
            poc_code = """(() => {
  const originalFetch = window.fetch;
  window.fetch = async function(input, init = {}) {
    const url = input;
    const options = init || {};
    const target = String(url).toLowerCase();
    if (target.includes('session') || target.includes('auth') || target.includes('user')) {
      console.group('[PoC] auth/session request observed');
      console.log('URL:', url);
      console.log('Method:', options.method || 'GET');
      console.log('Credentials:', options.credentials || null);
      console.log('Body:', options.body || null);
      console.groupEnd();
    }
    return originalFetch.call(this, input, init);
  };
  console.log('[PoC] fetch hook installed. Perform a normal login/page navigation and check Console logs.');
})();"""

        return ReadableFinding(
            id=self._id(f.path + 'a'),
            title='client-side auth value manipulation may bypass access control',
            vulnerability_type='Client-side Authorization Bypass',
            severity=_auth_bypass_severity(f.content),
            confidence=('low' if needs_manual_validation else 'medium'),
            affected_files=[f.path],
            summary=('client-side storage-based auth branch detected' if not needs_manual_validation else 'client-side auth branch bypass possible but needs manual confirmation'),
            evidence=self._ev(f, 'auth branch evidence'),
            console_poc=ConsoleSafePoc(
                poc_type='browser_console',
                description='check session storage manipulation',
                preconditions=['logged-in session'],
                steps=['run in Console', 'execute the code', 'reload the page'],
                code=poc_code,
                expected_result='confirm UI branch change',
                safety='observes existing requests without creating new ones',
            ),
            attack_scenario=['storage value manipulation'],
            impact='client-side control bypass possible',
            root_cause='relies on client-side state',
            remediation='enforce server-side authorization',
            verification_notes=verification_notes,
            verification_playbook=_build_playbook(f, auth=True),
        )

    def _mk_dom_xss(self, f: FileContent) -> ReadableFinding | None:
        if any(x in f.path.lower() for x in ('jquery-ui.js', 'jquery.fullpage.js', 'jquery.selectbox.js', '/vendor/', '/vendors/', '/plugins/')):
            return None
        flow = _find_dom_xss_flow(f.content)
        if flow is None:
            return None
        start_line, end_line, snippet = flow
        # Detect the source expression from the snippet for a more targeted PoC.
        src_expr = 'location.hash'
        snip_low = snippet.lower()
        if 'location.search' in snip_low:
            src_expr = 'location.search'
        elif 'postmessage' in snip_low or 'event.data' in snip_low:
            src_expr = 'postMessage/event.data'
        poc_code = build_dom_xss_poc(source_expr=src_expr)
        return ReadableFinding(
            id=self._id(f.path + 'x'),
            title='user-controlled input may reach DOM sink',
            vulnerability_type='DOM XSS',
            severity='high',
            confidence='medium',
            affected_files=[f.path],
            summary='user-controlled input may reach a dangerous DOM sink',
            evidence=[ReadableEvidence(
                source_path=f.path, start_line=start_line, end_line=end_line,
                snippet=snippet, reason='source-sink flow confirmed by static pattern',
                data_flow=[
                    f'source: {src_expr} (line {start_line})',
                    'sink: innerHTML / DOM sink (line ' + str(end_line) + ')',
                    'method: DOM', 'endpoint: DOM sink: innerHTML', 'sink: innerHTML',
                ],
            )],
            console_poc=ConsoleSafePoc(
                poc_type='browser_console',
                description='Single-line direct PoC - no setup required',
                preconditions=['page is accessible in the browser'],
                steps=[
                    'Open browser DevTools Console on the target page',
                    'Paste the PoC code and press Enter',
                    'Observe whether the payload executes (console.log fires)',
                ],
                code=poc_code,
                expected_result='console.log(1) fires, confirming script execution via the DOM sink',
                safety='non-destructive: uses console.log, not alert or data-exfiltration',
            ),
            attack_scenario=['user controls external input', 'input reaches DOM sink without encoding'],
            impact='arbitrary script execution possible in victim browser',
            root_cause='missing input validation/encoding before DOM sink assignment',
            remediation='use safe DOM API (textContent) or DOMPurify sanitizer',
        )

    def _classify_api_candidate(self, candidate: ApiCallCandidate, source_path: str = '') -> dict[str, str]:
        endpoint_l = (candidate.endpoint or '').lower()
        method = (candidate.method or 'UNKNOWN').upper()
        params_l = [p.lower() for p in (candidate.parameters or [])]
        sink_l = (candidate.sink or '').lower()

        payment_keys = {'wallet', 'charge', 'point', 'payment', 'pay', 'iamport', 'stripe', 'amount', 'totalamount', 'usepoints', 'merchant_uid', 'imp_uid'}
        idor_keys = {'userid', 'memberid', 'accountid', 'orderid', 'productid', 'itemid'}
        state_keys = {'status', 'role', 'usertype', 'isadmin', 'authlevel'}
        recovery_keys = {'password', 'reset', 'verify', 'verification', 'code'}

        endpoint_tokens = set(re.findall(r'[a-zA-Z_]+', endpoint_l))
        if (method in {'POST', 'PUT', 'PATCH', 'DELETE'}) and (payment_keys & (endpoint_tokens | set(params_l))):
            return {
                'vulnerability_type': 'Payment/Point Manipulation Candidate',
                'title': 'payment/point request parameter manipulation possible',
                'impact': 'payment/point business logic abuse possible',
                'root_cause': 'request controlled by client-side parameters',
                'remediation': 'strengthen server-side amount/point/payment parameter validation',
                'severity': 'high' if method in {'POST', 'PUT', 'PATCH', 'DELETE'} else 'medium',
            }
        if method == 'GET' and (idor_keys & (endpoint_tokens | set(params_l))):
            return {
                'vulnerability_type': 'IDOR / Unauthorized Data Access Candidate',
                'title': 'access control check required for identifier-based query',
                'impact': 'unauthorized access to other user data possible',
                'root_cause': 'authorization uncertain for identifier-based query',
                'remediation': 'apply server-side object-level authorization',
                'severity': 'medium',
            }
        if method in {'POST', 'PUT', 'PATCH', 'DELETE'} and (state_keys & (endpoint_tokens | set(params_l))):
            return {
                'vulnerability_type': 'State/Status Manipulation Candidate',
                'title': 'state/auth change request manipulation possible',
                'impact': 'authorization/state value forgery possible',
                'root_cause': 'server validation uncertain for client-controlled values',
                'remediation': 'strengthen server validation and audit logging for state/auth change API',
                'severity': 'high',
            }
        if 'verify-identity' in endpoint_l and 'findpassword' not in source_path.lower():
            return {
                'vulnerability_type': 'Identity Verification / Action Authorization Bypass Candidate',
                'title': 'identity/action verification flow bypass needs confirmation',
                'impact': 'unauthorized action possible if identity/action verification is bypassed',
                'root_cause': 'server validation uncertain for identity/action verification flow',
                'remediation': 'enforce server-side action/identity verification and re-validate tokens',
                'severity': 'high',
            }
        if recovery_keys & endpoint_tokens:
            return {
                'vulnerability_type': 'Account Recovery Flow Abuse Candidate',
                'title': 'account recovery/verification code flow needs confirmation',
                'impact': 'account recovery flow abuse possible',
                'root_cause': 'server validation uncertain for recovery/verification code flow',
                'remediation': 'strengthen rate-limiting/token validation for recovery/code verification API',
                'severity': 'medium',
            }
        if method in {'POST', 'PUT', 'PATCH', 'DELETE'}:
            return {
                'vulnerability_type': 'Client-side Validation Bypass',
                'title': 'request mutation via client-side validation value manipulation possible',
                'impact': 'business logic abuse possible',
                'root_cause': 'relies on client-side validation',
                'remediation': 'enforce server-side validation',
                'severity': 'medium',
            }
        return {
            'vulnerability_type': 'Generic API Review Candidate',
            'title': 'API request candidate requires manual review',
            'impact': 'request flow abuse possible',
            'root_cause': 'cannot confirm server validation from frontend source alone',
            'remediation': 'cross-check backend authorization/validation policy',
            'severity': 'low',
        }

    def _mk_validation_bypass(self, f: FileContent, candidate: ApiCallCandidate) -> ReadableFinding | None:
        endpoint = candidate.endpoint or 'UNKNOWN'
        if candidate.parameters:
            parameters = candidate.parameters
        elif (candidate.method or 'UNKNOWN').upper() == 'GET':
            parameters = []
        else:
            parameters = _extract_validation_parameters(candidate.snippet or '')
        method = (candidate.method or 'UNKNOWN').upper()
        sink = candidate.sink or 'UNKNOWN'
        if sink in {'$.ajax', 'jQuery.ajax'} and endpoint == 'UNKNOWN' and any('generic ajax wrapper requires callsite tracing' in n for n in (candidate.notes or [])):
            return None

        block = _find_enclosing_function_block(f.content, candidate.start_line)
        function_name = block[0] if block else None
        flow = ['source -> state/storage -> sink', f'method: {method}', f'endpoint: {endpoint}']
        if function_name:
            flow.append(f'function: {function_name}')
        for k in parameters:
            flow.append(f'parameter: {k}')
        flow.append(f'sink: {sink}')

        ev = [ReadableEvidence(
            source_path=f.path,
            start_line=candidate.start_line,
            end_line=candidate.end_line,
            snippet=candidate.snippet,
            reason='validation value + API call combination',
            data_flow=flow,
        )]

        notes: list[str] = []
        conf = 'low'
        poc_type = 'manual_check'
        poc_code = None
        safety = 'does not perform actual state-changing requests'
        page_hint, action_hint, function_name = _infer_page_action_hints(f.path, candidate.snippet, function_name=function_name)
        page_hint, action_hint, _, _ = infer_interaction_context(
            source_path=f.path,
            function_name=function_name,
            snippet=candidate.snippet or '',
            endpoint=endpoint,
            method=method,
            parameters=parameters,
            surrounding_block=block[3] if block else '',
            ui_candidates=None,
        )

        if endpoint == 'UNKNOWN':
            notes.append('endpoint variable requires manual review')

        important_get = (
            any(k in endpoint.lower() for k in ('session', 'auth', 'me', 'profile', 'wallet', 'order'))
            or any(p.lower() in {'userid', 'memberid', 'accountid', 'orderid', 'paymentid'} for p in parameters)
            or any('endpoint variable requires manual review' in n for n in (candidate.notes or []))
        )

        # Unimportant GETs are always skipped, regardless of action inference.
        if method == 'GET' and (endpoint == 'UNKNOWN' or not important_get):
            return None

        action_is_generic = (action_hint == 'target action')
        if action_is_generic:
            notes.append('Not a runnable proof yet: user action could not be inferred from source code')
            notes.append('Confirm the page and triggering user action manually before using any PoC')

        # Normalize the endpoint: strip leading base-URL variable so
        # {API_BASE_URL}/login -> /login before passing to the PoC builder.
        norm_ep = normalize_endpoint(endpoint) if endpoint != 'UNKNOWN' else 'UNKNOWN'

        # Build a direct PoC when:
        #   (a) action hint is concrete, OR
        #   (b) function_name is known even if action hint is generic
        #       (the PoC is self-contained; button text isn't needed).
        # Exception: bare calls with no function context stay manual_plan.
        has_concrete_context = not action_is_generic or (function_name is not None)

        # Build the shortest possible self-contained PoC using poc_templates.
        if has_concrete_context:
            if method == 'DELETE' or self._is_irreversible_or_high_risk(method, norm_ep, parameters):
                notes.append('High-risk endpoint: observe-only, no replay PoC generated.')
                poc_code = None
            elif method == 'GET' and norm_ep != 'UNKNOWN' and important_get:
                direct = build_request_replay_poc(method, norm_ep)
                if direct:
                    poc_type = 'browser_console'
                    poc_code = direct
                    conf = 'medium'
                    safety = 'Read-only GET request. Inspect response status/body only.'
            elif method in {'POST', 'PUT', 'PATCH'} and norm_ep != 'UNKNOWN':
                primary = next(
                    (p for p in parameters
                     if p.lower() in {'amount', 'price', 'totalamount', 'usepoints', 'status', 'code', 'role', 'userid', 'orderid'}),
                    parameters[0] if parameters else '',
                )
                test_val: int | str = 1 if primary.lower() in {'amount', 'price', 'totalamount', 'usepoints'} else 'TEST_VALUE'
                direct = build_request_replay_poc(method, norm_ep, primary, test_val, fields=parameters)
                if direct:
                    poc_type = 'browser_console'
                    poc_code = direct
                    conf = 'medium'
                    safety = 'Browser confirmation guard blocks execution until the tester approves it in an authorized test environment.'
                    notes.append('Approve the browser confirmation guard only in an isolated authorized test environment.')

        is_direct_poc = poc_code is not None and is_interceptor_free(poc_code)
        # An executable status requires a concrete (possibly normalized) endpoint.
        poc_gen_status = (
            'executable' if is_direct_poc and norm_ep not in ('UNKNOWN', '')
            else 'manual_plan' if (endpoint == 'UNKNOWN' or not poc_code)
            else 'observational'
        )
        if is_direct_poc:
            steps = [
                'Open browser DevTools Console on the target page',
                'Paste the PoC code and press Enter',
                'For mutation PoCs: approve the browser confirmation guard only after explicit authorization',
                'Observe the response status in the Console output',
            ]
            description = 'Direct self-contained PoC - no helper installation required'
            expected = 'Server responds with 200/201 or meaningful error; compare payload before/after.'
        else:
            steps = [
                _review_page_step(page_hint),
                'Identify the request in the browser Network tab (URL, method, payload)',
                'Set a breakpoint in DevTools Sources at the call site',
                f"Perform action: {_english_review_hint(action_hint, 'target action')}",
                'Check request payload and server response status',
            ]
            description = 'Discovery aid - install and observe, then build direct PoC from captured data'
            expected = 'Captured request data is visible in Console; use payload values to construct a direct PoC.'

        classification = self._classify_api_candidate(candidate, source_path=f.path)
        return ReadableFinding(
            id=self._id(f"{f.path}:{method}:{endpoint}:{sink}:{','.join(sorted(parameters))}:{classification['vulnerability_type']}"),
            title=classification['title'],
            vulnerability_type=classification['vulnerability_type'],
            severity=classification['severity'],
            confidence=conf,
            affected_files=[f.path],
            summary='Potential request value manipulation before transmission.',
            evidence=ev,
            console_poc=ConsoleSafePoc(
                poc_type=poc_type,
                description=description,
                preconditions=['Approved test account', 'Test data or test order'],
                steps=steps,
                code=poc_code,
                expected_result=expected,
                safety=safety,
            ),
            attack_scenario=['parameter manipulation'],
            impact=classification['impact'],
            root_cause=classification['root_cause'],
            remediation=classification['remediation'],
            verification_notes=notes,
            verification_playbook=_build_playbook(f, candidate=candidate, page_hint=page_hint, action_hint=action_hint, function_name=function_name),
            poc_generation_status=poc_gen_status,
            poc_generation_reason=(
                'endpoint unknown' if endpoint == 'UNKNOWN'
                else 'Not a runnable proof yet: user action could not be resolved' if action_is_generic
                else 'direct CONFIRM-guarded replay PoC' if is_direct_poc
                else 'endpoint/method available; interceptor discovery aid assigned'
            ),
            observational_poc=None,
            manual_poc_plan=(_build_manual_poc_plan(f.path, function_name, endpoint, method) if (endpoint == 'UNKNOWN' or action_is_generic) else []),
        )



class GeminiConsolePocAnalyzer(ConsolePocAnalyzer):
    def __init__(self, client: GeminiClientProtocol):
        self.client = client
        self.last_debug = AiAnalysisDebug(backend='gemini')

    def analyze(self, files: list[FileContent], project_map=None) -> list[ReadableFinding]:
        def _summary(item: dict) -> dict:
            evidence = item.get('evidence') or []
            ev0 = evidence[0] if isinstance(evidence, list) and evidence and isinstance(evidence[0], dict) else {}
            return {
                'title': item.get('title'),
                'vulnerability_type': item.get('vulnerability_type'),
                'severity': item.get('severity'),
                'source_path': ev0.get('source_path'),
            }

        def _drop(index: int | None, stage: str, reason: str, item: dict | None = None) -> None:
            self.last_debug.dropped_item_count += 1
            self.last_debug.drop_reasons.append(
                AnalysisDebugDropReason(index=index, stage=stage, reason=reason[:240], item_summary=(_summary(item) if item else None))
            )

        def _ensure_finding_id(item: dict) -> None:
            if item.get('id'):
                return
            evidence = item.get('evidence') or []
            ev0 = evidence[0] if isinstance(evidence, list) and evidence else {}
            seed = "|".join([
                str(item.get('vulnerability_type', '')),
                str(item.get('title', '')),
                ",".join(item.get('affected_files') or []),
                str(ev0.get('source_path', '')) if isinstance(ev0, dict) else '',
                str(ev0.get('start_line', '')) if isinstance(ev0, dict) else '',
                str(item.get('root_cause', '')),
            ])
            item['id'] = hashlib.sha256(seed.encode()).hexdigest()[:12]

        safe_files = [f for f in files if not _is_build_or_third_party_path(f.path, f.content)]
        candidates = extract_api_call_candidates(safe_files).candidates
        self.last_debug = AiAnalysisDebug(
            backend='gemini',
            model=getattr(self.client, 'model', None),
            configured=bool(self.client),
            called=False,
            candidate_count=len(candidates),
        )
        self.last_debug.called = True
        self.last_debug.call_count += 1
        try:
            project_map = project_map or build_project_understanding(safe_files)
            raw_text = self.client.analyze(build_candidate_analysis_prompt(safe_files, candidates, project_map))
        except Exception as exc:
            self.last_debug.errors.append(f'call failed: {type(exc).__name__}')
            return []
        payload = extract_json_payload(raw_text)
        if payload is None or not isinstance(payload.get('findings'), list):
            self.last_debug.errors.append('parse failed: Gemini response was not valid JSON findings payload')
            return []

        out: list[ReadableFinding] = []
        items = payload['findings']
        self.last_debug.raw_item_count = len(items)
        for idx, item in enumerate(items):
            if not isinstance(item, dict):
                _drop(idx, 'shape', 'Item is not a dict')
                continue
            if item.get('severity') not in ALLOWED_SEVERITIES or item.get('confidence') not in ALLOWED_CONFIDENCES:
                _drop(idx, 'shape', 'Invalid severity/confidence', item)
                continue
            if not isinstance(item.get('evidence'), list) or not item['evidence']:
                _drop(idx, 'shape', 'Missing evidence', item)
                continue
            if not isinstance(item.get('attack_scenario'), list) or not item['attack_scenario']:
                _drop(idx, 'shape', 'Missing attack_scenario', item)
                continue

            poc = item.get('console_poc')
            if isinstance(poc, dict):
                if poc.get('poc_type') not in ALLOWED_POC_TYPES:
                    _drop(idx, 'shape', 'Invalid console_poc type', item)
                    continue
                code = (poc.get('code') or '').lower()
                if any(x in code for x in DANGEROUS_POC_PATTERNS) or not _is_allowed_guarded_poc_code(code):
                    poc['code'] = None
                    notes = item.get('verification_notes') or []
                    notes.append('potentially dangerous request detected: Console PoC code removed')
                    item['verification_notes'] = notes
                    self.last_debug.errors.append('safety: Dangerous Console PoC code removed')

            poc_code = poc.get('code') or '' if isinstance(poc, dict) else ''
            if poc_code and not is_interceptor_free(poc_code):
                poc['code'] = None

            try:
                _ensure_finding_id(item)
                out.append(ReadableFinding(**item))
                self.last_debug.accepted_item_count += 1
            except Exception as exc:
                _drop(idx, 'validation', f'ReadableFinding validation failed: {type(exc).__name__}: {str(exc)[:120]}', item)
                continue
        return out


def _build_playbook_poc(
    vuln_type: str,
    method: str,
    endpoint: str,
    parameters: list[str],
) -> 'str | None':
    """
    Return the shortest self-contained PoC code suitable for the playbook
    console_code field.

    - DOM XSS: 1-2 line template PoC.
    - API mutation with concrete endpoint: CONFIRM-guarded direct fetch.
    - Fallback (dynamic/unknown endpoint): SSS_POC capture flow.
    """
    if vuln_type == 'DOM XSS':
        return build_dom_xss_poc()

    if vuln_type == 'Client-side Authorization Bypass':
        return build_storage_auth_poc()

    # Normalize before passing to the replay builder so base-URL prefixes and
    # path params are handled correctly.
    norm_ep = normalize_endpoint(endpoint) if endpoint and endpoint != 'UNKNOWN' else endpoint
    if norm_ep and norm_ep != 'UNKNOWN':
        primary = next(
            (p for p in parameters
             if p.lower() in {'amount', 'price', 'totalamount', 'usepoints', 'status', 'code', 'userid', 'orderid'}),
            parameters[0] if parameters else '',
        )
        test_val: int | str = 1 if primary.lower() in {'amount', 'price', 'totalamount', 'usepoints'} else 'TEST_VALUE'
        direct = build_request_replay_poc(method, norm_ep, primary, test_val, fields=parameters)
        if direct:
            return direct

    # No self-contained PoC could be built; caller handles None correctly.
    return None


def get_console_poc_analyzer() -> ConsolePocAnalyzer:
    backend = settings.ANALYZER_BACKEND.lower()
    if backend == 'mock':
        return MockConsolePocAnalyzer()
    if backend == 'gemini':
        return GeminiConsolePocAnalyzer(GeminiClient(settings.GEMINI_API_KEY, settings.GEMINI_MODEL))
    raise ValueError(f'Unsupported readable analysis backend: {settings.ANALYZER_BACKEND}')



def _compute_common_helper(
    playbooks: list,
    review_candidates: list,
) -> 'str | None':
    """Return the common_console_helper only when at least one playbook or
    observational review candidate actually needs it (i.e. references SSS_POC).
    Otherwise return None so the UI does not show a 226-line block."""
    for pb in playbooks:
        code = pb.console_code or ''
        if 'window.SSS_POC.find(' in code or any(sig in code for sig in INTERCEPTOR_SIGS):
            return _build_common_console_helper()
    for rc in review_candidates:
        if rc.poc_generation_status == 'observational':
            return _build_common_console_helper()
    return None


def _find_unresolved_poc_placeholders(*values: str | None) -> list[str]:
    found: list[str] = []
    tracked_placeholders = [p for p in UNRESOLVED_POC_PLACEHOLDERS if p != 'UNKNOWN']
    for value in values:
        text = str(value or '')
        stripped = text.strip()
        if stripped == 'UNKNOWN' or re.fullmatch(r'(GET|POST|PUT|PATCH|DELETE|DOM)\s+UNKNOWN', stripped, flags=re.IGNORECASE):
            found.append('UNKNOWN')
        for placeholder in tracked_placeholders:
            if placeholder in text and placeholder not in found:
                found.append(placeholder)
        for placeholder in re.findall(r'\{(?:API_BASE_URL|API_BASE|BASE_URL|apiBase|userId|sessionData\.userId|auctionItem\.orderId|orderId|test_[^}]+)\}', text):
            if placeholder not in found:
                found.append(placeholder)
        for token in ('test_user_id', 'test_order_id'):
            if re.search(rf'(?<![A-Za-z0-9_]){re.escape(token)}(?![A-Za-z0-9_])', text) and token not in found:
                found.append(token)
    return found


def analyze_console_exploitability(files: list[FileContent], analyzer: ConsolePocAnalyzer | None = None) -> ReadableAnalysisResult:
    selected = select_console_relevant_files(files)
    analyzer = analyzer or get_console_poc_analyzer()
    project_map_files = [f for f in selected if not _is_build_or_third_party_path(f.path, f.content)]
    project_map = build_project_understanding(project_map_files)
    try:
        findings = analyzer.analyze(selected, project_map=project_map)
    except TypeError:
        findings = analyzer.analyze(selected)
    verification_playbooks: list[ConsoleVerificationPlaybookSummary] = []
    executive_findings: list[ReadableFinding] = []
    review_candidates: list[ReadableFinding] = []
    seen_flow: set[tuple[str, str, str, str, str, str]] = set()
    playbook_candidates: list[tuple[int, ConsoleVerificationPlaybookSummary]] = []

    def _is_compressed_or_library_evidence(finding: ReadableFinding, function_name: str | None) -> bool:
        if not finding.evidence:
            return False
        snippet = finding.evidence[0].snippet or ''
        lines = snippet.splitlines() or [snippet]
        avg_len = sum(len(x) for x in lines) / max(1, len(lines))
        if any(len(x) >= 800 for x in lines):
            return True
        low = snippet.lower()
        signals = ('deflate', 'gzip', 'crypto', 'webpack', '__webpack_require__', 'sourcemappingurl', 'function(', 'return wa', 'constants')
        if sum(1 for s in signals if s in low) >= 2:
            return True
        fn = (function_name or '').strip()
        if 1 <= len(fn) <= 2:
            return True
        return avg_len > 240

    def _flow_and_meta(f: ReadableFinding) -> tuple[tuple[str, str, str, str, str, str], str, str, str]:
        source_path = f.evidence[0].source_path if f.evidence else (f.affected_files[0] if f.affected_files else '')
        flows = f.evidence[0].data_flow if f.evidence else []
        method = next((x.replace('method: ', '') for x in flows if x.startswith('method: ')), 'UNKNOWN')
        endpoint = next((x.replace('endpoint: ', '') for x in flows if x.startswith('endpoint: ')), 'UNKNOWN')
        sink = next((x.replace('sink: ', '') for x in flows if x.startswith('sink: ')), '')
        function_name = next((x.replace('function: ', '') for x in flows if x.startswith('function: ')), '')
        return (f.vulnerability_type, source_path, function_name, method, endpoint, sink), method, endpoint, function_name

    for f in findings:
        flow, method, endpoint, function_name = _flow_and_meta(f)
        src = flow[1]
        sink = flow[5]
        api_match = next((a for a in project_map.api_inventory if a.source_path == src and a.endpoint == endpoint and (not function_name or a.function_name == function_name)), None)
        page_obj = next((p for p in project_map.pages if p.source_path == src), None)
        ui_matches = [u.model_dump() for u in project_map.ui_events if u.source_path == src and (not function_name or u.handler_name == function_name)]
        surrounding_block = ''
        if f.evidence:
            ff = next((x for x in selected if x.path == src), None)
            if ff:
                b = _find_enclosing_function_block(ff.content, f.evidence[0].start_line)
                surrounding_block = b[3] if b else ''
        fallback_page, fallback_action, function_name = _infer_page_action_hints(src, f.evidence[0].snippet if f.evidence else '', function_name=function_name or None)
        page_hint, action_hint, _, _ = infer_interaction_context(
            src,
            function_name or None,
            f.evidence[0].snippet if f.evidence else '',
            endpoint,
            method,
            (api_match.parameters if api_match else []),
            surrounding_block,
            ui_matches or None,
        )
        if page_hint == 'target feature page' and page_obj and page_obj.page_hint:
            page_hint = page_obj.page_hint
        if page_hint == 'target feature page':
            page_hint = fallback_page
        if action_hint == 'target action':
            action_hint = fallback_action
        is_low_conf = f.confidence == 'low'
        is_disabled_only = bool(f.verification_playbook and f.verification_playbook.strategy == 'disabled_button_bypass')
        is_unknown = endpoint == 'UNKNOWN'
        no_code = not (f.console_poc and f.console_poc.code)
        ux_disabled = any(x in ' '.join(f.evidence[0].data_flow).lower() for x in ('disabled_expression: loading', 'disabled_expression: submitting', 'disabled_expression: isloading')) if f.evidence else False
        top_import_like = bool(f.evidence and f.evidence[0].start_line <= 20 and 'import ' in (f.evidence[0].snippet or '').lower())
        fn_low = (function_name or '').lower()
        explicit_action_fn = {
            'sendverificationcode', 'verifycode', 'resetpassword',
            'handlestripecheckout', 'requestiamportpay', 'handleiamportquick', 'handlepointcharge',
        }
        is_auto_fn = (
            fn_low in {
                'loaddashboarddata', 'fetchdashboard', 'loaduser', 'loaduserinfo', 'fetchuser', 'fetchme', 'fetchsession',
                'getsession', 'initdata', 'initialize', 'loadorders', 'fetchorders'
            }
            or (fn_low.startswith(('load', 'fetch', 'get', 'init', 'initialize', 'request')) and fn_low not in explicit_action_fn)
            or 'useeffect' in (f.evidence[0].snippet.lower() if f.evidence else '')
        )
        is_generic_action = _is_generic_action_hint(action_hint)
        is_generic_page = _is_generic_page_hint(page_hint)
        # Compute unresolved placeholders. When the finding already has a
        # self-contained direct PoC (interceptor-free), only the PoC code
        # matters — base-URL prefixes and REPLACE_WITH_* constants in the code
        # are not blocking. We pass the normalized endpoint (not raw) so that
        # {API_BASE_URL}/login is treated as /login (no placeholders).
        _poc_code_chk = f.console_poc.code if f.console_poc else None
        _obs_code_chk = f.observational_poc.code if f.observational_poc else None
        if _poc_code_chk and is_interceptor_free(_poc_code_chk):
            unresolved_placeholders = _find_unresolved_poc_placeholders(_poc_code_chk)
        else:
            unresolved_placeholders = _find_unresolved_poc_placeholders(
                normalize_endpoint(endpoint),
                _poc_code_chk,
                _obs_code_chk,
            )
        endpoint_norm = endpoint.lower().split('?', 1)[0].rstrip('/')
        endpoint_norm = re.sub(r'^\{api_base\}', '', endpoint_norm)
        is_session_get = method == 'GET' and (
            endpoint_norm in {'/api/user/session', '/api/auth/me', '/api/me', '/api/profile/me'}
            or endpoint_norm.endswith('/api/user/session')
        )
        is_generic_type = f.vulnerability_type == 'Generic API Review Candidate'
        is_compressed = _is_compressed_or_library_evidence(f, function_name)
        is_dom_flow = method == 'DOM' or f.vulnerability_type == 'DOM XSS'
        is_jq_html_promotable = bool(
            api_match and
            method in {'POST', 'PUT', 'PATCH'} and
            (api_match.ui_event_type or api_match.ui_event_handler or api_match.ui_event_text) and
            api_match.risk_category in {'identity_verification', 'account_recovery', 'payment', 'authorization', 'wallet_point'}
        )
        score = 0
        score_reasons: list[str] = []
        if function_name:
            score += 3
            score_reasons.append('function_block')
        else:
            score -= 3
        if api_match and (api_match.ui_event_handler or api_match.ui_event_type):
            score += 3
            score_reasons.append('ui_event_connected')
        if api_match and api_match.ui_event_text and action_hint != 'target action':
            score += 2
            score_reasons.append('ui_text_matches_action')
        if api_match and api_match.risk_category:
            score += 2
            score_reasons.append(f'endpoint_category={api_match.risk_category}')
        if api_match and any(p.lower() in {'amount', 'price', 'userid', 'orderid', 'status', 'code', 'email', 'password'} for p in (api_match.parameters or [])):
            score += 2
            score_reasons.append('sensitive_payload')
        score += 2 if action_hint != 'target action' else -2
        score += 1 if page_hint != 'target feature page' else -2
        score += 2 if endpoint != 'UNKNOWN' else -2
        score += -3 if is_generic_type else 0
        score += -3 if is_session_get else 0
        score += -3 if is_compressed else 0
        score += -2 if is_auto_fn else 0

        # A finding with a short self-contained PoC (no global hook) can be
        # promoted on proof quality alone, bypassing cosmetic hint gates.
        poc_code_val = f.console_poc.code if f.console_poc else None
        has_short_direct_poc = (
            poc_code_val is not None
            and len(poc_code_val.splitlines()) <= MAX_POC_LINES
            and is_interceptor_free(poc_code_val)
        )
        # A self-contained PoC bypasses the placeholder/function-none gates only when:
        #   - not compressed/library code (always excluded),
        #   - function_name known (auto-fns excluded), not a Generic Candidate, AND
        #   - either action hint is concrete, OR there is an explicit UI event type
        #     (e.g. onClick from a real button) so we know a real user action exists.
        # This lets {API_BASE_URL}/login+button reach the playbook while keeping
        # bare functions with no button (doRequest, doLogin) in review.
        is_confirmed_short_poc = has_short_direct_poc and not is_compressed and (
            f.vulnerability_type in {'DOM XSS', 'Client-side Authorization Bypass'}
            or (
                function_name is not None
                and not is_auto_fn
                and not is_generic_type
                and (
                    not is_generic_action
                    or (api_match is not None and api_match.ui_event_type is not None)
                )
            )
        )

        # Assign security rule category before should_review so the gate can use it.
        f.category = _VULN_TYPE_TO_CATEGORY.get(f.vulnerability_type, 'Business Logic Manipulation')

        should_review = (
            (not is_confirmed_short_poc or (score < 0 and f.category not in {'XSS', 'Admin/Role/Permission Bypass'})) and (
                is_disabled_only or is_unknown or no_code or ux_disabled or top_import_like or is_auto_fn or is_generic_type or
                bool(unresolved_placeholders) or
                is_generic_action or is_generic_page or (function_name is None and not is_jq_html_promotable and not is_dom_flow) or is_session_get or is_compressed or
                (score < PROMOTION_SCORE_THRESHOLD and not is_dom_flow) or
                (is_low_conf and f.category not in _HIGH_PRIORITY_CATEGORIES)
            )
        )
        if should_review:
            # Clear PoC code when demoting to review:
            #   - full hook codes (SSS_REVIEW_POC_STATE / TARGET_ENDPOINT)
            #   - short interceptor-free replay PoCs that have no confirmed user context
            #     (no function name, or generic action hint with no real button)
            #     so review candidates never appear to have "runnable" PoC.
            if f.console_poc and f.console_poc.code:
                code = f.console_poc.code
                is_full_hook = 'SSS_REVIEW_POC_STATE' in code or 'TARGET_ENDPOINT' in code
                is_unconfirmed_replay = (
                    is_interceptor_free(code)
                    and len(code.splitlines()) <= MAX_POC_LINES
                    and (function_name is None or is_generic_action)
                )
                if is_full_hook or is_unconfirmed_replay:
                    f.console_poc = f.console_poc.model_copy(update={'code': None})

            has_snippet = bool(f.evidence and (f.evidence[0].snippet or '').strip())
            disallow_observational = is_compressed or _is_external_or_static_endpoint(endpoint)
            # Only generate an observational hint when page, action, and endpoint are all
            # concretely resolved. Generic/unresolved cases get manual_plan only.
            resolved_context = (
                endpoint != 'UNKNOWN'
                and method != 'UNKNOWN'
                and has_snippet
                and not disallow_observational
                and not is_generic_action
                and not is_generic_page
                and not bool(unresolved_placeholders)
            )
            if resolved_context:
                f.poc_generation_status = 'observational'
                f.poc_generation_reason = 'review candidate: short capture hint (install common_console_helper first)'
                f.observational_poc = ConsoleSafePoc(
                    poc_type='browser_console',
                    description='Request capture hint - install common_console_helper first.',
                    preconditions=['common_console_helper installed', 'Approved test environment'],
                    steps=[
                        _review_page_step(page_hint),
                        f"Perform: {_english_review_hint(action_hint, 'target action')}",
                        'window.SSS_POC.list()',
                        f'window.SSS_POC.find({{ urlIncludes: {json.dumps(endpoint)}, method: {json.dumps(method)} }})',
                    ],
                    code=_build_capture_hint(endpoint, method, page_hint, action_hint),
                    expected_result=f'Captured request for {method} {endpoint} is visible in window.SSS_POC.captured.',
                    safety='Comments only - no hook installer. Requires common_console_helper to be active.',
                )
            elif endpoint == 'UNKNOWN' or method == 'UNKNOWN' or is_compressed or not has_snippet:
                f.poc_generation_status = 'manual_plan'
                f.poc_generation_reason = 'manual verification required due to unknown/compressed/insufficient evidence'
                f.manual_poc_plan = _build_manual_poc_plan(flow[1], function_name, endpoint, method)
            else:
                f.poc_generation_status = 'manual_plan'
                f.poc_generation_reason = 'Not a runnable proof yet: page/action/endpoint could not be fully resolved'
                f.observational_poc = None
            if unresolved_placeholders:
                f.poc_generation_status = 'manual_plan'
                f.poc_generation_reason = f'manual verification required: unresolved placeholder(s) {", ".join(unresolved_placeholders)}'
                f.manual_poc_plan = _extend_manual_poc_plan_for_placeholders(
                    _build_manual_poc_plan(flow[1], function_name, endpoint, method),
                    unresolved_placeholders,
                )
                f.observational_poc = None
                _add_unique(f.verification_notes, f'Unresolved placeholder blocks promotion: {", ".join(unresolved_placeholders)}')
            if is_generic_action or is_generic_page:
                _add_unique(f.verification_notes, 'Generic page/action blocks promotion')
                _add_unique(f.verification_notes, 'Not a runnable proof yet: resolve the page and user action before using any PoC')
            f.verification_notes.append(f"playbook_score={score}: {', '.join(score_reasons) if score_reasons else 'no_strong_signals'}")
            if no_code and is_unknown and 'endpoint is UNKNOWN: auto PoC not generated' not in f.verification_notes:
                f.verification_notes.append('endpoint is UNKNOWN: auto PoC not generated')
            if is_generic_action:
                f.verification_notes.append('user action could not be inferred automatically: moved to manual review')
            if is_session_get:
                f.verification_notes.append('classified as auto session/init request: excluded from playbook')
            elif api_match and api_match.risk_category == 'search_recommend':
                f.verification_notes.append('classified as auto-query/recommend API: excluded from playbook')
            elif is_auto_fn:
                f.verification_notes.append('classified as auto-query/recommend API: excluded from playbook')
            if is_compressed:
                f.verification_notes.append('classified as compressed/library code: moved to manual review')
            if is_generic_type:
                f.verification_notes.append('generic API candidate: excluded from auto playbook, moved to manual review')
            # Lifecycle status: raw_signal for heavily suppressed; review_candidate for rest
            is_raw_signal = is_generic_type or is_session_get or is_compressed or ux_disabled or is_disabled_only
            f.status = 'raw_signal' if is_raw_signal else 'review_candidate'
            _mark_review_candidate(f)
            review_candidates.append(f)
        else:
            f.status = 'runtime_verification_candidate'
            f.poc_generation_status = 'executable'
            f.poc_generation_reason = 'promoted playbook with executable verification PoC'
            f.verification_notes.append(f"playbook_score={score}: {', '.join(score_reasons) if score_reasons else 'baseline'}")
            if flow not in seen_flow:
                seen_flow.add(flow)
                executable_poc = f.console_poc
                if (not executable_poc or not executable_poc.code) and endpoint != 'UNKNOWN' and method != 'UNKNOWN':
                    executable_poc = _build_safe_network_poc(endpoint, page_hint=page_hint, action_hint=action_hint, method=method)
                if not executable_poc or not executable_poc.code:
                    f.poc_generation_status = 'manual_plan'
                    f.poc_generation_reason = 'playbook promotion blocked: missing console code'
                    f.manual_poc_plan = _build_manual_poc_plan(flow[1], function_name, endpoint, method)
                    _mark_review_candidate(f)
                    review_candidates.append(f)
                    continue
                # For short direct PoCs (DOM XSS, storage auth) the endpoint is not
                # embedded in the code, so only check the code itself for placeholders.
                if is_confirmed_short_poc:
                    executable_placeholders = _find_unresolved_poc_placeholders(executable_poc.code)
                else:
                    executable_placeholders = _find_unresolved_poc_placeholders(endpoint, executable_poc.code)
                if executable_placeholders:
                    f.poc_generation_status = 'manual_plan'
                    f.poc_generation_reason = f'playbook promotion blocked: unresolved placeholder(s) {", ".join(executable_placeholders)}'
                    f.manual_poc_plan = _extend_manual_poc_plan_for_placeholders(
                        _build_manual_poc_plan(flow[1], function_name, endpoint, method),
                        executable_placeholders,
                    )
                    _add_unique(f.verification_notes, f'Unresolved placeholder blocks promotion: {", ".join(executable_placeholders)}')
                    _mark_review_candidate(f)
                    review_candidates.append(f)
                    continue
                contract = _apply_v1_contract(
                    finding=f,
                    method=method,
                    endpoint=endpoint,
                    sink=sink,
                    function_name=function_name or None,
                    page_hint=page_hint,
                    action_hint=action_hint,
                    api_match=api_match,
                )
                playbook_console_code = _build_playbook_poc(
                    vuln_type=f.vulnerability_type,
                    method=method,
                    endpoint=endpoint,
                    parameters=(api_match.parameters if api_match else []),
                )
                pb = ConsoleVerificationPlaybookSummary(
                    id=f.id,
                    title=f.title,
                    vulnerability_title=contract['vulnerability_title'],
                    source_path=flow[1],
                    start_line=contract['start_line'],
                    end_line=contract['end_line'],
                    function_name=(function_name or None),
                    endpoint=(normalize_endpoint(endpoint) if endpoint and endpoint != 'UNKNOWN' else endpoint),
                    method=method,
                    page_hint=page_hint,
                    user_action_hint=action_hint,
                    risk_type=f.vulnerability_type,
                    confidence=f.confidence,
                    vulnerable_code_summary=contract['vulnerable_code_summary'],
                    root_cause=f.root_cause,
                    why_exploitable=contract['why_exploitable'],
                    data_flow=contract['data_flow'],
                    breakpoint_plan=contract['breakpoint_plan'],
                    poc_injection_plan=contract['poc_injection_plan'],
                    console_code=playbook_console_code,
                    setup_steps=executable_poc.steps,
                    proof_steps=_proof_steps(method, page_hint, action_hint),
                    success_criteria=_success_criteria(method, f.vulnerability_type),
                    failure_criteria=_failure_criteria(method, f.vulnerability_type),
                    evidence_to_capture=_evidence_to_capture(method, f.vulnerability_type),
                    limitations=(f.verification_playbook.limitations if f.verification_playbook else []),
                )
                if f.verification_playbook:
                    f.verification_playbook = f.verification_playbook.model_copy(
                        update={
                            'console_code': playbook_console_code,
                            'console_steps': pb.proof_steps,
                            'expected_observation': '; '.join(pb.success_criteria),
                        }
                    )
                pri = {
                    'Payment/Point Manipulation Candidate': 1,
                    'Account Recovery Flow Abuse Candidate': 2,
                    'IDOR / Unauthorized Data Access Candidate': 3,
                    'State/Status Manipulation Candidate': 4,
                    'Client-side Validation Bypass': 5,
                }.get(f.vulnerability_type, 99)
                playbook_candidates.append((pri, pb))
            if (f.severity in {'high', 'medium'} and f.confidence != 'low') or f.category in _HIGH_PRIORITY_CATEGORIES:
                executive_findings.append(f)
    # sort, dedup, cap playbooks
    playbook_candidates.sort(key=lambda x: x[0])
    seen_pb: set[tuple[str, str, str]] = set()
    promoted_playbook_ids: set[str] = set()
    for _, pb in playbook_candidates:
        key = (pb.source_path, pb.endpoint or '', pb.function_name or '')
        if key in seen_pb:
            continue
        seen_pb.add(key)
        verification_playbooks.append(pb)
        promoted_playbook_ids.add(pb.id)
        if len(verification_playbooks) >= MAX_PLAYBOOK_COUNT:
            break
    for f in findings:
        if f.id in promoted_playbook_ids:
            _add_unique(f.verification_notes, 'Selected as runtime verification candidate')
            if f.console_poc:
                f.console_poc.code = None
            f.observational_poc = None
        else:
            f.verification_notes = [note for note in f.verification_notes if note != 'Selected as runtime verification candidate']
    # When no playbooks are promoted, common_console_helper is hidden from the UI.
    # Any review candidate still marked observational would reference a hidden helper,
    # so downgrade to manual_plan to keep guidance consistent.
    if not verification_playbooks:
        for f in review_candidates:
            if f.poc_generation_status == 'observational':
                f.poc_generation_status = 'manual_plan'
                prev_reason = f.poc_generation_reason or ''
                f.poc_generation_reason = (
                    prev_reason.rstrip('; ') +
                    '; downgraded: no promoted playbook, common helper not shown'
                ).lstrip('; ')
                f.observational_poc = None
                if not f.manual_poc_plan:
                    src = f.evidence[0].source_path if f.evidence else 'UNKNOWN'
                    flows = f.evidence[0].data_flow if f.evidence else []
                    ep = next((x[len('endpoint: '):] for x in flows if x.startswith('endpoint: ')), 'UNKNOWN')
                    meth = next((x[len('method: '):] for x in flows if x.startswith('method: ')), 'UNKNOWN')
                    fn = next((x[len('function: '):] for x in flows if x.startswith('function: ')), None)
                    f.manual_poc_plan = _build_manual_poc_plan(src, fn, ep, meth)
                _add_unique(f.verification_notes,
                            'No promoted playbook: use Network tab and breakpoints instead of Console helper')
    # Build ProjectProfile for consumers
    raw_signal_count = sum(1 for f in findings if f.status == 'raw_signal')
    rtvc_count = len(verification_playbooks)
    rc_count = len(review_candidates)
    total_signals = len(findings)
    excluded_vendor = sum(1 for f in selected if _is_vendor_or_minified(f))
    blockers: list[str] = []
    for f in review_candidates[:5]:
        notes = [n for n in f.verification_notes if any(k in n for k in ('UNKNOWN', 'generic', 'placeholder', 'score=', 'compressed', 'manual'))]
        if notes:
            blockers.append(notes[0][:80])
    profile = ProjectProfile(
        project_type=project_map.project_type,
        languages=sorted({f.path.rsplit('.', 1)[-1].lower() for f in selected if '.' in f.path and f.path.rsplit('.', 1)[-1].lower() in {'js', 'ts', 'jsx', 'tsx', 'html', 'vue', 'mjs', 'cjs'}}),
        frameworks=([project_map.framework] if project_map.framework else []),
        api_clients=_detect_api_clients(selected),
        scanned_files=len(files),
        analyzed_files=len(selected),
        excluded_vendor_files=excluded_vendor,
        raw_signals=raw_signal_count,
        review_candidates=rc_count,
        runtime_verification_candidates=rtvc_count,
        confirmed_findings=0,
        duplicate_findings_removed=0,
        noise_ratio=round(raw_signal_count / max(1, total_signals), 2),
        top_blockers=sorted(set(blockers))[:5],
    )
    return ReadableAnalysisResult(
        finding_count=len(findings),
        findings=findings,
        analyzed_focus=['authorization', 'storage manipulation', 'dom xss', 'client-side validation bypass', 'api call tampering'],
        common_console_helper=_compute_common_helper(verification_playbooks, review_candidates),
        executive_findings=executive_findings,
        verification_playbooks=verification_playbooks,
        review_candidates=review_candidates,
        project_understanding=project_map,
        project_profile=profile,
    )
