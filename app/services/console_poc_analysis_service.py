import hashlib
import json
import re
from abc import ABC, abstractmethod

from app.core.config import settings
from app.models.schemas import AiAnalysisDebug, AnalysisDebugDropReason, ApiCallCandidate, BreakpointHint, ConsoleSafePoc, ConsoleVerificationPlaybook, ConsoleVerificationPlaybookSummary, FileContent, ReadableAnalysisResult, ReadableEvidence, ReadableFinding
from app.services.ai_clients import GeminiClient, GeminiClientProtocol
from app.services.api_candidate_extractor import extract_api_call_candidates, extract_ui_handler_candidates
from app.services.json_utils import extract_json_payload
from app.services.prompt_builder import build_candidate_analysis_prompt, build_console_poc_analysis_prompt
from app.services.source_intelligence import build_project_understanding

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
AUTH_SNIPPET_KEYS = ['requireAuth', 'checkSession', 'userInfo.userType', 'userType', 'role', 'isAdmin', 'ADMIN', 'NAFAL', 'navigate']
DOM_SNIPPET_KEYS = ['innerHTML', 'outerHTML', 'insertAdjacentHTML', 'document.write', 'location', 'document.URL', 'postMessage', 'input.value']
VALIDATION_SNIPPET_KEYS = ['axios.post', 'axios.put', 'fetch', 'FormData', 'amount', 'price', 'status', 'productId', 'userId', 'orderId', 'totalAmount', 'usePoints']
VALIDATION_PARAMETERS = ['amount', 'price', 'status', 'productId', 'userId', 'orderId', 'totalAmount', 'usePoints', 'paymentMethod', 'merchant_uid', 'imp_uid']


def _auth_bypass_severity(content: str) -> str:
    content_lower = content.lower()
    if 'navigate' in content_lower and 'requireauth' not in content_lower and 'axios.' not in content_lower and 'fetch(' not in content_lower:
        return 'low'
    return 'high'


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


def _extract_endpoints(content: str) -> list[str]:
    endpoints: list[str] = []
    for m in re.finditer(r'(?:axios\.(?:post|put)|fetch)\(\s*([\'"`])(.+?)\1', content, re.IGNORECASE):
        endpoint = re.sub(r'\$\{([^}]+)\}', r'{\1}', m.group(2))
        endpoint = re.sub(r'^\{apiBase\}', '', endpoint, flags=re.IGNORECASE)
        if '/api/' in endpoint:
            endpoint = endpoint[endpoint.index('/api/'):]
        endpoints.append(endpoint)
    return sorted(set(endpoints))


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
        '알림 표시', '역할별 뱃지', '역할별 알림', "return ['admin'", "return ['nafal'", "return 'var(",
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
        r'\bif\b[^{\n]*\b(usertype|role|isadmin)\b[^{\n]*\b(admin|nafal)\b',
        r'\bif\b[^{\n]*\b(admin|nafal)\b.*\bnavigate\s*\(',
        r'\bif\b[^{\n]*\b(admin|nafal)\b.*\breturn\b',
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
    has_sss_poc_guard = all(x in low for x in ('sss_poc_state', 'mutationarmed', 'armmutation', 'disarm'))
    has_high_risk_observer_guard = all(x in low for x in ('blocked_replay', 'replay blocked: high-risk endpoint', 'captured'))
    is_sss_hook = 'window.sss_poc' in low and ('window.fetch = async function' in low or 'xmlhttprequest.prototype.send' in low or 'axios.interceptors.request.use' in low)

    if is_sss_hook and (has_sss_poc_guard or has_high_risk_observer_guard):
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
        return has_legacy_guard or has_sss_poc_guard
    return True


def _has_storage_auth_evidence(files: list[FileContent], primary_file: FileContent) -> bool:
    storage_read_re = re.compile(r'(sessionStorage|localStorage)\.getItem\s*\(|document\.cookie', re.IGNORECASE)
    auth_key_re = re.compile(r'(userType|role|isAdmin)', re.IGNORECASE)
    admin_branch_re = re.compile(r'(ADMIN|NAFAL)', re.IGNORECASE)

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


def _build_network_hook_mutation_poc(endpoint: str, page_hint: str = '해당 기능 화면', action_hint: str = '대상 기능 버튼 클릭') -> str:
    endpoint_js = json.dumps(endpoint)
    page_js = json.dumps(page_hint)
    action_js = json.dumps(action_hint)
    return f"""(() => {{
  const TARGET_ENDPOINT = {endpoint_js};
  const PAGE_HINT = {page_js};
  const ACTION_HINT = {action_js};
  const SSS_POC_STATE = {{ mutationArmed: false, replayArmed: false }};
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
      console.warn('[SSS PoC] API JSON이 아니라 HTML이 반환되었습니다. 프론트엔드 라우팅 fallback 가능성이 있습니다.');
      console.warn('직접 endpoint 호출 대신 실제 UI 버튼 클릭 후 캡처된 요청을 확인하세요.');
    }}
  }};

  window.SSS_POC = {{
    captured,
    armMutation() {{
      SSS_POC_STATE.mutationArmed = true;
      console.warn('[SSS PoC] mutation mode armed. 승인된 테스트 환경에서만 진행하세요.');
    }},
    armReplay() {{
      if (BLOCKED_REPLAY) {{
        console.warn('[SSS PoC] replay blocked: high-risk endpoint');
        return;
      }}
      SSS_POC_STATE.replayArmed = true;
      console.warn('[SSS PoC] replay mode armed. 승인된 테스트 환경에서만 진행하세요.');
    }},
    disarm() {{
      SSS_POC_STATE.mutationArmed = false;
      SSS_POC_STATE.replayArmed = false;
      console.log('[SSS PoC] disarmed.');
    }},
    list() {{
      console.table(captured.map((x, i) => ({{ index: i, method: x.method, url: x.url }})));
    }},
    async replay(index, overrides = {{}}) {{
      if (BLOCKED_REPLAY) {{
        console.warn('[SSS PoC] replay blocked: high-risk endpoint');
        return null;
      }}
      if (!SSS_POC_STATE.replayArmed) {{
        console.warn('[SSS PoC] replayArmed=false. window.SSS_POC.armReplay() 후 실행하세요.');
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
        console.warn('[SSS PoC] axios replay unavailable: axios 인스턴스를 찾지 못했습니다.');
        return null;
      }}
      if (item.transport === 'xhr') {{
        console.warn('[SSS PoC] xhr replay는 수동 검증을 사용하세요.');
        return null;
      }}
      const init = Object.assign({{}}, item.init || {{}}, overrides || {{}});
      const resp = await originalFetch(item.url, init);
      await logCapturedResponse(resp);
      return resp;
    }},
  }};

  if (/test_order_id|test_user_id|test_value/i.test(TARGET_ENDPOINT)) {{
    console.warn('이 endpoint에는 placeholder가 포함되어 있어 직접 호출 대신 실제 UI 요청 캡처를 사용합니다.');
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
      if (SSS_POC_STATE.mutationArmed && parsed && !BLOCKED_REPLAY) {{
        if ('amount' in parsed) parsed.amount = 1;
        if ('status' in parsed) parsed.status = 'TEST_STATUS';
        init.body = JSON.stringify(parsed);
      }}
      captured.push({{ transport: 'fetch', method, url, init, body: init?.body || null, parsedPayload: parsed }});
      console.group('[SSS PoC] request captured');
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
      if (SSS_POC_STATE.mutationArmed && !BLOCKED_REPLAY && parsed) {{
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
        if (SSS_POC_STATE.mutationArmed && config?.data && typeof config.data === 'object' && !BLOCKED_REPLAY) {{
          if ('amount' in config.data) config.data.amount = 1;
          if ('status' in config.data) config.data.status = 'TEST_STATUS';
        }}
        captured.push({{ transport: 'axios', method: String(config?.method || 'GET').toUpperCase(), url: String(config?.url || ''), config }});
      }}
      return config;
    }});
  }}
  console.group('[SSS PoC] 설치 완료');
  console.log('mode:', 'observe');
  console.log('target:', TARGET_ENDPOINT);
  console.log('다음 단계: 검증 안내 섹션의 사용자 동작을 수행하세요.');
  console.log('요청이 감지되면 URL/method/payload/status가 출력됩니다.');
  console.log('변조 검증은 window.SSS_POC.armMutation() 실행 후 다시 버튼을 클릭하세요.');
  console.log('재전송 검증은 window.SSS_POC.armReplay() 후 window.SSS_POC.replay(index, overrides)로 수행하세요.');
  console.groupEnd();
  console.group('[SSS PoC] 검증 안내');
  console.log('검증 화면:', PAGE_HINT);
  console.log('사용자 동작:', ACTION_HINT);
  console.log('대상 API:', TARGET_ENDPOINT);
  console.log('현재 모드: observe');
  console.log('1) 이 화면으로 이동하세요:', PAGE_HINT);
  console.log('2) Console에 PoC 설치 완료 로그가 보이는지 확인하세요.');
  console.log('3) 사용자 동작을 수행하세요:', ACTION_HINT);
  console.log('4) window.SSS_POC.list()로 캡처된 요청을 확인하세요.');
  console.log('5) 변조 검증은 window.SSS_POC.armMutation() 실행 후 같은 동작을 다시 수행하세요.');
  console.log('6) 완료 후 window.SSS_POC.disarm()을 실행하세요.');
  if (ACTION_HINT === '대상 기능 버튼 클릭') {{
    console.warn('정확한 버튼/화면을 자동 추론하지 못했습니다. source_path와 function_name을 기준으로 수동 확인하세요.');
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
        ('paymentpage', '결제 화면'), ('purchasepage', '구매 화면'),
        ('auctionpage', '경매/입찰 화면'),
        ('findpassword', '비밀번호 찾기/계정 복구 화면'), ('loginpage', '로그인 화면'),
        ('signuppage', '회원가입 화면'), ('itemdetailpage', '상품 상세/입찰 화면'),
        ('nafalmypage', '마이페이지/관리 화면'), ('usermypage', '마이페이지/관리 화면'), ('adminmypage', '마이페이지/관리 화면'),
    ]
    page_hint = next((v for k, v in page_map if k in p), '해당 기능 화면')
    fn = function_name
    if not fn:
        m = re.search(r'(handle[A-Za-z0-9_]+|loadDashboardData|fetchDashboard)', snippet)
        if m:
            fn = m.group(1)
    action = '대상 기능 버튼 클릭'
    f = (fn or '').lower()
    if 'handlepay' in f or 'handlepayment' in f or 'handleretrypayment' in f:
        action = '결제/결제완료 버튼 클릭'
    elif 'handlestripecheckout' in f:
        action = 'Stripe 결제 버튼 클릭'
    elif 'requestiamportpay' in f:
        action = '아임포트 결제 요청 버튼 클릭'
    elif 'handleiamportquick' in f:
        action = '간편결제/포인트 충전 버튼 클릭'
    elif 'handlepointcharge' in f:
        action = '포인트 충전 버튼 클릭'
    elif 'handlecharge' in f:
        action = '포인트 충전 버튼 클릭'
    elif 'sendverificationcode' in f:
        action = '인증번호 발송 버튼 클릭'
    elif 'verifycode' in f:
        action = '인증번호 확인 버튼 클릭'
    elif 'resetpassword' in f:
        action = '비밀번호 재설정 버튼 클릭'
    elif 'handleverify' in f:
        action = '인증번호 확인 버튼 클릭'
    elif 'handleresetpassword' in f:
        action = '비밀번호 재설정 버튼 클릭'
    elif 'handlesubmit' in f:
        action = '현재 폼 제출 버튼 클릭'
    elif 'handlebid' in f:
        action = '입찰 버튼 클릭'
    elif 'handlepurchase' in f:
        action = '구매 버튼 클릭'
    return page_hint, action, fn

def _format_page_step(page_hint: str) -> str:
    return f'{page_hint}으로 이동' if page_hint.endswith('화면') else f'{page_hint} 화면으로 이동'


def infer_interaction_context(source_path: str, function_name: str | None, snippet: str, endpoint: str, method: str, parameters: list[str], surrounding_block: str = '', ui_candidates: list[dict] | None = None) -> tuple[str, str, str, list[str]]:
    low_endpoint = (endpoint or '').lower()
    low_text = ' '.join(filter(None, [snippet, surrounding_block] + [c.get('element_text', '') for c in (ui_candidates or [])])).lower()
    low_fn = (function_name or '').lower()
    reasons: list[str] = []
    page_hint = '해당 기능 화면'
    action_hint = '대상 기능 버튼 클릭'
    confidence = 'low'
    if any(k in low_endpoint for k in ('payment', 'order', 'checkout', 'pay', 'billing')):
        page_hint, reasons = '결제/주문 화면', reasons + ['endpoint category: payment/order']
    elif any(k in low_endpoint for k in ('auction', 'bid')):
        page_hint, reasons = '경매/입찰 화면', reasons + ['endpoint category: auction/bid']
    elif any(k in low_endpoint for k in ('password', 'reset', 'verify-code', 'send-verification', 'verify', 'chkmobi', 'chgmobi', 'mobile', 'sms', 'cert', 'authno')):
        page_hint, reasons = '계정 복구/인증 화면', reasons + ['endpoint category: recovery/verify']
    elif any(k in low_endpoint for k in ('wallet', 'point', 'charge')):
        page_hint, reasons = '지갑/포인트 화면', reasons + ['endpoint category: wallet/point']
    elif any(k in low_endpoint for k in ('iamport',)):
        page_hint, reasons = '결제/주문 화면', reasons + ['endpoint category: iamport payment']
    elif any(k in low_endpoint for k in ('login', 'auth/token')):
        page_hint, reasons = '로그인/인증 화면', reasons + ['endpoint category: login/auth']
    if any(k in low_text for k in ('pay now', 'checkout', '결제하기', '결제 완료')):
        action_hint = '결제 버튼 클릭'; reasons.append('ui text indicates payment')
    elif any(k in low_text for k in ('입찰', 'bid')):
        action_hint = '입찰 버튼 클릭'; reasons.append('ui text indicates bid')
    elif any(k in low_text for k in ('인증번호 발송', 'send code')):
        action_hint = '인증번호 발송 버튼 클릭'; reasons.append('ui text indicates send code')
    elif any(k in low_text for k in ('인증 확인', 'verify')):
        action_hint = '인증번호 확인 버튼 클릭'; reasons.append('ui text indicates verify')
    elif any(k in low_text for k in ('reset password', '비밀번호 재설정')):
        action_hint = '비밀번호 재설정 버튼 클릭'; reasons.append('ui text indicates reset')
    elif any(k in low_endpoint for k in ('verify-code', 'authno', 'verify')):
        action_hint = '인증번호 확인 버튼 클릭'; reasons.append('endpoint indicates verify-code')
    elif any(k in low_endpoint for k in ('reset-password',)):
        action_hint = '비밀번호 재설정 버튼 클릭'; reasons.append('endpoint indicates reset-password')
    elif any(k in low_endpoint for k in ('send-verification', 'chkmobisendajax', 'chgmobisendajax', 'sendsms', 'sms')):
        action_hint = '인증번호 발송 버튼 클릭'; reasons.append('endpoint indicates send-verification')
    elif 'create-checkout-session' in low_endpoint:
        action_hint = 'Stripe 결제 버튼 클릭'; reasons.append('endpoint indicates stripe checkout session')
    elif any(k in low_endpoint for k in ('iamport/prepare', 'iamport/verify')):
        action_hint = '결제 승인/검증 버튼 클릭'; reasons.append('endpoint indicates iamport verification')
    elif any(k in low_endpoint for k in ('wallet/charge', '/charge')):
        action_hint = '포인트 충전 버튼 클릭'; reasons.append('endpoint indicates charge')
    elif any(k in low_fn for k in ('payment', 'checkout', 'pay', 'submitorder', 'process')):
        action_hint = '결제 버튼 클릭'; reasons.append('function fallback indicates payment')
    elif any(k in low_fn for k in ('bid', 'placebid')):
        action_hint = '입찰 버튼 클릭'; reasons.append('function fallback indicates bid')
    elif any(k in low_fn for k in ('verifycode', 'confirmcode', 'validatecode')):
        action_hint = '인증번호 확인 버튼 클릭'; reasons.append('function fallback indicates verify')
    elif any(k in low_fn for k in ('resetpassword', 'changepassword')):
        action_hint = '비밀번호 재설정 버튼 클릭'; reasons.append('function fallback indicates reset')
    elif any(k in low_fn for k in ('sendverificationcode', 'requestcode')):
        action_hint = '인증번호 발송 버튼 클릭'; reasons.append('function fallback indicates send-code')
    if action_hint != '대상 기능 버튼 클릭' and page_hint != '해당 기능 화면':
        confidence = 'high'
    elif action_hint != '대상 기능 버튼 클릭' or page_hint != '해당 기능 화면':
        confidence = 'medium'
    return page_hint, action_hint, confidence, reasons


def _build_playbook(f: FileContent, candidate: ApiCallCandidate | None = None, auth: bool = False, disabled: bool = False, page_hint: str | None = None, action_hint: str | None = None, function_name: str | None = None) -> ConsoleVerificationPlaybook:
    if auth:
        return ConsoleVerificationPlaybook(
            strategy='auth_route_guard',
            breakpoints=[BreakpointHint(source_path=f.path, start_line=1, end_line=max(1, len(f.content.splitlines())), reason='권한 조건문 분기 확인', watch_variables=['userInfo', 'user', 'role', 'userType', 'isAdmin'])],
            console_steps=['권한 조건문 breakpoint 설정', '로그인 후 보호 페이지 접근', 'Scope에서 userType/role 확인', '클라이언트 분기만 막는지, API 서버 검증도 있는지 확인'],
            expected_observation='권한 분기가 클라이언트에만 존재하는지 확인',
        )
    if disabled:
        bps = []
        if candidate is not None:
            bps.append(BreakpointHint(source_path=f.path, start_line=candidate.start_line, end_line=candidate.end_line, reason='API 호출 직전 payload 변조 확인', watch_variables=['payload'] + (candidate.parameters or [])))
        return ConsoleVerificationPlaybook(
            strategy='disabled_button_bypass',
            breakpoints=bps,
            console_steps=['disabled 버튼 목록 확인', '대상 버튼 disabled 해제', '클릭 후 핸들러/요청 발생 여부 확인'],
            console_code=_build_disabled_console_code(),
            expected_observation='disabled 속성 제거만으로 요청이 발생하는지 확인',
            limitations=['React/Vue state 기반 검증이 있으면 DOM disabled 제거만으로는 부족할 수 있음', 'handler 내부 validation return 지점 breakpoint 확인 필요'],
        )
    endpoint = (candidate.endpoint if candidate else '/api') or '/api'
    validation_bps = _find_validation_return_breakpoints(f, candidate)
    vars_from_validation = {w for bp in validation_bps for w in bp.watch_variables}
    vars_from_endpoint = set(re.findall(r'\{([^}]+)\}', (candidate.endpoint if candidate else '') or ''))
    watch = ['payload'] + ((candidate.parameters or []) if candidate else []) + list(vars_from_validation) + list(vars_from_endpoint)
    breakpoints = list(validation_bps)
    breakpoints.append(BreakpointHint(source_path=f.path, start_line=(candidate.start_line if candidate else 1), end_line=(candidate.end_line if candidate else 1), reason='API 호출 직전 payload 변조 확인', watch_variables=sorted(set(watch))))
    return ConsoleVerificationPlaybook(
        strategy='breakpoint_payload_mutation',
        breakpoints=breakpoints,
        console_steps=['DevTools Sources에서 breakpoint 설정', '정상 UI 버튼 클릭', 'Scope에서 payload 값 확인', '테스트 값으로 변경', 'Resume 후 서버 응답 확인'],
        console_code=(_build_network_hook_mutation_poc(endpoint, page_hint=page_hint or '해당 기능 화면', action_hint=action_hint or '대상 기능 버튼 클릭') if endpoint != 'UNKNOWN' else None),
        expected_observation='요청 직전 payload 변경이 전송 본문에 반영됨',
        limitations=(['endpoint가 UNKNOWN이라 자동 hook 코드는 생성하지 않았습니다.'] if endpoint == 'UNKNOWN' else []),
    )




def _build_observational_network_poc(endpoint: str, method: str, source_path: str, function_name: str | None, page_hint: str, action_hint: str) -> ConsoleSafePoc:
    return ConsoleSafePoc(
        poc_type='browser_console',
        description='관찰형 PoC: 네트워크 요청 캡처/관찰',
        preconditions=['승인된 테스트 환경', '브라우저 DevTools Console 접근 가능'],
        steps=[
            'Console에 관찰형 Hook 코드를 붙여넣고 실행',
            _format_page_step(page_hint or '해당 기능 화면'),
            f'{action_hint or "대상 기능 버튼 클릭"} 수행',
            'window.SSS_POC.list()로 캡처된 요청을 확인',
        ],
        code=_build_network_hook_mutation_poc(endpoint, page_hint=page_hint or '해당 기능 화면', action_hint=action_hint or '대상 기능 버튼 클릭'),
        expected_result=f'요청 URL/method/payload/status가 캡처됨 (target: {method} {endpoint})',
        safety='관찰형 PoC이며 기본 상태에서는 요청 변조/재전송을 수행하지 않음. armMutation()을 명시적으로 호출하기 전 mutation 비활성.',
    )


def _is_external_or_static_endpoint(endpoint: str) -> bool:
    ep = (endpoint or '').lower().strip()
    if not ep:
        return False
    if ep.startswith(('http://', 'https://')) and not any(h in ep for h in ('localhost', '127.0.0.1')):
        return True
    return any(k in ep for k in ('analytics', 'google-analytics', 'gtag', 'doubleclick', '/static/', '/assets/', '.js', '.css', '.png', '.jpg', '.gif', '.svg'))

def _build_manual_poc_plan(source_path: str, function_name: str | None, endpoint: str, method: str) -> list[str]:
    return [
        f'파일 확인: {source_path}',
        f'함수 확인: {function_name or "UNKNOWN"}',
        f'요청 정보 확인: {method or "UNKNOWN"} {endpoint or "UNKNOWN"}',
        'data_flow(method/endpoint/function/sink) 항목을 evidence에서 재확인',
        '요청 직전 payload 변수/검증 분기(if return/throw) 라인에 breakpoint 설정',
        '브라우저 Network 탭에서 URL/method/payload/status/response를 확인',
        'Console hook 적용 가능 여부를 확인(UNKNOWN endpoint 또는 압축/라이브러리 코드는 제한될 수 있음)',
        'executable/observational PoC 제한 사유를 검토 노트에 기록',
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
                reason='클라이언트 검증 실패 분기 확인',
                watch_variables=vars_found,
            ))
    return hints


class ConsolePocAnalyzer(ABC):
    @abstractmethod
    def analyze(self, files: list[FileContent]) -> list[ReadableFinding]:
        raise NotImplementedError


class MockConsolePocAnalyzer(ConsolePocAnalyzer):
    """Pattern-based fallback for tests and offline validation only.

    Production-quality reasoning should use GeminiConsolePocAnalyzer with
    structured API candidates.
    """
    def analyze(self, files: list[FileContent]) -> list[ReadableFinding]:
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
                    title='비활성화 UI 우회 검증 필요',
                    vulnerability_type='Client-side Validation Bypass',
                    severity='low',
                    confidence='low',
                    affected_files=[f.path],
                    summary='disabled UI 제한은 Console/DevTools에서 우회될 수 있어 추가 검증이 필요합니다.',
                    evidence=[ReadableEvidence(source_path=f.path, start_line=1, end_line=min(20, len(c.splitlines()) or 1), snippet='\n'.join((c.splitlines() or [''])[:20]), reason='disabled UI 조건 탐지', data_flow=[
                        'source -> state/storage -> sink',
                        f"ui_event: {event_item.get('ui_event') if event_item else 'unknown'}",
                        f"disabled_expression: {disabled_item.get('disabled_expression') if disabled_item else ''}",
                        f"handler: {event_item.get('handler_name') if event_item else ''}",
                        f"endpoint: {endpoint_item.endpoint}",
                    ])],
                    attack_scenario=['disabled 속성 제거 후 클릭'],
                    impact='클라이언트 단 제약 우회 가능성',
                    root_cause='UI 속성 기반 제한',
                    remediation='서버측 유효성/권한 검증 강제',
                    verification_notes=['disabled 제거만으로 우회 가능한지 확인 필요'],
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

    def _build_readonly_get_poc(self, endpoint: str) -> str:
        endpoint = self._replace_endpoint_placeholders(endpoint)
        return _build_network_hook_mutation_poc(endpoint)

    def _build_guarded_mutation_poc(self, method: str, endpoint: str, parameters: list[str]) -> str:
        endpoint = self._replace_endpoint_placeholders(endpoint)
        return _build_network_hook_mutation_poc(endpoint)

    def _is_irreversible_or_high_risk(self, method: str, endpoint: str, parameters: list[str]) -> bool:
        if method.upper() == 'DELETE':
            return True
        hay = f"{endpoint.lower()} {' '.join(p.lower() for p in parameters)}"
        return any(k in hay for k in ('delete', 'remove', 'withdraw', 'transfer', 'refund', 'bulk', 'cancel-all', 'admin/delete'))

    def _ev(self, f: FileContent, reason: str) -> list[ReadableEvidence]:
        if '권한' in reason:
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
        poc_code = (
            "sessionStorage.setItem('user', JSON.stringify({ userType: 'ADMIN' })); location.reload();"
            if has_storage_evidence and not missing_deps
            else None
        )
        verification_notes = []
        if needs_manual_validation:
            verification_notes.extend([
                '권한값 저장/조회 위치가 확인되지 않아 Console PoC code는 생성하지 않았습니다.',
                'requireAuth/checkSession 구현 파일 확인이 필요합니다.',
                'sessionStorage/localStorage 조작 PoC는 현재 코드 근거로 검증되지 않았습니다.',
            ])
        verification_notes.extend([f'{d} 구현 파일이 ZIP에 없어 requireAuth 동작을 확정할 수 없습니다.' for d in missing_deps])

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
  console.log('[PoC] fetch hook installed. 정상 로그인/페이지 이동을 수행하고 Console 로그를 확인하세요.');
})();"""

        return ReadableFinding(
            id=self._id(f.path + 'a'),
            title='클라이언트 권한 값 조작을 통한 접근 우회 가능성',
            vulnerability_type='Client-side Authorization Bypass',
            severity=_auth_bypass_severity(f.content),
            confidence=('low' if needs_manual_validation else 'medium'),
            affected_files=[f.path],
            summary=('클라이언트 저장소 권한값 기반 분기 가능성이 보입니다.' if not needs_manual_validation else '클라이언트 권한 분기 우회 가능성은 있으나 추가 확인 필요'),
            evidence=self._ev(f, '권한 분기 정황'),
            console_poc=ConsoleSafePoc(
                poc_type='browser_console',
                description='세션 저장값 조작 확인',
                preconditions=['로그인 세션'],
                steps=['Console 실행', '코드 실행', '새로고침'],
                code=poc_code,
                expected_result='화면 분기 변화 확인',
                safety='새 요청을 생성하지 않고 기존 요청을 관찰한다.',
            ),
            attack_scenario=['저장소 값 조작'],
            impact='클라이언트 단 통제 우회 가능성',
            root_cause='클라이언트 상태 의존',
            remediation='서버 권한 검증 강제',
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
        return ReadableFinding(
            id=self._id(f.path + 'x'),
            title='외부 입력이 DOM sink로 전달될 가능성',
            vulnerability_type='DOM XSS',
            severity='high',
            confidence='medium',
            affected_files=[f.path],
            summary='외부 입력이 위험 sink로 전달될 수 있습니다.',
            evidence=[ReadableEvidence(source_path=f.path, start_line=start_line, end_line=end_line, snippet=snippet, reason='source-sink 조합', data_flow=['source -> state/storage -> sink'])],
            console_poc=ConsoleSafePoc(
                poc_type='browser_console',
                description='hash 기반 확인',
                preconditions=['페이지 접근 가능'],
                steps=['Console 실행', '코드 실행', '새로고침'],
                code="location.hash = '<img src=x onerror=alert(1)>'; location.reload();",
                expected_result='alert 실행 여부',
                safety='alert 수준의 비파괴 스크립트 실행 여부만 확인한다.',
            ),
            attack_scenario=['외부 입력 제어', 'DOM sink 전달'],
            impact='스크립트 실행 가능성',
            root_cause='검증/인코딩 부재',
            remediation='안전한 DOM API 사용',
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
                'title': '결제/포인트 요청 파라미터 조작 가능성',
                'impact': '결제/포인트 관련 비즈니스 로직 오남용 가능성',
                'root_cause': '클라이언트 파라미터 기반 요청 제어',
                'remediation': '서버측 금액/포인트/결제 파라미터 검증 강화',
                'severity': 'high' if method in {'POST', 'PUT', 'PATCH', 'DELETE'} else 'medium',
            }
        if method == 'GET' and (idor_keys & (endpoint_tokens | set(params_l))):
            return {
                'vulnerability_type': 'IDOR / Unauthorized Data Access Candidate',
                'title': '식별자 기반 조회 요청의 접근 제어 확인 필요',
                'impact': '타 사용자 데이터 조회 가능성',
                'root_cause': '식별자 기반 조회 요청의 권한 검증 불확실',
                'remediation': '서버측 객체 단위 권한 검증 적용',
                'severity': 'medium',
            }
        if method in {'POST', 'PUT', 'PATCH', 'DELETE'} and (state_keys & (endpoint_tokens | set(params_l))):
            return {
                'vulnerability_type': 'State/Status Manipulation Candidate',
                'title': '상태/권한 변경 요청 조작 가능성',
                'impact': '권한/상태 값 위변조 가능성',
                'root_cause': '클라이언트 제어 값에 대한 서버 검증 불확실',
                'remediation': '상태/권한 변경 API 서버 검증 및 감사 로깅 강화',
                'severity': 'high',
            }
        if 'verify-identity' in endpoint_l and 'findpassword' not in source_path.lower():
            return {
                'vulnerability_type': 'Identity Verification / Action Authorization Bypass Candidate',
                'title': '본인 인증/행위 검증 흐름 우회 가능성 검증 필요',
                'impact': '인증/행위 검증 우회 시 권한 없는 작업 가능성',
                'root_cause': '본인 인증/행위 검증 흐름의 서버 검증 불확실',
                'remediation': '행위 승인/본인인증 검증을 서버에서 강제하고 토큰 재검증 적용',
                'severity': 'high',
            }
        if recovery_keys & endpoint_tokens:
            return {
                'vulnerability_type': 'Account Recovery Flow Abuse Candidate',
                'title': '계정 복구/인증 코드 흐름 검증 필요',
                'impact': '계정 복구 흐름 악용 가능성',
                'root_cause': '복구/인증 코드 요청 흐름의 서버 검증 불확실',
                'remediation': '복구/코드 검증 API에 rate-limit/토큰 검증 강화',
                'severity': 'medium',
            }
        if method in {'POST', 'PUT', 'PATCH', 'DELETE'}:
            return {
                'vulnerability_type': 'Client-side Validation Bypass',
                'title': '클라이언트 검증값 조작을 통한 요청 변조 가능성',
                'impact': '비즈니스 로직 오남용',
                'root_cause': '클라이언트 검증 의존',
                'remediation': '서버 검증 강제',
                'severity': 'medium',
            }
        return {
            'vulnerability_type': 'Generic API Review Candidate',
            'title': 'API 요청 후보 수동 검토 필요',
            'impact': '요청 흐름 오남용 가능성',
            'root_cause': '프론트 소스만으로 서버 검증 여부 판단 불가',
            'remediation': '백엔드 권한/유효성 검증 정책 교차 검토',
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
            reason='검증값+요청 API 조합',
            data_flow=flow,
        )]

        notes: list[str] = []
        conf = 'low'
        poc_type = 'manual_check'
        poc_code = None
        safety = '실제 변경 요청을 수행하지 않는다.'
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
        if method == 'GET' and endpoint != 'UNKNOWN' and important_get:
            poc_type = 'browser_console'
            poc_code = _build_network_hook_mutation_poc(endpoint, page_hint=page_hint, action_hint=action_hint)
            conf = 'medium'
            safety = '조회형 요청으로 응답 status/body만 확인한다.'
        elif method == 'GET' and not important_get:
            return None
        elif method in {'POST', 'PUT', 'PATCH'}:
            if endpoint != 'UNKNOWN':
                poc_type = 'browser_console'
                poc_code = _build_network_hook_mutation_poc(endpoint, page_hint=page_hint, action_hint=action_hint)
                conf = 'medium'
                notes.append('변조 검증은 window.SSS_POC.armMutation() 실행 후 진행하세요.')
                safety = '기본값 false guard로 즉시 실행되지 않으며, 승인된 테스트 계정/테스트 데이터에서만 실행해야 한다.'
                if self._is_base_variable_endpoint(endpoint):
                    notes.append('API_BASE 값을 실제 대상 URL로 변경해야 합니다.')
        elif method == 'DELETE' or self._is_irreversible_or_high_risk(method, endpoint, parameters):
            if endpoint != 'UNKNOWN':
                poc_type = 'browser_console'
                poc_code = _build_network_hook_mutation_poc(endpoint, page_hint=page_hint, action_hint=action_hint)
                conf = 'medium'
            notes.append('고위험 요청은 replay/mutation이 차단되며 observe mode만 제공됩니다.')

        if action_hint == '대상 기능 버튼 클릭':
            notes.append('정확한 버튼/화면을 자동 추론하지 못했습니다. source_path/function_name 기준 수동 확인 필요.')

        classification = self._classify_api_candidate(candidate, source_path=f.path)
        steps = [
            'Console에 코드 전체 붙여넣기',
            '[SSS PoC] 설치 완료 로그 확인',
            _format_page_step(page_hint),
            f'{action_hint} 수행',
            'window.SSS_POC.list()로 캡처 요청 확인',
            '필요 시 window.SSS_POC.armMutation() 실행',
            f'{action_hint} 다시 수행',
            '변조 전/후 payload와 서버 응답 비교',
            'window.SSS_POC.disarm()으로 종료',
        ]
        return ReadableFinding(
            id=self._id(f"{f.path}:{method}:{endpoint}:{sink}:{','.join(sorted(parameters))}:{classification['vulnerability_type']}"),
            title=classification['title'],
            vulnerability_type=classification['vulnerability_type'],
            severity=classification['severity'],
            confidence=conf,
            affected_files=[f.path],
            summary='요청 전송 전 값 조작 가능성 정황입니다.',
            evidence=ev,
            console_poc=ConsoleSafePoc(
                poc_type=poc_type,
                description='브라우저 Console에 붙여넣으면 실제 UI에서 발생하는 fetch/XHR/axios 요청을 관찰하고, 승인된 테스트 환경에서 payload 변조 검증을 수행할 수 있는 PoC입니다.',
                preconditions=['승인된 테스트 계정', '테스트 데이터 또는 테스트 주문', 'Console에서 [SSS PoC] 설치 완료 로그 확인', '변조 검증 전 window.SSS_POC.armMutation()을 명시적으로 실행'],
                steps=steps,
                code=poc_code,
                expected_result='요청 캡처 로그 및 응답 정보를 통해 검증 포인트를 확인하고, armMutation 후 재실행 시 payload 변조 적용 여부를 확인',
                safety=safety,
            ),
            attack_scenario=['파라미터 조작'],
            impact=classification['impact'],
            root_cause=classification['root_cause'],
            remediation=classification['remediation'],
            verification_notes=notes,
            verification_playbook=_build_playbook(f, candidate=candidate, page_hint=page_hint, action_hint=action_hint, function_name=function_name),
            poc_generation_status=('manual_plan' if endpoint == 'UNKNOWN' else 'observational'),
            poc_generation_reason=('endpoint unknown' if endpoint == 'UNKNOWN' else 'endpoint/method available with safe observer PoC'),
            observational_poc=(None if endpoint == 'UNKNOWN' else ConsoleSafePoc(
                poc_type='browser_console',
                description='관찰형 PoC: 요청 캡처/응답 확인',
                preconditions=['승인된 테스트 환경'],
                steps=['Console 코드 실행', '정상 UI 동작 수행', 'window.SSS_POC.list() 확인'],
                code=_build_network_hook_mutation_poc(endpoint, page_hint=page_hint, action_hint=action_hint),
                expected_result='요청 URL/method/payload/status 캡처',
                safety='mutation/replay는 arm 호출 전 비활성',
            )),
            manual_poc_plan=(_build_manual_poc_plan(f.path, function_name, endpoint, method) if endpoint == 'UNKNOWN' else []),
        )



class GeminiConsolePocAnalyzer(ConsolePocAnalyzer):
    def __init__(self, client: GeminiClientProtocol):
        self.client = client
        self.last_debug = AiAnalysisDebug(backend='gemini')

    def analyze(self, files: list[FileContent]) -> list[ReadableFinding]:
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
            raw_text = self.client.analyze(build_candidate_analysis_prompt(safe_files, candidates))
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
                    notes.append('위험 요청 가능성이 있어 Console PoC code를 제거했습니다.')
                    item['verification_notes'] = notes
                    self.last_debug.errors.append('safety: Dangerous Console PoC code removed')

            try:
                _ensure_finding_id(item)
                out.append(ReadableFinding(**item))
                self.last_debug.accepted_item_count += 1
            except Exception as exc:
                _drop(idx, 'validation', f'ReadableFinding validation failed: {type(exc).__name__}: {str(exc)[:120]}', item)
                continue
        return out


def get_console_poc_analyzer() -> ConsolePocAnalyzer:
    backend = settings.ANALYZER_BACKEND.lower()
    if backend == 'mock':
        return MockConsolePocAnalyzer()
    if backend == 'gemini':
        return GeminiConsolePocAnalyzer(GeminiClient(settings.GEMINI_API_KEY, settings.GEMINI_MODEL))
    raise ValueError(f'Unsupported readable analysis backend: {settings.ANALYZER_BACKEND}')



def analyze_console_exploitability(files: list[FileContent], analyzer: ConsolePocAnalyzer | None = None) -> ReadableAnalysisResult:
    selected = select_console_relevant_files(files)
    analyzer = analyzer or get_console_poc_analyzer()
    findings = analyzer.analyze(selected)
    verification_playbooks: list[ConsoleVerificationPlaybookSummary] = []
    executive_findings: list[ReadableFinding] = []
    review_candidates: list[ReadableFinding] = []
    seen_flow: set[tuple[str, str, str, str, str, str]] = set()
    playbook_candidates: list[tuple[int, ConsoleVerificationPlaybookSummary]] = []
    project_map = build_project_understanding(selected)

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
        if page_hint == '해당 기능 화면' and page_obj and page_obj.page_hint:
            page_hint = page_obj.page_hint
        if page_hint == '해당 기능 화면':
            page_hint = fallback_page
        if action_hint == '대상 기능 버튼 클릭':
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
        is_generic_action = action_hint == '대상 기능 버튼 클릭'
        is_generic_page = page_hint == '해당 기능 화면'
        endpoint_norm = endpoint.lower().split('?', 1)[0].rstrip('/')
        endpoint_norm = re.sub(r'^\{api_base\}', '', endpoint_norm)
        is_session_get = method == 'GET' and (
            endpoint_norm in {'/api/user/session', '/api/auth/me', '/api/me', '/api/profile/me'}
            or endpoint_norm.endswith('/api/user/session')
        )
        is_generic_type = f.vulnerability_type == 'Generic API Review Candidate'
        is_compressed = _is_compressed_or_library_evidence(f, function_name)
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
        if api_match and api_match.ui_event_text and action_hint != '대상 기능 버튼 클릭':
            score += 2
            score_reasons.append('ui_text_matches_action')
        if api_match and api_match.risk_category:
            score += 2
            score_reasons.append(f'endpoint_category={api_match.risk_category}')
        if api_match and any(p.lower() in {'amount', 'price', 'userid', 'orderid', 'status', 'code', 'email', 'password'} for p in (api_match.parameters or [])):
            score += 2
            score_reasons.append('sensitive_payload')
        score += 2 if action_hint != '대상 기능 버튼 클릭' else -2
        score += 1 if page_hint != '해당 기능 화면' else -2
        score += 2 if endpoint != 'UNKNOWN' else -2
        score += -3 if is_generic_type else 0
        score += -3 if is_session_get else 0
        score += -3 if is_compressed else 0
        score += -2 if is_auto_fn else 0
        should_review = (
            is_disabled_only or is_unknown or no_code or ux_disabled or top_import_like or is_auto_fn or is_generic_type or
            is_generic_action or is_generic_page or (function_name is None and not is_jq_html_promotable) or is_session_get or is_compressed or
            score < 5 or
            (is_low_conf and 'Payment' not in f.vulnerability_type and 'Account Recovery' not in f.vulnerability_type and 'IDOR' not in f.vulnerability_type and 'Authorization' not in f.vulnerability_type)
        )
        if should_review:
            has_snippet = bool(f.evidence and (f.evidence[0].snippet or '').strip())
            disallow_observational = is_compressed or _is_external_or_static_endpoint(endpoint)
            if endpoint != 'UNKNOWN' and method != 'UNKNOWN' and has_snippet and not disallow_observational:
                f.poc_generation_status = 'observational'
                f.poc_generation_reason = 'review candidate with generated safe observational PoC'
                f.observational_poc = _build_observational_network_poc(
                    endpoint=endpoint,
                    method=method,
                    source_path=flow[1],
                    function_name=function_name,
                    page_hint=page_hint,
                    action_hint=action_hint,
                )
            elif endpoint == 'UNKNOWN' or method == 'UNKNOWN' or is_compressed or not has_snippet:
                f.poc_generation_status = 'manual_plan'
                f.poc_generation_reason = 'manual verification required due to unknown/compressed/insufficient evidence'
                f.manual_poc_plan = _build_manual_poc_plan(flow[1], function_name, endpoint, method)
            else:
                f.poc_generation_status = 'not_possible'
                f.poc_generation_reason = 'third-party/static/analytics endpoint or insufficient safe context'
            f.verification_notes.append(f"playbook_score={score}: {', '.join(score_reasons) if score_reasons else 'no_strong_signals'}")
            if no_code and is_unknown and 'endpoint가 UNKNOWN이라 자동 PoC를 생성하지 않았습니다.' not in f.verification_notes:
                f.verification_notes.append('endpoint가 UNKNOWN이라 자동 PoC를 생성하지 않았습니다.')
            if is_generic_action:
                f.verification_notes.append('사용자 동작을 자동 추론하지 못해 수동 검토 후보로 분류했습니다.')
            if is_session_get:
                f.verification_notes.append('자동 세션/초기화 요청으로 판단되어 Playbook에서 제외했습니다.')
            elif api_match and api_match.risk_category == 'search_recommend':
                f.verification_notes.append('자동 조회/추천검색성 API로 판단되어 Playbook에서 제외했습니다.')
            elif is_auto_fn:
                f.verification_notes.append('자동 조회/추천검색성 API로 판단되어 Playbook에서 제외했습니다.')
            if is_compressed:
                f.verification_notes.append('압축/라이브러리성 코드로 판단되어 수동 검토 후보로 분류했습니다.')
            if is_generic_type:
                f.verification_notes.append('일반 API 후보라 자동 검증 Playbook에서 제외하고 수동 검토 후보로 분류했습니다.')
            review_candidates.append(f)
        else:
            f.poc_generation_status = 'executable'
            f.poc_generation_reason = 'promoted playbook with executable verification PoC'
            f.verification_notes.append(f"playbook_score={score}: {', '.join(score_reasons) if score_reasons else 'baseline'}")
            if flow not in seen_flow:
                seen_flow.add(flow)
                executable_poc = f.console_poc
                if (not executable_poc or not executable_poc.code) and endpoint != 'UNKNOWN' and method != 'UNKNOWN':
                    executable_poc = _build_safe_network_poc(endpoint, page_hint=page_hint, action_hint=action_hint)
                if not executable_poc or not executable_poc.code:
                    f.poc_generation_status = 'manual_plan'
                    f.poc_generation_reason = 'playbook promotion blocked: missing console code'
                    f.manual_poc_plan = _build_manual_poc_plan(flow[1], function_name, endpoint, method)
                    review_candidates.append(f)
                    continue
                pb = ConsoleVerificationPlaybookSummary(
                    id=f.id,
                    title=f.title,
                    source_path=flow[1],
                    function_name=(function_name or None),
                    endpoint=endpoint,
                    method=method,
                    page_hint=page_hint,
                    user_action_hint=action_hint,
                    risk_type=f.vulnerability_type,
                    confidence=f.confidence,
                    console_code=executable_poc.code,
                    setup_steps=executable_poc.steps,
                    proof_steps=['Console에 PoC 붙여넣기', '[SSS PoC] 설치 완료 확인', _format_page_step(page_hint), f'{action_hint} 수행', 'window.SSS_POC.list() 실행', '캡처된 요청 endpoint/method/payload 확인', 'window.SSS_POC.armMutation() 실행', '동일 동작 재수행', '변조 전/후 payload와 서버 응답 비교'],
                    success_criteria=['요청 payload가 Console에 캡처됨', 'armMutation 후 지정 필드가 변조됨', '서버가 변조된 값에 대해 200/201 또는 상태 변경을 허용함', '또는 권한 없는 객체 조회가 200으로 응답함'],
                    failure_criteria=['서버가 400/401/403으로 차단함', 'payload 변조가 서버 반영 전에 정규화됨', 'endpoint가 호출되지 않음', 'HTML fallback이 반환됨'],
                    evidence_to_capture=['Console 캡처 로그', 'Network 요청 URL/method', '변조 전 payload', '변조 후 payload', '서버 응답 status/body', '화면 상태 변화'],
                    limitations=(f.verification_playbook.limitations if f.verification_playbook else []),
                )
                pri = {
                    'Payment/Point Manipulation Candidate': 1,
                    'Account Recovery Flow Abuse Candidate': 2,
                    'IDOR / Unauthorized Data Access Candidate': 3,
                    'State/Status Manipulation Candidate': 4,
                    'Client-side Validation Bypass': 5,
                }.get(f.vulnerability_type, 99)
                playbook_candidates.append((pri, pb))
            if (f.severity in {'high', 'medium'} and f.confidence != 'low') or any(x in f.vulnerability_type for x in ('Payment', 'Account Recovery', 'IDOR', 'Authorization')):
                executive_findings.append(f)
    # sort, dedup, cap playbooks
    playbook_candidates.sort(key=lambda x: x[0])
    seen_pb: set[tuple[str, str, str]] = set()
    for _, pb in playbook_candidates:
        key = (pb.source_path, pb.endpoint or '', pb.function_name or '')
        if key in seen_pb:
            continue
        seen_pb.add(key)
        verification_playbooks.append(pb)
        if len(verification_playbooks) >= 7:
            break
    return ReadableAnalysisResult(
        finding_count=len(findings),
        findings=findings,
        analyzed_focus=['authorization', 'storage manipulation', 'dom xss', 'client-side validation bypass', 'api call tampering'],
        executive_findings=executive_findings,
        verification_playbooks=verification_playbooks,
        review_candidates=review_candidates,
        project_understanding=project_map,
    )
