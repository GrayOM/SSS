import hashlib
import re
from abc import ABC, abstractmethod

from app.core.config import settings
from app.models.schemas import ApiCallCandidate, ConsoleSafePoc, FileContent, ReadableAnalysisResult, ReadableEvidence, ReadableFinding
from app.services.ai_clients import GeminiClient, GeminiClientProtocol
from app.services.api_candidate_extractor import extract_api_call_candidates
from app.services.json_utils import extract_json_payload
from app.services.prompt_builder import build_candidate_analysis_prompt, build_console_poc_analysis_prompt

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
    'xmlhttprequest', 'document.cookie=', 'child_process', 'exec', 'eval(',
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
            endpoint = next((x.replace('endpoint: ', '') for x in flows if x.startswith('endpoint: ')), '')
            method = next((x.replace('method: ', '') for x in flows if x.startswith('method: ')), '')
            sink = next((x.replace('sink: ', '') for x in flows if x.startswith('sink: ')), '')
            parameters = tuple(sorted([x.replace('parameter: ', '') for x in flows if x.startswith('parameter: ')]))
        key = (f.vulnerability_type, method, endpoint, parameters, sink, f.root_cause)
        if key not in grouped:
            grouped[key] = f
            continue
        g = grouped[key]
        g.affected_files = sorted(set(g.affected_files + f.affected_files))
        g.evidence = (g.evidence + f.evidence)[:5]
    return list(grouped.values())


def _is_allowed_guarded_poc_code(code: str) -> bool:
    low = code.lower()
    if 'fetch(' not in low:
        return True
    if re.search(r"method\s*:\s*['\"]delete['\"]", low):
        return False
    if any(x in low for x in ('refund', 'transfer', 'withdraw', 'delete', 'remove', 'bulk')):
        return False
    is_mutation = bool(re.search(r"method\s*:\s*['\"](post|put|patch)['\"]", low))
    if is_mutation:
        return 'confirm_authorized_test = false' in low and 'if (!confirm_authorized_test)' in low
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
        for f in files:
            c = f.content
            c_lower = c.lower()
            if (
                any(x in c_lower for x in ('usertype', 'role', 'isadmin'))
                and 'admin' in c_lower
                and any(x in c_lower for x in ('navigate', '관리자 권한', 'requireauth'))
            ):
                findings.append(self._mk_auth_bypass(f, files, missing_deps))
            if 'innerhtml' in c_lower and any(x in c_lower for x in ('location', 'document.url', 'input.value', 'postmessage')):
                findings.append(self._mk_dom_xss(f))
            if any(x in c_lower for x in ('axios.', 'fetch(', 'apiclient.', 'request.', 'httpclient.', 'client.', '$.ajax', 'jquery.ajax', 'formdata')):
                for cand in extract_api_call_candidates([f]).candidates:
                    if cand.sink.startswith(('axios', 'fetch', '$.ajax', 'apiClient', 'request', 'httpClient', 'client')):
                        finding = self._mk_validation_bypass(f, candidate=cand)
                        if finding is not None:
                            findings.append(finding)
        return _dedup_findings(findings)

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
        base_var = self._is_base_variable_endpoint(endpoint)
        endpoint = self._replace_endpoint_placeholders(endpoint)
        endpoint_decl = (
            f"  const API_BASE = 'https://TARGET_BASE_URL';\n  const endpoint = `${{API_BASE}}{self._strip_base_variable(endpoint)}`;"
            if base_var
            else f"  const endpoint = '{endpoint}';"
        )
        return f"""(async () => {{
{endpoint_decl}

  const res = await fetch(endpoint, {{
    method: 'GET',
    credentials: 'include'
  }});

  const text = await res.text();

  console.log('[PoC] read-only check:', {{
    endpoint,
    status: res.status,
    body: text
  }});
}})();"""

    def _build_guarded_mutation_poc(self, method: str, endpoint: str, parameters: list[str]) -> str:
        base_var = self._is_base_variable_endpoint(endpoint)
        endpoint = self._replace_endpoint_placeholders(endpoint)
        endpoint_decl = (
            f"  const API_BASE = 'https://TARGET_BASE_URL';\n  const endpoint = `${{API_BASE}}{self._strip_base_variable(endpoint)}`;"
            if base_var
            else f"  const endpoint = '{endpoint}';"
        )
        payload = self._build_payload_from_parameters(parameters)
        payload_lines = '\n'.join([f"    {repr(k)}: {repr(v)}," for k, v in payload.items()])
        return f"""(async () => {{
  const CONFIRM_AUTHORIZED_TEST = false;
  if (!CONFIRM_AUTHORIZED_TEST) {{
    throw new Error('승인된 테스트 환경에서만 true로 변경 후 실행하세요.');
  }}

{endpoint_decl}

  const payload = {{
{payload_lines}
  }};

  const res = await fetch(endpoint, {{
    method: '{method}',
    credentials: 'include',
    headers: {{
      'Content-Type': 'application/json'
    }},
    body: JSON.stringify(payload)
  }});

  const text = await res.text();

  console.log('[PoC] guarded request check:', {{
    endpoint,
    payload,
    status: res.status,
    body: text
  }});
}})();"""

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
        )

    def _mk_dom_xss(self, f: FileContent) -> ReadableFinding:
        start_line, end_line, snippet = _extract_relevant_snippet(f.content, DOM_SNIPPET_KEYS)
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

    def _classify_api_candidate(self, candidate: ApiCallCandidate) -> dict[str, str]:
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
        parameters = candidate.parameters or _extract_validation_parameters(f.content)
        method = (candidate.method or 'UNKNOWN').upper()
        sink = candidate.sink or 'UNKNOWN'

        flow = ['source -> state/storage -> sink', f'method: {method}', f'endpoint: {endpoint}']
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

        if endpoint == 'UNKNOWN':
            notes.append('endpoint variable requires manual review')

        important_get = (
            any(k in endpoint.lower() for k in ('session', 'auth', 'me', 'profile', 'wallet', 'order'))
            or any(p.lower() in {'userid', 'memberid', 'accountid', 'orderid', 'paymentid'} for p in parameters)
            or any('endpoint variable requires manual review' in n for n in (candidate.notes or []))
        )
        if method == 'GET' and endpoint != 'UNKNOWN' and important_get:
            poc_type = 'browser_console'
            poc_code = self._build_readonly_get_poc(endpoint)
            conf = 'medium'
            safety = '조회형 요청으로 응답 status/body만 확인한다.'
        elif method == 'GET' and not important_get:
            return None
        elif method in {'POST', 'PUT', 'PATCH'}:
            if endpoint != 'UNKNOWN' and not endpoint.startswith('TEST_VALUE') and not self._is_irreversible_or_high_risk(method, endpoint, parameters):
                poc_type = 'browser_console'
                poc_code = self._build_guarded_mutation_poc(method, endpoint, parameters)
                conf = 'medium'
                notes.append('Guarded PoC: CONFIRM_AUTHORIZED_TEST 값을 true로 변경해야 실행됩니다.')
                safety = '기본값 false guard로 즉시 실행되지 않으며, 승인된 테스트 계정/테스트 데이터에서만 실행해야 한다.'
                if self._is_base_variable_endpoint(endpoint):
                    notes.append('API_BASE 값을 실제 대상 URL로 변경해야 합니다.')
            else:
                notes.append('비가역/고위험 요청은 실행형 Console PoC를 생성하지 않았습니다.')
        elif method == 'DELETE' or self._is_irreversible_or_high_risk(method, endpoint, parameters):
            notes.append('비가역/고위험 요청은 실행형 Console PoC를 생성하지 않았습니다.')

        classification = self._classify_api_candidate(candidate)
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
                description=('승인된 테스트 환경에서 실행 가능한 Guarded PoC' if method in {'POST', 'PUT', 'PATCH'} and poc_code else 'payload 점검 및 비파괴 확인'),
                preconditions=(['승인된 테스트 계정', '테스트 데이터 또는 테스트 주문', 'CONFIRM_AUTHORIZED_TEST 값을 true로 변경해야 실행됨'] if method in {'POST', 'PUT', 'PATCH'} and poc_code else ['요청 전 payload 확인']),
                steps=(['Console에 PoC 입력', 'CONFIRM_AUTHORIZED_TEST를 true로 변경', '응답 status/body 확인'] if method in {'POST', 'PUT', 'PATCH'} and poc_code else ['개발자도구 점검']),
                code=poc_code,
                expected_result=('서버가 조작된 payload를 허용하는지 status/body로 확인' if method in {'POST', 'PUT', 'PATCH'} and poc_code else '변조 가능성 확인'),
                safety=safety,
            ),
            attack_scenario=['파라미터 조작'],
            impact=classification['impact'],
            root_cause=classification['root_cause'],
            remediation=classification['remediation'],
            verification_notes=notes,
        )



class GeminiConsolePocAnalyzer(ConsolePocAnalyzer):
    def __init__(self, client: GeminiClientProtocol):
        self.client = client

    def analyze(self, files: list[FileContent]) -> list[ReadableFinding]:
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

        candidates = extract_api_call_candidates(files).candidates
        payload = extract_json_payload(self.client.analyze(build_candidate_analysis_prompt(files, candidates)))
        if payload is None or not isinstance(payload.get('findings'), list):
            return []

        out: list[ReadableFinding] = []
        dropped_count = 0
        for item in payload['findings']:
            if not isinstance(item, dict):
                dropped_count += 1
                continue
            if item.get('severity') not in ALLOWED_SEVERITIES or item.get('confidence') not in ALLOWED_CONFIDENCES:
                dropped_count += 1
                continue
            if not isinstance(item.get('evidence'), list) or not item['evidence']:
                dropped_count += 1
                continue
            if not isinstance(item.get('attack_scenario'), list) or not item['attack_scenario']:
                dropped_count += 1
                continue

            poc = item.get('console_poc')
            if isinstance(poc, dict):
                if poc.get('poc_type') not in ALLOWED_POC_TYPES:
                    continue
                code = (poc.get('code') or '').lower()
                if any(x in code for x in DANGEROUS_POC_PATTERNS) or not _is_allowed_guarded_poc_code(code):
                    poc['code'] = None
                    notes = item.get('verification_notes') or []
                    notes.append('위험 요청 가능성이 있어 Console PoC code를 제거했습니다.')
                    item['verification_notes'] = notes

            try:
                _ensure_finding_id(item)
                out.append(ReadableFinding(**item))
            except Exception:
                dropped_count += 1
                continue
        # NOTE: dropped_count is kept for debug/investigation when malformed Gemini items are skipped.
        return out


def analyze_console_exploitability(files: list[FileContent], analyzer: ConsolePocAnalyzer | None = None) -> ReadableAnalysisResult:
    selected = select_console_relevant_files(files)
    analyzer = analyzer or (
        MockConsolePocAnalyzer()
        if settings.ANALYZER_BACKEND.lower() == 'mock'
        else GeminiConsolePocAnalyzer(GeminiClient(settings.GEMINI_API_KEY, settings.GEMINI_MODEL))
    )
    findings = analyzer.analyze(selected)
    return ReadableAnalysisResult(
        finding_count=len(findings),
        findings=findings,
        analyzed_focus=['authorization', 'storage manipulation', 'dom xss', 'client-side validation bypass', 'api call tampering'],
    )
