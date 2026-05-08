import hashlib
import re
from abc import ABC, abstractmethod

from app.core.config import settings
from app.models.schemas import ConsoleSafePoc, FileContent, ReadableAnalysisResult, ReadableEvidence, ReadableFinding
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
    'delete', 'remove', 'payment', 'pay(', '/pay', 'transfer', 'fetch(', 'axios.post', 'axios.delete',
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
        parameters: tuple[str, ...] = tuple()
        if f.vulnerability_type == 'Client-side Validation Bypass' and f.evidence:
            endpoint = next((x.replace('endpoint: ', '') for x in f.evidence[0].data_flow if x.startswith('endpoint: ')), '')
            parameters = tuple(sorted([x.replace('parameter: ', '') for x in f.evidence[0].data_flow if x.startswith('parameter: ')]))
        key = (f.vulnerability_type, endpoint, parameters, f.root_cause)
        if key not in grouped:
            grouped[key] = f
            continue
        g = grouped[key]
        g.affected_files = sorted(set(g.affected_files + f.affected_files))
        g.evidence = (g.evidence + f.evidence)[:5]
    return list(grouped.values())


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
                        findings.append(self._mk_validation_bypass(f, endpoint=cand.endpoint, method=cand.method, parameters=cand.parameters, sink=cand.sink))
        return _dedup_findings(findings)

    def _id(self, seed: str) -> str:
        return hashlib.sha256(seed.encode()).hexdigest()[:12]

    def _ev(self, f: FileContent, reason: str) -> list[ReadableEvidence]:
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
                safety='데이터 변경 없이 화면 접근 가능성만 확인한다.',
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

    def _mk_validation_bypass(self, f: FileContent, endpoint: str | None = None, method: str | None = None, parameters: list[str] | None = None, sink: str | None = None) -> ReadableFinding:
        endpoint = endpoint or _extract_endpoint(f.content)
        parameters = parameters or _extract_validation_parameters(f.content)
        method = method or 'UNKNOWN'
        sink = sink or ('axios.post' if 'axios.post' in f.content.lower() else ('axios.put' if 'axios.put' in f.content.lower() else ('fetch' if 'fetch(' in f.content.lower() else 'formdata')))
        flow = ['source -> state/storage -> sink']
        flow.append(f'method: {method}')
        flow.append(f"endpoint: {endpoint or 'UNKNOWN'}")
        for k in parameters:
            flow.append(f'parameter: {k}')
        flow.append(f'sink: {sink}')
        start_line, end_line, snippet = _extract_relevant_snippet(f.content, VALIDATION_SNIPPET_KEYS)
        ev = [ReadableEvidence(source_path=f.path, start_line=start_line, end_line=end_line, snippet=snippet, reason='검증값+요청 API 조합', data_flow=flow)]
        notes = []
        conf = 'low'
        poc_type = 'manual_check'
        poc_code = None
        if endpoint == 'UNKNOWN':
            notes.append('endpoint variable requires manual review')
        if method == 'GET' and endpoint and endpoint != 'UNKNOWN':
            poc_type = 'browser_console'
            poc_code = f"fetch('{endpoint}', {{ method: 'GET' }}).then(r => r.status)"
            conf = 'medium'
        return ReadableFinding(
            id=self._id(f.path + 'v'),
            title='클라이언트 검증값 조작을 통한 요청 변조 가능성',
            vulnerability_type='Client-side Validation Bypass',
            severity='medium',
            confidence=conf,
            affected_files=[f.path],
            summary='요청 전송 전 값 조작 가능성 정황입니다.',
            evidence=ev,
            console_poc=ConsoleSafePoc(
                poc_type=poc_type,
                description='payload 점검 및 비파괴 확인',
                preconditions=['요청 전 payload 확인'],
                steps=['개발자도구 점검'],
                code=poc_code,
                expected_result='변조 가능성 확인',
                safety='실제 변경 요청을 수행하지 않는다.',
            ),
            attack_scenario=['파라미터 조작'],
            impact='비즈니스 로직 오남용',
            root_cause='클라이언트 검증 의존',
            remediation='서버 검증 강제',
            verification_notes=notes,
        )


class GeminiConsolePocAnalyzer(ConsolePocAnalyzer):
    def __init__(self, client: GeminiClientProtocol):
        self.client = client

    def analyze(self, files: list[FileContent]) -> list[ReadableFinding]:
        candidates = extract_api_call_candidates(files).candidates
        payload = extract_json_payload(self.client.analyze(build_candidate_analysis_prompt(files, candidates)))
        if payload is None or not isinstance(payload.get('findings'), list):
            return []

        out: list[ReadableFinding] = []
        for item in payload['findings']:
            if not isinstance(item, dict):
                continue
            if item.get('severity') not in ALLOWED_SEVERITIES or item.get('confidence') not in ALLOWED_CONFIDENCES:
                continue
            if not isinstance(item.get('evidence'), list) or not item['evidence']:
                continue
            if not isinstance(item.get('attack_scenario'), list) or not item['attack_scenario']:
                continue

            poc = item.get('console_poc')
            if isinstance(poc, dict):
                if poc.get('poc_type') not in ALLOWED_POC_TYPES:
                    continue
                code = (poc.get('code') or '').lower()
                if any(x in code for x in DANGEROUS_POC_PATTERNS):
                    poc['code'] = None
                    notes = item.get('verification_notes') or []
                    notes.append('위험 요청 가능성이 있어 Console PoC code를 제거했습니다.')
                    item['verification_notes'] = notes

            try:
                out.append(ReadableFinding(**item))
            except Exception:
                continue
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
