import hashlib
import json
from abc import ABC, abstractmethod

from app.core.config import settings
from app.models.schemas import ConsoleSafePoc, FileContent, ReadableAnalysisResult, ReadableEvidence, ReadableFinding
from app.services.ai_clients import GeminiClient, GeminiClientProtocol
from app.services.prompt_builder import build_console_poc_analysis_prompt

KEYWORDS = [
    'login','auth','session','token','jwt','cookie','localStorage','sessionStorage','userType','role','admin','isAdmin',
    'requireAuth','ProtectedRoute','PrivateRoute','navigate','withCredentials','Authorization','innerHTML','outerHTML',
    'insertAdjacentHTML','document.write','eval','Function','location','document.URL','postMessage','input.value',
    'price','amount','status','productId','userId','payment','order','auction'
]


def select_console_relevant_files(files: list[FileContent]) -> list[FileContent]:
    scored: list[tuple[int, FileContent]] = []
    for f in files:
        fname = f.path.lower()
        content = f.content
        score = sum(2 for k in KEYWORDS if k.lower() in fname)
        score += sum(1 for k in KEYWORDS if k in content)
        if score > 0:
            scored.append((score, f))
    scored.sort(key=lambda x: x[0], reverse=True)
    return [f for _, f in scored[:20]]


class ConsolePocAnalyzer(ABC):
    @abstractmethod
    def analyze(self, files: list[FileContent]) -> list[ReadableFinding]:
        raise NotImplementedError


class MockConsolePocAnalyzer(ConsolePocAnalyzer):
    def analyze(self, files: list[FileContent]) -> list[ReadableFinding]:
        findings: list[ReadableFinding] = []
        for f in files:
            c = f.content
            if any(x in c for x in ('userType', 'role', 'isAdmin')) and 'ADMIN' in c and any(x in c for x in ('navigate', '관리자 권한', 'requireAuth')):
                findings.append(self._mk_auth_bypass(f))
            if 'innerHTML' in c and any(x in c for x in ('location', 'document.URL', 'input.value', 'postMessage')):
                findings.append(self._mk_dom_xss(f))
            if any(x in c for x in ('price', 'amount', 'status')) and any(x in c for x in ('FormData', 'axios.post', 'fetch(')):
                findings.append(self._mk_validation_bypass(f))
        return findings

    def _id(self, seed: str) -> str:
        return hashlib.sha256(seed.encode()).hexdigest()[:12]

    def _ev(self, f: FileContent, reason: str) -> list[ReadableEvidence]:
        return [ReadableEvidence(source_path=f.path, start_line=1, end_line=min(20, len(f.content.splitlines()) or 1), snippet=f.content[:160], reason=reason, data_flow=['source -> state/storage -> sink'])]

    def _mk_auth_bypass(self, f: FileContent) -> ReadableFinding:
        return ReadableFinding(id=self._id(f.path+'auth'), title='클라이언트 권한 값 조작을 통한 접근 우회 가능성', vulnerability_type='Client-side Authorization Bypass', severity='high', confidence='medium', affected_files=[f.path], summary='클라이언트 저장소 권한값 기반 분기 가능성이 보입니다.', evidence=self._ev(f, 'userType/role/isAdmin 기반 권한 분기 정황'), console_poc=ConsoleSafePoc(poc_type='browser_console', description='세션 저장값 조작 후 화면 접근 여부 확인', preconditions=['로그인된 브라우저 세션'], steps=['개발자도구 Console 실행','코드 실행 후 새로고침','관리자 UI 접근 여부 확인'], code="sessionStorage.setItem('user', JSON.stringify({ userType: 'ADMIN' })); location.reload();", expected_result='관리자 전용 화면 분기 변화 여부 확인', safety='데이터 변경 없이 화면 접근 가능성만 확인한다.'), attack_scenario=['클라이언트 저장소 값 조작', '화면 라우팅/가드 우회 시도'], impact='클라이언트 단 권한 통제가 우회될 수 있음', root_cause='신뢰 불가능한 클라이언트 상태값에 권한 결정을 의존', remediation='권한 검증은 서버에서 강제하고, UI 분기는 보조 수단으로만 사용', verification_notes=['서버 API 레벨 권한검증 동반 확인 필요'])

    def _mk_dom_xss(self, f: FileContent) -> ReadableFinding:
        return ReadableFinding(id=self._id(f.path+'xss'), title='외부 입력이 DOM sink로 전달될 가능성', vulnerability_type='DOM XSS', severity='high', confidence='medium', affected_files=[f.path], summary='외부 입력이 innerHTML 등 위험 sink로 전달될 수 있습니다.', evidence=self._ev(f, 'location/document.URL/input/postMessage 흐름과 innerHTML 조합'), console_poc=ConsoleSafePoc(poc_type='browser_console', description='hash 입력 기반 alert 실행 가능성 확인', preconditions=['대상 페이지 접근 가능'], steps=['Console 실행','코드 실행','새로고침 후 alert 여부 확인'], code="location.hash = '<img src=x onerror=alert(1)>'; location.reload();", expected_result='alert(1) 수준의 스크립트 실행 여부 확인', safety='alert 수준의 비파괴 스크립트 실행 여부만 확인한다.'), attack_scenario=['외부 입력 제어', 'DOM sink 전달', '스크립트 실행'], impact='사용자 브라우저에서 스크립트 실행 가능성', root_cause='입력값 검증/인코딩 부재', remediation='textContent 사용 또는 안전 sanitizer 적용')

    def _mk_validation_bypass(self, f: FileContent) -> ReadableFinding:
        return ReadableFinding(id=self._id(f.path+'val'), title='클라이언트 검증값 조작을 통한 요청 변조 가능성', vulnerability_type='Client-side Validation Bypass', severity='medium', confidence='low', affected_files=[f.path], summary='요청 전송 전 파라미터를 개발자도구에서 조작할 수 있는 정황입니다.', evidence=self._ev(f, 'price/amount/status와 fetch/axios/FormData 조합'), console_poc=ConsoleSafePoc(poc_type='browser_console', description='요청 전 payload 값 검증/변조 가능성 점검', preconditions=['요청 직전 payload 확인 가능'], steps=['Network/Console에서 payload 구성 코드 확인','요청 전 값 조작 가능 여부 점검'], code='// 요청 전송 전 개발자도구에서 payload(price/amount/status) 변경 가능성만 점검', expected_result='클라이언트 검증 우회 가능성 확인', safety='실제 결제/권한 변경/데이터 변경 요청을 수행하지 않는다.'), attack_scenario=['클라이언트 파라미터 조작', '서버 검증 미비 시 비정상 처리 유도'], impact='비즈니스 로직 오남용 가능성', root_cause='클라이언트 검증에 과도 의존', remediation='서버측 파라미터 무결성/권한/상태 검증 강제')


class GeminiConsolePocAnalyzer(ConsolePocAnalyzer):
    def __init__(self, client: GeminiClientProtocol):
        self.client = client

    def analyze(self, files: list[FileContent]) -> list[ReadableFinding]:
        prompt = build_console_poc_analysis_prompt(files)
        raw = self.client.analyze(prompt)
        try:
            payload = json.loads(raw)
        except Exception:
            return []
        if not isinstance(payload, dict) or not isinstance(payload.get('findings'), list):
            return []
        findings=[]
        for item in payload['findings']:
            try:
                findings.append(ReadableFinding(**item))
            except Exception:
                continue
        return findings


def analyze_console_exploitability(files: list[FileContent], analyzer: ConsolePocAnalyzer | None = None) -> ReadableAnalysisResult:
    selected = select_console_relevant_files(files)
    analyzer = analyzer or (MockConsolePocAnalyzer() if settings.ANALYZER_BACKEND.lower() == 'mock' else GeminiConsolePocAnalyzer(GeminiClient(settings.GEMINI_API_KEY, settings.GEMINI_MODEL)))
    findings = analyzer.analyze(selected)
    return ReadableAnalysisResult(finding_count=len(findings), findings=findings, analyzed_focus=['authorization','storage manipulation','dom xss','client-side validation bypass','api call tampering'])
