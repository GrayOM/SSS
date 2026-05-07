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
ALLOWED_SEVERITIES = {'low', 'medium', 'high', 'critical'}
ALLOWED_CONFIDENCES = {'low', 'medium', 'high'}
ALLOWED_POC_TYPES = {'browser_console', 'manual_check'}
DANGEROUS_POC_PATTERNS = ('delete', 'remove', 'payment', 'pay', 'transfer', 'fetch(', 'axios.post', 'axios.delete', 'xmlhttprequest', 'document.cookie=', 'child_process', 'exec', 'eval(')


def _extract_json_payload(raw: str) -> dict | None:
    text = raw.strip()
    for candidate in (text,):
        try:
            payload = json.loads(candidate)
            return payload if isinstance(payload, dict) else None
        except Exception:
            pass
    if text.startswith('```'):
        lines = text.splitlines()
        if len(lines) >= 3 and lines[-1].strip() == '```':
            body = '\n'.join(lines[1:-1]).strip()
            try:
                payload = json.loads(body)
                return payload if isinstance(payload, dict) else None
            except Exception:
                pass
    s, e = text.find('{'), text.rfind('}')
    if s != -1 and e > s:
        try:
            payload = json.loads(text[s:e+1])
            return payload if isinstance(payload, dict) else None
        except Exception:
            return None
    return None


def select_console_relevant_files(files: list[FileContent]) -> list[FileContent]:
    scored = []
    for f in files:
        fname = f.path.lower()
        score = sum(2 for k in KEYWORDS if k.lower() in fname) + sum(1 for k in KEYWORDS if k in f.content)
        if score > 0:
            scored.append((score, f))
    scored.sort(key=lambda x: x[0], reverse=True)
    return [f for _, f in scored[:20]]


class ConsolePocAnalyzer(ABC):
    @abstractmethod
    def analyze(self, files: list[FileContent]) -> list[ReadableFinding]: ...


class MockConsolePocAnalyzer(ConsolePocAnalyzer):
    # same as before trimmed
    def analyze(self, files: list[FileContent]) -> list[ReadableFinding]:
        findings=[]
        for f in files:
            c=f.content
            if any(x in c for x in ('userType','role','isAdmin')) and 'ADMIN' in c and any(x in c for x in ('navigate','관리자 권한','requireAuth')):
                findings.append(self._mk_auth_bypass(f))
            if 'innerHTML' in c and any(x in c for x in ('location','document.URL','input.value','postMessage')):
                findings.append(self._mk_dom_xss(f))
            if any(x in c for x in ('price','amount','status')) and any(x in c for x in ('FormData','axios.post','fetch(')):
                findings.append(self._mk_validation_bypass(f))
        return findings
    def _id(self, s): return hashlib.sha256(s.encode()).hexdigest()[:12]
    def _ev(self,f,r): return [ReadableEvidence(source_path=f.path,start_line=1,end_line=min(20,len(f.content.splitlines()) or 1),snippet=f.content[:160],reason=r,data_flow=['source -> state/storage -> sink'])]
    def _mk_auth_bypass(self,f): return ReadableFinding(id=self._id(f.path+'a'),title='클라이언트 권한 값 조작을 통한 접근 우회 가능성',vulnerability_type='Client-side Authorization Bypass',severity='high',confidence='medium',affected_files=[f.path],summary='클라이언트 저장소 권한값 기반 분기 가능성이 보입니다.',evidence=self._ev(f,'권한 분기 정황'),console_poc=ConsoleSafePoc(poc_type='browser_console',description='세션 저장값 조작 확인',preconditions=['로그인 세션'],steps=['Console 실행','코드 실행','새로고침'],code="sessionStorage.setItem('user', JSON.stringify({ userType: 'ADMIN' })); location.reload();",expected_result='화면 분기 변화 확인',safety='데이터 변경 없이 화면 접근 가능성만 확인한다.'),attack_scenario=['저장소 값 조작'],impact='클라이언트 단 통제 우회 가능성',root_cause='클라이언트 상태 의존',remediation='서버 권한 검증 강제')
    def _mk_dom_xss(self,f): return ReadableFinding(id=self._id(f.path+'x'),title='외부 입력이 DOM sink로 전달될 가능성',vulnerability_type='DOM XSS',severity='high',confidence='medium',affected_files=[f.path],summary='외부 입력이 위험 sink로 전달될 수 있습니다.',evidence=self._ev(f,'source-sink 조합'),console_poc=ConsoleSafePoc(poc_type='browser_console',description='hash 기반 확인',preconditions=['페이지 접근 가능'],steps=['Console 실행','코드 실행','새로고침'],code="location.hash = '<img src=x onerror=alert(1)>'; location.reload();",expected_result='alert 실행 여부',safety='alert 수준의 비파괴 스크립트 실행 여부만 확인한다.'),attack_scenario=['외부 입력 제어','DOM sink 전달'],impact='스크립트 실행 가능성',root_cause='검증/인코딩 부재',remediation='안전한 DOM API 사용')
    def _mk_validation_bypass(self,f): return ReadableFinding(id=self._id(f.path+'v'),title='클라이언트 검증값 조작을 통한 요청 변조 가능성',vulnerability_type='Client-side Validation Bypass',severity='medium',confidence='low',affected_files=[f.path],summary='요청 전송 전 값 조작 가능성 정황입니다.',evidence=self._ev(f,'검증값+요청 API 조합'),console_poc=ConsoleSafePoc(poc_type='browser_console',description='payload 점검',preconditions=['요청 전 payload 확인'],steps=['개발자도구 점검'],code='// payload 값 변조 가능성만 점검',expected_result='변조 가능성 확인',safety='실제 변경 요청을 수행하지 않는다.'),attack_scenario=['파라미터 조작'],impact='비즈니스 로직 오남용',root_cause='클라이언트 검증 의존',remediation='서버 검증 강제')


class GeminiConsolePocAnalyzer(ConsolePocAnalyzer):
    def __init__(self, client: GeminiClientProtocol):
        self.client = client

    def analyze(self, files: list[FileContent]) -> list[ReadableFinding]:
        payload = _extract_json_payload(self.client.analyze(build_console_poc_analysis_prompt(files)))
        if payload is None or not isinstance(payload.get('findings'), list):
            return []
        out=[]
        for item in payload['findings']:
            if not isinstance(item, dict):
                continue
            if item.get('severity') not in ALLOWED_SEVERITIES or item.get('confidence') not in ALLOWED_CONFIDENCES:
                continue
            if not isinstance(item.get('evidence'), list) or not item['evidence']:
                continue
            if not isinstance(item.get('attack_scenario'), list) or not item['attack_scenario']:
                continue
            poc=item.get('console_poc')
            if isinstance(poc, dict):
                if poc.get('poc_type') not in ALLOWED_POC_TYPES:
                    continue
                code=(poc.get('code') or '').lower()
                if any(x in code for x in DANGEROUS_POC_PATTERNS):
                    poc['code']=None
            try:
                out.append(ReadableFinding(**item))
            except Exception:
                continue
        return out


def analyze_console_exploitability(files: list[FileContent], analyzer: ConsolePocAnalyzer | None = None) -> ReadableAnalysisResult:
    selected = select_console_relevant_files(files)
    analyzer = analyzer or (MockConsolePocAnalyzer() if settings.ANALYZER_BACKEND.lower() == 'mock' else GeminiConsolePocAnalyzer(GeminiClient(settings.GEMINI_API_KEY, settings.GEMINI_MODEL)))
    findings = analyzer.analyze(selected)
    return ReadableAnalysisResult(finding_count=len(findings), findings=findings, analyzed_focus=['authorization','storage manipulation','dom xss','client-side validation bypass','api call tampering'])
