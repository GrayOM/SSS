import hashlib
import re
from abc import ABC, abstractmethod

from app.core.config import settings
from app.models.schemas import AnalysisEvidence, AnalysisResult, CodeChunk, VulnerabilityFinding
from app.services.ai_clients import GeminiClient, GeminiClientProtocol
from app.services.json_utils import extract_json_payload
from app.services.prompt_builder import build_analysis_prompt

DOM_XSS_SOURCES = (
    'location.hash', 'location.search', 'document.URL', 'document.location',
    'input.value', 'URLSearchParams', 'event.data', 'window.name',
)
DOM_XSS_SINKS = ('innerHTML', 'outerHTML', 'insertAdjacentHTML', 'document.write')
EVAL_PATTERN = 'eval('
COMMAND_EXEC_PATTERNS = (
    'child_process.exec',
    'child_process.execSync',
    'require("child_process").exec',
    "require('child_process').exec",
)

ALLOWED_SEVERITIES = {'low', 'medium', 'high', 'critical'}
ALLOWED_CONFIDENCES = {'low', 'medium', 'high'}




def _is_probable_build_artifact_path_or_content(path: str, content: str) -> bool:
    path_l = path.lower()
    name = path_l.rsplit('/', 1)[-1]
    path_patterns = (
        r'^(app|commons|framework|webpack-runtime|runtime|polyfill|polyfills|vendors?|component---.+)-[a-f0-9]{8,}\.js$',
        r'^[0-9]+-[a-f0-9]{8,}\.js$',
        r'^[a-f0-9]{8,}-[a-f0-9]{8,}\.js$',
        r'^.+-[a-f0-9]{12,}\.js$',
    )
    if any(re.match(p, name) for p in path_patterns):
        return True
    if any(seg in path_l for seg in ('/vendor/', '/vendors/', '/node_modules/', '/lib/', '/plugins/')):
        return True
    head = content[:8192].lower()
    return any(sig in head for sig in ('webpackchunk', '__webpack_require__', '.license.txt', 'sourcemappingurl'))


def _has_dom_xss_flow(content: str) -> bool:
    lines = content.splitlines() or ['']
    for idx, line in enumerate(lines):
        low = line.lower()
        if not any(s.lower() in low for s in DOM_XSS_SINKS):
            continue
        if 'testelement.innerhtml' in low:
            continue
        if "innerhtml = ''" in low or 'innerhtml = ""' in low:
            continue
        if re.search(r"innerhtml\s*=\s*['\"][^'\"]*['\"]\s*;?", line, re.IGNORECASE):
            continue
        start = max(0, idx - 6)
        end = min(len(lines) - 1, idx + 6)
        window = '\n'.join(lines[start:end + 1])
        if any(src in window for src in DOM_XSS_SOURCES):
            return True
    return False

class Analyzer(ABC):
    @abstractmethod
    def analyze_chunk(self, chunk: CodeChunk) -> list[VulnerabilityFinding]:
        raise NotImplementedError


class MockAnalyzer(Analyzer):
    """Mock analyzer for pipeline validation only; not a real security analysis engine."""

    def _snippet(self, content: str, limit: int = 300) -> str:
        return content[:limit]

    def _make_finding(self, chunk: CodeChunk, vulnerability_type: str, severity: str, confidence: str,
                      reason: str, attack_scenario: list[str], safe_poc: str | None,
                      impact: str, root_cause: str, remediation: str, related_cwe: list[str]) -> VulnerabilityFinding:
        evidence = [AnalysisEvidence(
            source_path=chunk.source_path,
            start_line=chunk.start_line,
            end_line=chunk.end_line,
            snippet=self._snippet(chunk.content),
            reason=reason,
        )]
        return VulnerabilityFinding(
            id='',
            vulnerability_type=vulnerability_type,
            severity=severity,
            confidence=confidence,
            source_path=chunk.source_path,
            start_line=chunk.start_line,
            end_line=chunk.end_line,
            evidence=evidence,
            attack_scenario=attack_scenario,
            safe_poc=safe_poc,
            impact=impact,
            root_cause=root_cause,
            remediation=remediation,
            related_cwe=related_cwe,
        )

    def analyze_chunk(self, chunk: CodeChunk) -> list[VulnerabilityFinding]:
        findings: list[VulnerabilityFinding] = []
        content = chunk.content

        if not _is_probable_build_artifact_path_or_content(chunk.source_path, content) and _has_dom_xss_flow(content):
            findings.append(self._make_finding(
                chunk, 'DOM XSS', 'high', 'medium', '외부 입력이 innerHTML sink로 전달될 가능성',
                ['공격자가 외부 입력값을 조작한다.', '조작된 값이 DOM sink(innerHTML)에 전달된다.', '브라우저에서 스크립트가 실행될 수 있다.'],
                '<img src=x onerror=alert(1)>', '사용자 브라우저에서 임의 스크립트 실행 가능',
                '외부 입력이 검증/인코딩 없이 innerHTML에 전달됨',
                'innerHTML 대신 textContent 사용 또는 DOMPurify 등 신뢰 가능한 sanitizer 적용', ['CWE-79']
            ))

        if EVAL_PATTERN in content:
            findings.append(self._make_finding(
                chunk, 'Unsafe eval', 'high', 'medium', 'eval() 사용으로 코드 실행 위험',
                ['공격자가 문자열 입력에 코드 조각을 삽입한다.', 'eval이 삽입된 문자열을 실행할 수 있다.'],
                'eval input에 alert(1) 수준의 비파괴 테스트 문자열 사용', '임의 코드 실행 가능성',
                '신뢰되지 않은 데이터가 eval에 전달됨', 'eval 사용 제거 및 안전한 파서/매핑 기반 로직으로 대체', ['CWE-95']
            ))

        if any(p in content for p in COMMAND_EXEC_PATTERNS):
            findings.append(self._make_finding(
                chunk, 'Command Injection', 'critical', 'low', '명령 실행 함수에 사용자 입력 결합 가능성',
                ['공격자가 명령 문자열 입력을 조작한다.', '서버에서 시스템 명령이 실행될 수 있다.'],
                'whoami 또는 id 같은 비파괴 명령으로 실행 여부 확인', '서버 원격 명령 실행 가능성',
                '명령 실행 함수에 입력 검증 없이 데이터가 전달됨', '파라미터 화/allowlist 적용 및 shell 실행 경로 제거', ['CWE-78']
            ))

        return findings


class GeminiAnalyzer(Analyzer):
    def __init__(self, client: GeminiClientProtocol):
        self.client = client

    def analyze_chunk(self, chunk: CodeChunk) -> list[VulnerabilityFinding]:
        prompt = build_analysis_prompt(chunk)
        raw = self.client.analyze(prompt)

        payload = extract_json_payload(raw)
        if payload is None:
            return []

        findings_data = payload.get('findings')
        if not isinstance(findings_data, list):
            return []

        findings: list[VulnerabilityFinding] = []
        for item in findings_data:
            required = ['vulnerability_type', 'severity', 'confidence', 'source_path', 'start_line', 'end_line', 'evidence', 'attack_scenario', 'impact', 'root_cause', 'remediation']
            if not isinstance(item, dict) or any(k not in item for k in required):
                continue

            if item['severity'] not in ALLOWED_SEVERITIES:
                continue
            if item['confidence'] not in ALLOWED_CONFIDENCES:
                continue
            if not isinstance(item['evidence'], list) or not item['evidence']:
                continue
            if not isinstance(item['attack_scenario'], list) or not item['attack_scenario']:
                continue

            try:
                evidence = [AnalysisEvidence(**ev) for ev in item['evidence'] if isinstance(ev, dict)]
                if not evidence:
                    continue
                findings.append(VulnerabilityFinding(
                    id='',
                    vulnerability_type=item['vulnerability_type'],
                    severity=item['severity'],
                    confidence=item['confidence'],
                    source_path=item['source_path'],
                    start_line=item['start_line'],
                    end_line=item['end_line'],
                    evidence=evidence,
                    attack_scenario=item['attack_scenario'],
                    safe_poc=item.get('safe_poc'),
                    impact=item['impact'],
                    root_cause=item['root_cause'],
                    remediation=item['remediation'],
                    related_cwe=item.get('related_cwe', []),
                ))
            except Exception:
                continue

        return findings


def get_analyzer() -> Analyzer:
    backend = settings.ANALYZER_BACKEND.lower()
    if backend == 'mock':
        return MockAnalyzer()
    if backend == 'gemini':
        return GeminiAnalyzer(GeminiClient(settings.GEMINI_API_KEY, settings.GEMINI_MODEL))
    raise ValueError(
        f'Unknown analyzer backend: {settings.ANALYZER_BACKEND}. '
        'Supported backends: mock, gemini. OpenAI/Claude backends are not implemented yet.'
    )


def _deterministic_id(chunk: CodeChunk, finding: VulnerabilityFinding, occurrence_index: int) -> str:
    evidence_reason = finding.evidence[0].reason if finding.evidence else ''
    evidence_snippet = finding.evidence[0].snippet[:50] if finding.evidence else ''
    base = '|'.join([
        chunk.source_path,
        str(chunk.chunk_index),
        finding.vulnerability_type,
        str(finding.start_line),
        str(finding.end_line),
        evidence_reason,
        evidence_snippet,
        str(occurrence_index),
        chunk.chunk_hash,
    ])
    return hashlib.sha256(base.encode('utf-8')).hexdigest()[:12]


def analyze_chunks(chunks: list[CodeChunk], analyzer: Analyzer | None = None) -> AnalysisResult:
    analyzer = analyzer or get_analyzer()
    findings: list[VulnerabilityFinding] = []
    skipped_chunks: list[CodeChunk] = []
    analyzed_chunks = 0

    for chunk in chunks:
        if not chunk.content:
            skipped_chunks.append(chunk)
            continue

        analyzed_chunks += 1
        chunk_findings = analyzer.analyze_chunk(chunk)
        for occurrence_index, finding in enumerate(chunk_findings):
            findings.append(finding.model_copy(update={'id': _deterministic_id(chunk, finding, occurrence_index)}))

    return AnalysisResult(
        total_chunks=len(chunks),
        analyzed_chunks=analyzed_chunks,
        finding_count=len(findings),
        findings=findings,
        skipped_chunks=skipped_chunks,
    )
