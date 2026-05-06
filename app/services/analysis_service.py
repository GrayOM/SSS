import hashlib
from abc import ABC, abstractmethod

from app.models.schemas import AnalysisEvidence, AnalysisResult, CodeChunk, VulnerabilityFinding


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

        if 'innerHTML' in content and any(x in content for x in ('location', 'document.URL', 'document.location', 'input.value')):
            findings.append(self._make_finding(
                chunk,
                'DOM XSS',
                'high',
                'medium',
                '외부 입력이 innerHTML sink로 전달될 가능성',
                [
                    '공격자가 외부 입력값을 조작한다.',
                    '조작된 값이 DOM sink(innerHTML)에 전달된다.',
                    '브라우저에서 스크립트가 실행될 수 있다.',
                ],
                '<img src=x onerror=alert(1)>',
                '사용자 브라우저에서 임의 스크립트 실행 가능',
                '외부 입력이 검증/인코딩 없이 innerHTML에 전달됨',
                'innerHTML 대신 textContent 사용 또는 DOMPurify 등 신뢰 가능한 sanitizer 적용',
                ['CWE-79'],
            ))

        if 'eval(' in content:
            findings.append(self._make_finding(
                chunk,
                'Unsafe eval',
                'high',
                'medium',
                'eval() 사용으로 코드 실행 위험',
                ['공격자가 문자열 입력에 코드 조각을 삽입한다.', 'eval이 삽입된 문자열을 실행할 수 있다.'],
                'eval input에 alert(1) 수준의 비파괴 테스트 문자열 사용',
                '임의 코드 실행 가능성',
                '신뢰되지 않은 데이터가 eval에 전달됨',
                'eval 사용 제거 및 안전한 파서/매핑 기반 로직으로 대체',
                ['CWE-95'],
            ))

        if 'child_process.exec' in content or 'exec(' in content:
            findings.append(self._make_finding(
                chunk,
                'Command Injection',
                'critical',
                'low',
                '명령 실행 함수에 사용자 입력 결합 가능성',
                ['공격자가 명령 문자열 입력을 조작한다.', '서버에서 시스템 명령이 실행될 수 있다.'],
                'whoami 또는 id 같은 비파괴 명령으로 실행 여부 확인',
                '서버 원격 명령 실행 가능성',
                '명령 실행 함수에 입력 검증 없이 데이터가 전달됨',
                '파라미터 화/allowlist 적용 및 shell 실행 경로 제거',
                ['CWE-78'],
            ))

        return findings


def _deterministic_id(chunk: CodeChunk, vulnerability_type: str) -> str:
    base = f'{chunk.source_path}:{chunk.chunk_index}:{vulnerability_type}'
    return hashlib.sha256(base.encode('utf-8')).hexdigest()[:12]


def analyze_chunks(chunks: list[CodeChunk], analyzer: Analyzer | None = None) -> AnalysisResult:
    analyzer = analyzer or MockAnalyzer()
    findings: list[VulnerabilityFinding] = []
    skipped_chunks: list[CodeChunk] = []
    analyzed_chunks = 0

    for chunk in chunks:
        if not chunk.content:
            skipped_chunks.append(chunk)
            continue

        analyzed_chunks += 1
        chunk_findings = analyzer.analyze_chunk(chunk)
        for finding in chunk_findings:
            findings.append(finding.model_copy(update={'id': _deterministic_id(chunk, finding.vulnerability_type)}))

    return AnalysisResult(
        total_chunks=len(chunks),
        analyzed_chunks=analyzed_chunks,
        finding_count=len(findings),
        findings=findings,
        skipped_chunks=skipped_chunks,
    )
