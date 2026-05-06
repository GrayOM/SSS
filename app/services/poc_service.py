from app.models.schemas import VulnerabilityFinding
from app.services.ai_clients import GeminiClientProtocol


class GeminiPocGenerator:
    def __init__(self, client: GeminiClientProtocol):
        self.client = client

    def generate_safe_poc(self, finding: VulnerabilityFinding) -> str | None:
        prompt = f"""
Generate a SAFE proof-of-concept snippet for this finding.

Constraints:
- destructive payload 금지
- 데이터 삭제/변조 금지
- 권한 상승 금지
- 외부 연결 금지
- 취약 여부 확인용 safe PoC만 생성
- 보고서에 넣을 수 있는 짧은 PoC 형태로 반환

Finding:
- type: {finding.vulnerability_type}
- severity: {finding.severity}
- source_path: {finding.source_path}
- start_line: {finding.start_line}
- end_line: {finding.end_line}
- root_cause: {finding.root_cause}
- remediation: {finding.remediation}
""".strip()
        return self.client.generate(prompt)


class MockPocGenerator:
    def generate_safe_poc(self, finding: VulnerabilityFinding) -> str | None:
        return finding.safe_poc or 'Safe PoC not generated'
