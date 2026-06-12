"""Secret Detection Agent — API keys, tokens, credentials in all resources."""
from __future__ import annotations
import logging

from scanner.models import AgentResult, CrawlResult, Finding, Severity
from scanner.tools.pattern_tools import scan_secrets

log = logging.getLogger("secret_detection_agent")

STR_TO_SEVERITY = {
    "Critical": Severity.CRITICAL,
    "High": Severity.HIGH,
    "Medium": Severity.MEDIUM,
    "Low": Severity.LOW,
}

# False-positive suppressors
FP_SNIPPETS = [
    "example", "placeholder", "your-key", "YOUR_KEY", "xxxx", "1234",
    "dummy", "test", "sample", "changeme", "replace",
]


def _is_fp(snippet: str) -> bool:
    low = snippet.lower()
    return any(fp in low for fp in FP_SNIPPETS)


class SecretDetectionAgent:
    name = "Secret Detection Agent"

    def run(self, crawl: CrawlResult) -> AgentResult:
        log.info("[Secret Detection] Scanning %d resources", len(crawl.js_contents) + len(crawl.page_contents))
        result = AgentResult(agent_name=self.name)

        sources: dict[str, str] = {}
        sources.update(crawl.js_contents)
        sources.update(crawl.page_contents)

        for url, content in sources.items():
            for hit in scan_secrets(content):
                if _is_fp(hit["snippet"]):
                    continue
                severity = STR_TO_SEVERITY.get(hit["severity"], Severity.MEDIUM)
                result.findings.append(Finding(
                    title=f"Exposed {hit['name']}",
                    severity=severity,
                    agent=self.name,
                    affected_resource=url,
                    evidence=f"Line {hit['line']}: `{hit['snippet']}`",
                    description=f"{hit['name']} found in client-accessible resource `{url}`.",
                    attack_scenario="Any user who loads this page/script can extract the credential and abuse it.",
                    impact=f"Unauthorized access using exposed {hit['name']}.",
                    remediation="Move secrets to server-side environment variables. Never embed credentials in client-side code.",
                    confidence=0.75,
                    tags=["secret", hit["name"].lower().replace(" ", "-")],
                ))

        log.info("[Secret Detection] %d findings", len(result.findings))
        return result
