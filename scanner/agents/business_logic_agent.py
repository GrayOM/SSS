"""Business Logic Analysis Agent — hidden features, debug flags, role gates."""
from __future__ import annotations
import logging

from scanner.models import AgentResult, CrawlResult, Finding, Severity
from scanner.tools.pattern_tools import scan_role_logic

log = logging.getLogger("business_logic_agent")


class BusinessLogicAgent:
    name = "Business Logic Agent"

    def run(self, crawl: CrawlResult) -> AgentResult:
        log.info("[Business Logic] Analyzing %d JS files", len(crawl.js_contents))
        result = AgentResult(agent_name=self.name)

        for js_url, code in crawl.js_contents.items():
            for hit in scan_role_logic(code):
                severity = self._classify(hit["name"])
                result.findings.append(Finding(
                    title=f"Business Logic Weakness: {hit['name']}",
                    severity=severity,
                    agent=self.name,
                    affected_resource=js_url,
                    evidence=f"Line {hit['line']}: `{hit['snippet']}`",
                    description=self._describe(hit["name"]),
                    attack_scenario=self._scenario(hit["name"]),
                    impact="Bypasses intended access restrictions or enables hidden functionality.",
                    remediation="Move all authorization decisions to server side. Remove debug/test flags from production builds.",
                    confidence=0.7,
                    tags=["business-logic", hit["name"].lower().replace(" ", "-")],
                ))

        log.info("[Business Logic] %d findings", len(result.findings))
        return result

    def _classify(self, name: str) -> Severity:
        if "admin" in name.lower() or "superuser" in name.lower():
            return Severity.CRITICAL
        if "debug" in name.lower() or "internal" in name.lower():
            return Severity.HIGH
        if "feature flag" in name.lower() or "test" in name.lower():
            return Severity.MEDIUM
        return Severity.LOW

    def _describe(self, name: str) -> str:
        return (
            f"The client-side code contains a `{name}` pattern. "
            "This logic can be manipulated by an attacker via browser console "
            "or by crafting requests that skip the client-side gate."
        )

    def _scenario(self, name: str) -> str:
        if "admin" in name.lower():
            return "Set admin flag in browser console → unlock admin UI → perform privileged operations."
        if "debug" in name.lower():
            return "Enable debug flag → expose verbose error messages, internal state, or hidden debug endpoints."
        if "feature flag" in name.lower():
            return "Toggle feature flag → access unreleased or disabled functionality."
        return "Manipulate client-side logic flag → bypass intended workflow restrictions."
