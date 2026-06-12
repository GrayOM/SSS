"""JS Security Analysis Agent — DOM XSS, sinks, token handling."""
from __future__ import annotations
import logging

from scanner.models import AgentResult, CrawlResult, Finding, Severity
from scanner.tools.pattern_tools import scan_sinks

log = logging.getLogger("js_security_agent")

CATEGORY_SEVERITY = {
    "DOM XSS": Severity.HIGH,
    "Code Injection": Severity.CRITICAL,
    "postMessage misuse": Severity.MEDIUM,
    "postMessage receiver": Severity.MEDIUM,
}

AUTH_PATTERNS = [
    ("localStorage.getItem", "Token read from localStorage", Severity.MEDIUM),
    ("sessionStorage.getItem", "Token read from sessionStorage", Severity.LOW),
    ("document.cookie", "Cookie access in JS", Severity.MEDIUM),
    ("atob(", "Base64 decode (possible token decode)", Severity.LOW),
    ("window.location.hash", "Hash-based token handling", Severity.MEDIUM),
]


class JsSecurityAgent:
    name = "JS Security Agent"

    def run(self, crawl: CrawlResult) -> AgentResult:
        log.info("[JS Security] Analyzing %d JS files", len(crawl.js_contents))
        result = AgentResult(agent_name=self.name)

        for js_url, code in crawl.js_contents.items():
            # Dangerous sinks
            for hit in scan_sinks(code):
                severity = CATEGORY_SEVERITY.get(hit["category"], Severity.MEDIUM)
                result.findings.append(Finding(
                    title=f"{hit['category']}: {hit['name']}",
                    severity=severity,
                    agent=self.name,
                    affected_resource=js_url,
                    evidence=f"Line {hit['line']}: `{hit['snippet']}`",
                    description=(
                        f"Dangerous sink `{hit['name']}` detected in `{js_url}`. "
                        f"If attacker-controlled data reaches this sink it can lead to {hit['category']}."
                    ),
                    attack_scenario=f"Inject payload via URL parameter or user input → reaches `{hit['name']}` → executes arbitrary JS.",
                    impact="Arbitrary JavaScript execution in victim's browser; session hijacking.",
                    remediation="Sanitize all user-controlled input before passing to DOM-modifying APIs. Use textContent instead of innerHTML.",
                    confidence=0.7,
                    tags=["js", hit["category"].lower().replace(" ", "-")],
                ))

            # Auth / token handling
            for pattern, label, severity in AUTH_PATTERNS:
                if pattern in code:
                    line_no = next(
                        (i + 1 for i, ln in enumerate(code.splitlines()) if pattern in ln),
                        0,
                    )
                    result.findings.append(Finding(
                        title=f"Insecure Token Handling: {label}",
                        severity=severity,
                        agent=self.name,
                        affected_resource=js_url,
                        evidence=f"Pattern `{pattern}` found (line ~{line_no})",
                        description=f"`{pattern}` usage detected in client-side code — {label}.",
                        attack_scenario="XSS or physical access allows token extraction from storage.",
                        impact="Authentication token theft; account takeover.",
                        remediation="Store sensitive tokens in HttpOnly cookies. Avoid localStorage for auth tokens.",
                        confidence=0.5,
                        tags=["js", "auth", "token"],
                    ))

        log.info("[JS Security] %d findings", len(result.findings))
        return result
