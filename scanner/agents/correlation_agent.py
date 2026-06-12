"""Vulnerability Correlation Agent — chains findings into multi-step attack paths."""
from __future__ import annotations
import logging
from itertools import combinations

from scanner.models import AgentResult, Finding, Severity

log = logging.getLogger("correlation_agent")

CHAIN_RULES: list[dict] = [
    {
        "name": "Admin API + Client-side Auth Bypass",
        "requires_tags": [{"api", "admin"}, {"auth", "client-side"}],
        "severity": Severity.CRITICAL,
        "title": "Chained: Admin API Accessible via Client-side Auth Bypass",
        "scenario": (
            "1. Identify admin API endpoint from JS source.\n"
            "2. Bypass client-side role check via browser console.\n"
            "3. Call admin API directly → full administrative access."
        ),
        "impact": "Complete privilege escalation to administrator.",
        "remediation": "Server-side authorization on every admin endpoint + remove client-side role gates.",
    },
    {
        "name": "DOM XSS + Token in Storage",
        "requires_tags": [{"dom-xss"}, {"auth", "token"}],
        "severity": Severity.CRITICAL,
        "title": "Chained: DOM XSS leads to Token Theft",
        "scenario": (
            "1. Inject XSS payload via DOM sink.\n"
            "2. XSS reads token from localStorage/sessionStorage.\n"
            "3. Exfiltrate token → account takeover."
        ),
        "impact": "Persistent account takeover; full session hijack.",
        "remediation": "Fix DOM XSS sinks + move tokens to HttpOnly cookies.",
    },
    {
        "name": "Secret in JS + API Endpoint",
        "requires_tags": [{"secret"}, {"api"}],
        "severity": Severity.HIGH,
        "title": "Chained: Exposed Secret Enables Direct API Abuse",
        "scenario": (
            "1. Extract API key/token from client-side JavaScript.\n"
            "2. Use credential to authenticate directly to discovered API.\n"
            "3. Perform unauthorized operations."
        ),
        "impact": "Unauthorized API access using exposed credentials.",
        "remediation": "Remove secrets from client code. Rotate all exposed credentials immediately.",
    },
    {
        "name": "Business Logic + Hidden API",
        "requires_tags": [{"business-logic"}, {"api", "hidden"}],
        "severity": Severity.HIGH,
        "title": "Chained: Business Logic Flag Enables Hidden API",
        "scenario": (
            "1. Toggle debug/internal flag in browser console.\n"
            "2. Hidden admin UI or API route becomes accessible.\n"
            "3. Perform privileged operations."
        ),
        "impact": "Access to unreleased or restricted functionality.",
        "remediation": "Remove debug flags and hidden routes from production builds.",
    },
]


def _tags_of(f: Finding) -> set[str]:
    return set(f.tags)


class CorrelationAgent:
    name = "Correlation Agent"

    def run(self, all_findings: list[Finding]) -> AgentResult:
        log.info("[Correlation] Correlating %d findings", len(all_findings))
        result = AgentResult(agent_name=self.name)

        for rule in CHAIN_RULES:
            required_tag_sets: list[set[str]] = rule["requires_tags"]
            # For each required tag-set, find at least one matching finding
            matched_findings: list[Finding] = []
            satisfied = True
            for tag_set in required_tag_sets:
                candidates = [f for f in all_findings if tag_set.issubset(_tags_of(f))]
                if not candidates:
                    satisfied = False
                    break
                matched_findings.append(candidates[0])

            if satisfied and len(matched_findings) == len(required_tag_sets):
                evidence_lines = [f"- [{f.agent}] {f.title} ({f.affected_resource})" for f in matched_findings]
                result.findings.append(Finding(
                    title=rule["title"],
                    severity=rule["severity"],
                    agent=self.name,
                    affected_resource=", ".join(f.affected_resource for f in matched_findings),
                    evidence="Individual findings that form this chain:\n" + "\n".join(evidence_lines),
                    description=f"Correlation rule: `{rule['name']}` — multiple findings combine into a high-impact attack chain.",
                    attack_scenario=rule["scenario"],
                    impact=rule["impact"],
                    remediation=rule["remediation"],
                    confidence=0.85,
                    tags=["chain", "correlation"],
                ))
                log.info("[Correlation] Chain found: %s", rule["name"])

        log.info("[Correlation] %d chained findings", len(result.findings))
        return result
