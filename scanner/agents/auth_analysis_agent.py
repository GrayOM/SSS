"""Authentication & Authorization Analysis Agent."""
from __future__ import annotations
import logging
import re

from scanner.models import AgentResult, CrawlResult, Finding, Severity

log = logging.getLogger("auth_analysis_agent")


class AuthAnalysisAgent:
    name = "Auth Analysis Agent"

    def run(self, crawl: CrawlResult) -> AgentResult:
        log.info("[Auth Analysis] Starting")
        result = AgentResult(agent_name=self.name)

        all_js = "\n".join(crawl.js_contents.values())
        all_html = "\n".join(crawl.page_contents.values())
        combined = all_js + "\n" + all_html

        self._check_client_side_auth(combined, result)
        self._check_session_exposure(crawl, result)
        self._check_insecure_redirect(combined, result)
        self._check_jwt_none_alg(all_js, result)

        log.info("[Auth Analysis] %d findings", len(result.findings))
        return result

    def _check_client_side_auth(self, code: str, result: AgentResult) -> None:
        patterns = [
            (r'if\s*\(.*?role.*?===?\s*["\']admin["\']', "Client-side role check (admin)"),
            (r'if\s*\(.*?isAdmin\b', "Client-side isAdmin flag"),
            (r'if\s*\(.*?permission\b.*?\)', "Client-side permission check"),
            (r'if\s*\(.*?token\s*===?\s*null', "Token null check used as auth gate"),
        ]
        for pattern, label in patterns:
            if re.search(pattern, code, re.IGNORECASE):
                result.findings.append(Finding(
                    title=f"Client-side Authorization: {label}",
                    severity=Severity.HIGH,
                    agent=self.name,
                    affected_resource="JS/HTML",
                    evidence=label,
                    description="Authorization logic implemented in client-side code. Attackers can bypass it by manipulating variables in browser console.",
                    attack_scenario="Open browser console → set `isAdmin=true` or `role='admin'` → access restricted features without server validation.",
                    impact="Privilege escalation; unauthorized access to admin functionality.",
                    remediation="Enforce all authorization checks on the server side. Client-side checks are for UX only.",
                    confidence=0.8,
                    tags=["auth", "authorization", "client-side"],
                ))

    def _check_session_exposure(self, crawl: CrawlResult, result: AgentResult) -> None:
        for url, html in crawl.page_contents.items():
            if re.search(r'(session|token|auth)[^=]*=\s*["\'][A-Za-z0-9\-_.]{20,}["\']', html, re.IGNORECASE):
                result.findings.append(Finding(
                    title="Session/Token Embedded in HTML",
                    severity=Severity.HIGH,
                    agent=self.name,
                    affected_resource=url,
                    evidence="Auth token literal found in HTML response",
                    description="An authentication token appears to be embedded directly in the HTML page.",
                    attack_scenario="View page source → extract token → replay requests as authenticated user.",
                    impact="Session hijacking if token is sensitive.",
                    remediation="Pass tokens via HttpOnly cookies or API responses, not embedded in HTML.",
                    confidence=0.6,
                    tags=["auth", "session", "exposure"],
                ))

    def _check_insecure_redirect(self, code: str, result: AgentResult) -> None:
        if re.search(r'(redirect|returnUrl|next)\s*=\s*(?:location|window\.location|params)', code, re.IGNORECASE):
            result.findings.append(Finding(
                title="Open Redirect via Client-side Parameter",
                severity=Severity.MEDIUM,
                agent=self.name,
                affected_resource="JS",
                evidence="Redirect destination read from URL parameter without validation",
                description="Redirect target derived from attacker-controlled URL parameter on client side.",
                attack_scenario="Craft URL with `?next=https://evil.com` → user redirected to attacker site after login.",
                impact="Phishing; credential harvesting.",
                remediation="Validate redirect URLs against an allowlist on the server side.",
                confidence=0.65,
                tags=["auth", "redirect"],
            ))

    def _check_jwt_none_alg(self, js_code: str, result: AgentResult) -> None:
        if re.search(r'alg.*none|algorithm.*none', js_code, re.IGNORECASE):
            result.findings.append(Finding(
                title="JWT 'none' Algorithm Accepted",
                severity=Severity.CRITICAL,
                agent=self.name,
                affected_resource="JS",
                evidence="String 'alg:none' or 'algorithm:none' found in JWT handling code",
                description="Client-side JWT code references the 'none' algorithm, suggesting the server may accept unsigned tokens.",
                attack_scenario="Modify JWT header to `{\"alg\":\"none\"}` → remove signature → server accepts forged token.",
                impact="Authentication bypass; arbitrary user impersonation.",
                remediation="Reject JWTs with 'none' algorithm on the server. Use a strong algorithm (RS256/ES256).",
                confidence=0.8,
                tags=["auth", "jwt", "critical"],
            ))
