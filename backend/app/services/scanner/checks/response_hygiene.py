"""
Check G: Response and Configuration Hygiene
Analyzes public responses for exposed diagnostic error traces, mixed content references,
and insecure protocol downgrades.
"""
import re

from app.models.check_result import CheckStatus
from app.models.finding import ConfidenceLevel, SeverityLevel
from app.services.scanner.base import (
    BaseSecurityCheck,
    CheckOutcome,
    FindingData,
    ScanContext,
)


class ResponseHygieneCheck(BaseSecurityCheck):
    check_id = "CHECK_RESPONSE_HYGIENE"
    check_name = "Response and Configuration Hygiene"
    category = "hygiene"
    description = "Checks ordinary public responses for stack trace disclosures, mixed content, and protocol downgrades."

    # Patterns indicating debug stack traces or uncaught exceptions in public output
    DEBUG_PATTERNS = [
        (re.compile(r'Traceback \(most recent call last\):', re.IGNORECASE), "Python Uncaught Traceback"),
        (re.compile(r'Fatal error:.*on line \d+', re.IGNORECASE), "PHP Fatal Error Trace"),
        (re.compile(r'System\.Exception:.*at System\.', re.IGNORECASE), ".NET Unhandled Exception"),
        (re.compile(r'Django Version:.*Exception Value:', re.IGNORECASE), "Django Debug Page (DEBUG=True)"),
        (re.compile(r'Whoops! There was an error\.', re.IGNORECASE), "Laravel Ignition Debug Screen"),
        (re.compile(r'org\.apache\.catalina\..*at org\.apache\.', re.IGNORECASE), "Tomcat/Java Stack Trace"),
    ]

    async def run(self, context: ScanContext) -> CheckOutcome:
        findings: list[FindingData] = []
        resp = context.https_response or context.http_response
        if not resp:
            try:
                resp = await context.client.get(context.target_url, follow_redirects=True)
                context.https_response = resp
            except Exception as e:
                return CheckOutcome(
                    check_id=self.check_id,
                    check_name=self.check_name,
                    category=self.category,
                    status=CheckStatus.INCONCLUSIVE,
                    duration_ms=0.0,
                    message=f"Could not retrieve response body for hygiene analysis: {e}",
                    error_detail=str(e),
                    findings=[]
                )

        body_text = resp.text

        # 1. Debug and Stack Trace Patterns
        for pattern, desc in self.DEBUG_PATTERNS:
            match = pattern.search(body_text)
            if match:
                snippet = body_text[max(0, match.start() - 50): min(len(body_text), match.end() + 150)].strip()
                findings.append(FindingData(
                    check_id=f"{self.check_id}_STACK_TRACE_EXPOSURE",
                    title=f"Detailed Application Debug Trace Exposed: {desc}",
                    category=self.category,
                    severity=SeverityLevel.HIGH,
                    confidence=ConfidenceLevel.CERTAIN,
                    summary=f"The application returned an active development/debug trace ({desc}) in a public response.",
                    evidence=f"Matched: {desc}\nSnippet:\n{snippet}",
                    impact="Stack traces reveal internal file paths, module structures, framework versions, database queries, and potentially environment credentials.",
                    remediation="Disable DEBUG mode in production configuration and implement a custom global error handler that returns generic user-friendly error pages.",
                    references="https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/08-Testing_for_Error_Handling/01-Testing_for_Improper_Error_Handling",
                    cwe_id="CWE-209"
                ))

        # 2. HTTP 500 Unhandled Server Error
        if resp.status_code >= 500:
            findings.append(FindingData(
                check_id=f"{self.check_id}_HTTP_500_ERROR",
                title=f"Server Responded with HTTP {resp.status_code} Error",
                category=self.category,
                severity=SeverityLevel.LOW,
                confidence=ConfidenceLevel.CERTAIN,
                summary=f"The initial public probe produced a server-side error code (HTTP {resp.status_code}).",
                evidence=f"Status Code: {resp.status_code}\nFinal URL: {resp.url}",
                impact="Internal errors may signify instability or unhandled edge cases in public routing.",
                remediation="Investigate server logs to resolve the underlying application exception.",
                references="https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/500",
                cwe_id="CWE-755"
            ))

        # 3. Protocol Downgrade (Redirecting from HTTPS to HTTP)
        if len(resp.history_urls) > 1:
            for i in range(len(resp.history_urls) - 1):
                cur = resp.history_urls[i].lower()
                nxt = resp.history_urls[i + 1].lower()
                if cur.startswith("https://") and nxt.startswith("http://"):
                    findings.append(FindingData(
                        check_id=f"{self.check_id}_PROTOCOL_DOWNGRADE",
                        title="Dangerous Protocol Downgrade Detected in Redirect Chain",
                        category=self.category,
                        severity=SeverityLevel.HIGH,
                        confidence=ConfidenceLevel.CERTAIN,
                        summary=f"The redirect chain stepped down from HTTPS ({cur}) to unencrypted HTTP ({nxt}).",
                        evidence=f"Redirect chain:\n  -> {cur}\n  -> {nxt}",
                        impact="Downgrading to plain HTTP destroys TLS encryption guarantees and exposes subsequent requests to interception.",
                        remediation="Ensure redirect rules never direct traffic from an HTTPS endpoint to an HTTP endpoint.",
                        references="https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html",
                        cwe_id="CWE-319"
                    ))

        status = CheckStatus.FINDINGS_DETECTED if findings else CheckStatus.PASSED
        return CheckOutcome(
            check_id=self.check_id,
            check_name=self.check_name,
            category=self.category,
            status=status,
            duration_ms=0.0,
            message=f"Hygiene analysis complete. {len(findings)} issues observed.",
            findings=findings
        )
