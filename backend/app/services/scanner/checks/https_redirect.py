"""
Check A: HTTPS Reachability and HTTP-to-HTTPS Redirection
"""
from app.core.logging import logger
from app.models.check_result import CheckStatus
from app.models.finding import ConfidenceLevel, SeverityLevel
from app.services.scanner.base import (
    BaseSecurityCheck,
    CheckOutcome,
    FindingData,
    ScanContext,
)


class HTTPSRedirectCheck(BaseSecurityCheck):
    check_id = "CHECK_HTTPS_REDIRECT"
    check_name = "HTTPS Enforcement and Redirection"
    category = "redirects"
    description = "Verifies HTTPS reachability and validates automatic upgrade of plain HTTP traffic to HTTPS."

    async def run(self, context: ScanContext) -> CheckOutcome:
        findings: list[FindingData] = []
        hostname = context.hostname

        # 1. Probe HTTPS
        https_url = f"https://{hostname}"
        https_ok = False
        https_error = None
        try:
            context.https_response = await context.client.get(https_url, follow_redirects=True)
            https_ok = True
        except Exception as e:
            https_error = str(e)
            logger.debug(f"HTTPS probe failed for {https_url}: {e}")

        # 2. Probe HTTP (plain)
        http_url = f"http://{hostname}"
        http_resp = None
        http_error = None
        try:
            http_resp = await context.client.get(http_url, follow_redirects=False)
            context.http_response = http_resp
        except Exception as e:
            http_error = str(e)
            logger.debug(f"HTTP probe failed for {http_url}: {e}")

        # Evaluation
        if not https_ok:
            findings.append(FindingData(
                check_id=self.check_id,
                title="HTTPS Not Reachable or Failing TLS Handshake",
                category=self.category,
                severity=SeverityLevel.HIGH,
                confidence=ConfidenceLevel.CERTAIN,
                summary=f"The target hostname '{hostname}' could not be reached over secure HTTPS: {https_error}",
                evidence=f"Attempted connection to: {https_url}\nError: {https_error}",
                impact="All traffic between visitors and the web application is either unavailable or transmitted over unencrypted channels, exposing users to eavesdropping and man-in-the-middle attacks.",
                remediation="Provision a valid TLS certificate and configure your web server (e.g. Nginx, Apache, or Cloudflare) to listen on port 443 with modern TLS protocols enabled.",
                references="https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html",
                cwe_id="CWE-319"
            ))
            return CheckOutcome(
                check_id=self.check_id,
                check_name=self.check_name,
                category=self.category,
                status=CheckStatus.FINDINGS_DETECTED,
                duration_ms=0.0,
                message="Target fails to support secure HTTPS connections.",
                findings=findings
            )

        # HTTPS is working. Now inspect HTTP redirect behavior.
        if http_resp:
            status = http_resp.status_code
            location = http_resp.headers.get("location", "")

            # Check if plain HTTP redirects to HTTPS
            if status in (301, 302, 307, 308) and location.lower().startswith("https://"):
                # Clean redirect to HTTPS observed
                return CheckOutcome(
                    check_id=self.check_id,
                    check_name=self.check_name,
                    category=self.category,
                    status=CheckStatus.PASSED,
                    duration_ms=0.0,
                    message=f"HTTP correctly redirects to HTTPS with status code {status} (Target: {location}).",
                    findings=[]
                )
            else:
                findings.append(FindingData(
                    check_id=self.check_id,
                    title="Missing Automatic HTTP to HTTPS Redirection",
                    category=self.category,
                    severity=SeverityLevel.MEDIUM,
                    confidence=ConfidenceLevel.CERTAIN,
                    summary=f"Plain HTTP requests to '{http_url}' returned HTTP {status} without redirecting to HTTPS.",
                    evidence=f"Initial URL: {http_url}\nStatus Code: {status}\nLocation Header: {location or 'None'}",
                    impact="Users visiting the site without typing 'https://' may transmit session tokens, form inputs, or cookies over plaintext HTTP before navigating to secure pages.",
                    remediation="Configure the web server to immediately issue an HTTP 301 Permanent Redirect for all port 80 requests to their HTTPS equivalent.",
                    references="https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/03-Testing_for_Weak_Transport_Layer_Security",
                    cwe_id="CWE-311"
                ))
        elif http_error and "connection refused" in http_error.lower():
            # Port 80 closed entirely, only HTTPS open
            return CheckOutcome(
                check_id=self.check_id,
                check_name=self.check_name,
                category=self.category,
                status=CheckStatus.PASSED,
                duration_ms=0.0,
                message="Port 80 is closed; target operates exclusively over HTTPS.",
                findings=[]
            )

        status_outcome = CheckStatus.FINDINGS_DETECTED if findings else CheckStatus.PASSED
        return CheckOutcome(
            check_id=self.check_id,
            check_name=self.check_name,
            category=self.category,
            status=status_outcome,
            duration_ms=0.0,
            message="Analyzed HTTPS reachability and HTTP redirection.",
            findings=findings
        )
