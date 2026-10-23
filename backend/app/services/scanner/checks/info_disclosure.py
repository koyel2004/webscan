"""
Check F: Information Disclosure via HTTP Headers
Inspects response headers for detailed software banners, frameworks, and runtime versions.
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


class InfoDisclosureCheck(BaseSecurityCheck):
    check_id = "CHECK_INFO_DISCLOSURE"
    check_name = "Information Disclosure and Banner Hygiene"
    category = "info_disclosure"
    description = "Inspects public response headers for server versions, technology stacks, and framework banners."

    # Pattern detecting version numbers like 1.2, 2.4.41, etc.
    VERSION_REGEX = re.compile(r'\d+\.\d+(?:\.\d+)?')

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
                    message=f"Could not retrieve response headers: {e}",
                    error_detail=str(e),
                    findings=[]
                )

        headers = {k.lower(): v for k, v in resp.headers.items()}

        # 1. Server Header Disclosure
        server_header = headers.get("server")
        if server_header:
            has_version = bool(self.VERSION_REGEX.search(server_header))
            if has_version:
                findings.append(FindingData(
                    check_id=f"{self.check_id}_SERVER_VERSION",
                    title="Detailed Web Server Software and Version Disclosed",
                    category=self.category,
                    severity=SeverityLevel.LOW,
                    confidence=ConfidenceLevel.CERTAIN,
                    summary=f"The 'Server' header exposes detailed software and version information: '{server_header}'.",
                    evidence=f"Server: {server_header}",
                    impact="Revealing specific server versions assists attackers in selecting targeted known exploits (CVEs) during reconnaissance.",
                    remediation="Configure your web server to suppress or tokenize the Server header (e.g. 'ServerTokens Prod' in Apache, or 'server_tokens off;' in Nginx).",
                    references="https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server",
                    cwe_id="CWE-200"
                ))

        # 2. X-Powered-By Header Disclosure
        powered_by = headers.get("x-powered-by")
        if powered_by:
            findings.append(FindingData(
                check_id=f"{self.check_id}_X_POWERED_BY",
                title="Application Framework Disclosed in 'X-Powered-By' Header",
                category=self.category,
                severity=SeverityLevel.LOW,
                confidence=ConfidenceLevel.CERTAIN,
                summary=f"The application framework exposes its identity in 'X-Powered-By: {powered_by}'.",
                evidence=f"X-Powered-By: {powered_by}",
                impact="Assists attackers in profiling technology-specific weaknesses and default framework behaviors.",
                remediation="Disable the X-Powered-By header in application settings (e.g. app.disable('x-powered-by') in Express, or expose_php = Off in php.ini).",
                references="https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html",
                cwe_id="CWE-200"
            ))

        # 3. ASP.NET specific headers
        for asp_hdr in ("x-aspnet-version", "x-aspnetmvc-version"):
            val = headers.get(asp_hdr)
            if val:
                findings.append(FindingData(
                    check_id=f"{self.check_id}_{asp_hdr.upper().replace('-', '_')}",
                    title=f"ASP.NET Version Disclosed in '{asp_hdr}' Header",
                    category=self.category,
                    severity=SeverityLevel.LOW,
                    confidence=ConfidenceLevel.CERTAIN,
                    summary=f"The server advertises '{asp_hdr}: {val}'.",
                    evidence=f"{asp_hdr}: {val}",
                    impact="Exposes the exact Microsoft .NET runtime/MVC framework version in production responses.",
                    remediation="Disable version disclosure in web.config by setting enableVersionHeader=\"false\".",
                    references="https://learn.microsoft.com/en-us/previous-versions/dotnet/articles/ms972969(v=msdn.10)",
                    cwe_id="CWE-200"
                ))

        status = CheckStatus.FINDINGS_DETECTED if findings else CheckStatus.PASSED
        return CheckOutcome(
            check_id=self.check_id,
            check_name=self.check_name,
            category=self.category,
            status=status,
            duration_ms=0.0,
            message=f"Banner inspection complete. {len(findings)} disclosures detected.",
            findings=findings
        )
