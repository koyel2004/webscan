"""
Check D: Cross-Origin Resource Sharing (CORS) Configuration Analysis
Sends a safe, non-destructive test origin to inspect CORS response headers.
"""

from app.models.check_result import CheckStatus
from app.models.finding import ConfidenceLevel, SeverityLevel
from app.services.scanner.base import (
    BaseSecurityCheck,
    CheckOutcome,
    FindingData,
    ScanContext,
)


class CORSConfigCheck(BaseSecurityCheck):
    check_id = "CHECK_CORS_CONFIG"
    check_name = "CORS Policy Configuration"
    category = "cors"
    description = "Evaluates Cross-Origin Resource Sharing (CORS) policies using controlled origin probes."

    async def run(self, context: ScanContext) -> CheckOutcome:
        findings: list[FindingData] = []
        test_origin = "https://sentinelscan-audit-probe.example.com"

        cors_resp = context.cors_response
        if not cors_resp:
            try:
                cors_resp = await context.client.get(
                    context.target_url,
                    headers={"Origin": test_origin},
                    follow_redirects=True
                )
                context.cors_response = cors_resp
            except Exception as e:
                return CheckOutcome(
                    check_id=self.check_id,
                    check_name=self.check_name,
                    category=self.category,
                    status=CheckStatus.INCONCLUSIVE,
                    duration_ms=0.0,
                    message=f"Could not execute CORS probe: {e}",
                    error_detail=str(e),
                    findings=[]
                )

        headers = {k.lower(): v for k, v in cors_resp.headers.items()}
        acao = headers.get("access-control-allow-origin")
        acac = headers.get("access-control-allow-credentials")

        if not acao:
            # No CORS headers exposed
            return CheckOutcome(
                check_id=self.check_id,
                check_name=self.check_name,
                category=self.category,
                status=CheckStatus.PASSED,
                duration_ms=0.0,
                message="Target does not expose permissive CORS headers to foreign origins.",
                findings=[]
            )

        acao_clean = acao.strip()
        credentials_allowed = bool(acac and acac.strip().lower() == "true")

        # 1. Reflected Origin with Credentials Allowed
        if acao_clean == test_origin and credentials_allowed:
            findings.append(FindingData(
                check_id=f"{self.check_id}_REFLECTED_ORIGIN_WITH_CREDENTIALS",
                title="Critical CORS Misconfiguration: Arbitrary Origin Reflection with Credentials",
                category=self.category,
                severity=SeverityLevel.HIGH,
                confidence=ConfidenceLevel.CERTAIN,
                summary=f"The server dynamically reflected the arbitrary untrusted origin '{test_origin}' and enabled 'Access-Control-Allow-Credentials: true'.",
                evidence=f"Sent Origin: {test_origin}\nReceived Access-Control-Allow-Origin: {acao_clean}\nReceived Access-Control-Allow-Credentials: {acac}",
                impact="Any malicious website can make cross-origin authenticated XMLHttpRequests/fetch to this application and read sensitive user data.",
                remediation="Validate the incoming 'Origin' header against a strict server-side allowlist of trusted origins. Never reflect untrusted origins when credentials are supported.",
                references="https://portswigger.net/web-security/cors\nhttps://developer.mozilla.org/en-US/docs/Web/HTTP/CORS",
                cwe_id="CWE-346"
            ))
        elif acao_clean == test_origin and not credentials_allowed:
            findings.append(FindingData(
                check_id=f"{self.check_id}_REFLECTED_ORIGIN_NO_CREDENTIALS",
                title="Permissive CORS Origin Reflection",
                category=self.category,
                severity=SeverityLevel.LOW,
                confidence=ConfidenceLevel.CERTAIN,
                summary="The server reflects arbitrary test origins in 'Access-Control-Allow-Origin', though credentials are not allowed.",
                evidence=f"Sent Origin: {test_origin}\nReceived Access-Control-Allow-Origin: {acao_clean}",
                impact="Unauthenticated data from this endpoint can be read by external scripts on third-party sites.",
                remediation="Only allow explicitly trusted partner domains in the Access-Control-Allow-Origin header.",
                references="https://cheatsheetseries.owasp.org/cheatsheets/Cross-Origin_Resource_Sharing_Cheat_Sheet.html",
                cwe_id="CWE-346"
            ))
        elif acao_clean == "*":
            if credentials_allowed:
                findings.append(FindingData(
                    check_id=f"{self.check_id}_WILDCARD_WITH_CREDENTIALS",
                    title="Invalid and Dangerous CORS Policy: Wildcard (*) with Credentials",
                    category=self.category,
                    severity=SeverityLevel.HIGH,
                    confidence=ConfidenceLevel.CERTAIN,
                    summary="The response specifies 'Access-Control-Allow-Origin: *' alongside 'Access-Control-Allow-Credentials: true'.",
                    evidence=f"Access-Control-Allow-Origin: *\nAccess-Control-Allow-Credentials: {acac}",
                    impact="While modern browsers reject wildcard origins with credentials, this indicates confused CORS configuration logic.",
                    remediation="If credentials are required, specify explicit trusted domain origins instead of '*'.",
                    references="https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS/Errors/CORSNotSupportingCredentials",
                    cwe_id="CWE-346"
                ))
            else:
                findings.append(FindingData(
                    check_id=f"{self.check_id}_WILDCARD_ORIGIN",
                    title="Public Wildcard (*) CORS Header Exposed",
                    category=self.category,
                    severity=SeverityLevel.INFORMATIONAL,
                    confidence=ConfidenceLevel.CERTAIN,
                    summary="The endpoint returns 'Access-Control-Allow-Origin: *', allowing any site to read unauthenticated responses.",
                    evidence="Access-Control-Allow-Origin: *",
                    impact="If this endpoint returns public data or static assets, this is expected. If it exposes internal or private data, it may leak content.",
                    remediation="Verify whether this resource is intended to be completely public. If not, restrict origins to authorized clients.",
                    references="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Origin",
                    cwe_id="CWE-346"
                ))
        elif acao_clean.lower() == "null":
            findings.append(FindingData(
                check_id=f"{self.check_id}_NULL_ORIGIN_ALLOWED",
                title="CORS Allows 'null' Origin",
                category=self.category,
                severity=SeverityLevel.MEDIUM,
                confidence=ConfidenceLevel.CERTAIN,
                summary="The server accepts 'null' as a permitted cross-origin domain.",
                evidence="Access-Control-Allow-Origin: null",
                impact="Sandboxed iframes and local file URIs can execute cross-origin requests and read data.",
                remediation="Do not include 'null' in the allowlist of origins.",
                references="https://portswigger.net/web-security/cors",
                cwe_id="CWE-346"
            ))

        status = CheckStatus.FINDINGS_DETECTED if findings else CheckStatus.PASSED
        return CheckOutcome(
            check_id=self.check_id,
            check_name=self.check_name,
            category=self.category,
            status=status,
            duration_ms=0.0,
            message=f"CORS evaluation complete: {len(findings)} findings.",
            findings=findings
        )
