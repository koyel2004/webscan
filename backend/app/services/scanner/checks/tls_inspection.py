"""
Check E: TLS Certificate and Transport Security Inspection
Inspects TLS handshake, validity period, hostname matching, and certificate chain.
"""

from app.models.check_result import CheckStatus
from app.models.finding import ConfidenceLevel, SeverityLevel
from app.services.scanner.base import (
    BaseSecurityCheck,
    CheckOutcome,
    FindingData,
    ScanContext,
)
from app.services.scanner.safe_client import inspect_tls_certificate


class TLSCertificateCheck(BaseSecurityCheck):
    check_id = "CHECK_TLS_CERTIFICATE"
    check_name = "TLS Certificate and Cipher Inspection"
    category = "tls"
    description = "Inspects TLS certificate validity, expiration dates, Subject Alternative Names (SAN), and chain trust."

    async def run(self, context: ScanContext) -> CheckOutcome:
        findings: list[FindingData] = []
        hostname = context.hostname
        port = 443

        tls_info = context.tls_info
        if not tls_info:
            tls_info = inspect_tls_certificate(hostname=hostname, port=port, timeout_seconds=context.timeout_seconds)
            context.tls_info = tls_info

        status = tls_info.get("status")
        error_detail = tls_info.get("error")

        if status == "CONNECTION_TIMEOUT":
            return CheckOutcome(
                check_id=self.check_id,
                check_name=self.check_name,
                category=self.category,
                status=CheckStatus.INCONCLUSIVE,
                duration_ms=0.0,
                message=f"TLS handshake timed out on {hostname}:{port}.",
                error_detail=error_detail,
                findings=[]
            )

        if status == "VERIFICATION_FAILED":
            findings.append(FindingData(
                check_id=f"{self.check_id}_VERIFICATION_FAILED",
                title="TLS Certificate Verification Failed",
                category=self.category,
                severity=SeverityLevel.HIGH,
                confidence=ConfidenceLevel.CERTAIN,
                summary=f"The TLS certificate for '{hostname}' could not be verified by the system trust store: {error_detail}",
                evidence=f"Target: {hostname}:{port}\nVerification Error: {error_detail}",
                impact="Visitors will encounter browser security warning screens. Unverified or self-signed certificates do not protect users against Man-in-the-Middle (MitM) attacks.",
                remediation="Ensure the server presents a valid certificate issued by a trusted Certificate Authority (e.g. Let's Encrypt, DigiCert) along with any required intermediate certificates.",
                references="https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html",
                cwe_id="CWE-295"
            ))

        if not tls_info.get("hostname_matched"):
            san_list = ", ".join(tls_info.get("san", [])) or "None"
            findings.append(FindingData(
                check_id=f"{self.check_id}_HOSTNAME_MISMATCH",
                title="TLS Certificate Hostname Mismatch",
                category=self.category,
                severity=SeverityLevel.HIGH,
                confidence=ConfidenceLevel.CERTAIN,
                summary=f"The presented certificate does not match the target hostname '{hostname}'.",
                evidence=f"Target Hostname: {hostname}\nCertificate SANs: {san_list}",
                impact="Browsers will block connection to the site with a name mismatch error.",
                remediation="Reissue the TLS certificate to include '{hostname}' (and '*.{hostname}' if applicable) in the Subject Alternative Name (SAN) extension.",
                references="https://datatracker.ietf.org/doc/html/rfc6125",
                cwe_id="CWE-297"
            ))

        if tls_info.get("is_expired"):
            findings.append(FindingData(
                check_id=f"{self.check_id}_EXPIRED",
                title="TLS Certificate is Expired",
                category=self.category,
                severity=SeverityLevel.CRITICAL,
                confidence=ConfidenceLevel.CERTAIN,
                summary=f"The TLS certificate expired on {tls_info.get('not_after')}.",
                evidence=f"Certificate Not-After: {tls_info.get('not_after')}\nDays Remaining: {tls_info.get('days_remaining')}",
                impact="All major browsers completely block user traffic when certificates expire.",
                remediation="Immediately renew and deploy a valid certificate.",
                references="https://www.eff.org/deeplinks/2016/11/how-tls-certificates-work",
                cwe_id="CWE-298"
            ))
        elif tls_info.get("days_remaining") is not None:
            days = tls_info.get("days_remaining")
            if days <= 7:
                findings.append(FindingData(
                    check_id=f"{self.check_id}_EXPIRING_SOON_CRITICAL",
                    title=f"TLS Certificate Expiring Very Soon ({days} Days Remaining)",
                    category=self.category,
                    severity=SeverityLevel.HIGH,
                    confidence=ConfidenceLevel.CERTAIN,
                    summary=f"The TLS certificate expires in {days} days on {tls_info.get('not_after')}.",
                    evidence=f"Expiration Date: {tls_info.get('not_after')}\nDays Remaining: {days}",
                    impact="If not renewed promptly, the site will suffer an immediate outage for all HTTPS traffic.",
                    remediation="Renew and deploy the TLS certificate before expiration.",
                    references="https://letsencrypt.org/docs/faq/",
                    cwe_id="CWE-298"
                ))
            elif days <= 30:
                findings.append(FindingData(
                    check_id=f"{self.check_id}_EXPIRING_SOON_WARNING",
                    title=f"TLS Certificate Expiring Within 30 Days ({days} Days Remaining)",
                    category=self.category,
                    severity=SeverityLevel.LOW,
                    confidence=ConfidenceLevel.CERTAIN,
                    summary=f"The TLS certificate will expire in {days} days on {tls_info.get('not_after')}.",
                    evidence=f"Expiration Date: {tls_info.get('not_after')}\nDays Remaining: {days}",
                    impact="Automated renewal scripts should be checked to prevent upcoming certificate expiry.",
                    remediation="Confirm that automated certificate renewal (e.g. Certbot) is functioning as expected.",
                    references="https://letsencrypt.org/docs/faq/",
                    cwe_id="CWE-298"
                ))

        outcome_status = CheckStatus.FINDINGS_DETECTED if findings else CheckStatus.PASSED
        cipher_used = tls_info.get("cipher", ("Unknown", "Unknown"))
        cipher_str = cipher_used[0] if isinstance(cipher_used, (list, tuple)) else str(cipher_used)
        message = f"TLS inspection complete. Protocol: {tls_info.get('version', 'N/A')}, Cipher: {cipher_str}."

        return CheckOutcome(
            check_id=self.check_id,
            check_name=self.check_name,
            category=self.category,
            status=outcome_status,
            duration_ms=0.0,
            message=message,
            findings=findings
        )
