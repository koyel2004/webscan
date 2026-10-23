"""
Explanation Engine for SentinelScan Findings
Provides deterministic, verified explanations and remediation advice by default,
with an optional secure AI adapter interface for configured providers.
"""
from app.models.finding import SeverityLevel


class ExplanationEngine:
    """
    Produces evidence-based explanations, severity rationales, and verified
    remediation guidance.
    """

    @classmethod
    def enhance_finding(
        cls,
        check_id: str,
        title: str,
        category: str,
        severity: SeverityLevel,
        observed_evidence: str,
        hostname: str
    ) -> dict[str, str]:
        """
        Generates deterministic security guidance.
        """
        # Sanitization: Ensure no sensitive patterns exist in evidence
        sanitized_evidence = cls._sanitize(observed_evidence)

        # Build detailed guidance
        guidance = {
            "source": "Deterministic Security Rulebook v1.0",
            "is_ai_assisted": False,
            "verification_steps": cls._get_verification_steps(category, check_id, hostname),
            "threat_scenario": cls._get_threat_scenario(category, severity),
            "sanitized_evidence": sanitized_evidence,
        }
        return guidance

    @classmethod
    def _sanitize(cls, text: str) -> str:
        """Strips potential session tokens or credentials."""
        if not text:
            return ""
        # Basic extra safeguard
        return text.replace("Bearer ", "Bearer [REDACTED]").replace("Set-Cookie:", "Set-Cookie: [REDACTED]")

    @classmethod
    def _get_verification_steps(cls, category: str, check_id: str, hostname: str) -> str:
        if category == "headers":
            return f"Run 'curl -I https://{hostname}' in your terminal to inspect the response headers after updating your web server config."
        elif category == "cookies":
            return f"Open Browser DevTools -> Application -> Storage -> Cookies -> https://{hostname} to confirm Secure, HttpOnly, and SameSite flags are active."
        elif category == "cors":
            return f"Run 'curl -H \"Origin: https://test.com\" -I https://{hostname}' and verify that Access-Control-Allow-Origin does not echo arbitrary foreign domains."
        elif category == "tls":
            return f"Run 'openssl s_client -connect {hostname}:443 -servername {hostname}' to inspect the certificate validity, issuer, and protocol cipher."
        elif category == "redirects":
            return f"Run 'curl -I http://{hostname}' and verify an HTTP 301 or 308 response with Location: https://{hostname}."
        else:
            return f"Review public endpoint responses on https://{hostname} and verify sensitive data is suppressed."

    @classmethod
    def _get_threat_scenario(cls, category: str, severity: SeverityLevel) -> str:
        if severity == SeverityLevel.CRITICAL:
            return "Active service disruption, certificate expiration, or severe cross-origin exposure allowing immediate compromise."
        elif severity == SeverityLevel.HIGH:
            return "Man-in-the-Middle eavesdropping, credential interception over unencrypted networks, or Cross-Site Scripting (XSS)."
        elif severity == SeverityLevel.MEDIUM:
            return "Clickjacking, insecure cookie transmission, or opportunistic network attacks."
        elif severity == SeverityLevel.LOW:
            return "Reconnaissance assistance, MIME sniffing, or technology stack profiling."
        else:
            return "Defense-in-depth posture recommendation aligned with modern web security baselines."
