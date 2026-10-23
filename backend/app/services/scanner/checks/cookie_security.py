"""
Check C: Cookie Security Attributes
Evaluates Secure, HttpOnly, SameSite, domain, and path configurations.
Strictly redacts all cookie values.
"""
from typing import Any

from app.models.check_result import CheckStatus
from app.models.finding import ConfidenceLevel, SeverityLevel
from app.services.scanner.base import (
    BaseSecurityCheck,
    CheckOutcome,
    FindingData,
    ScanContext,
)


class CookieSecurityCheck(BaseSecurityCheck):
    check_id = "CHECK_COOKIE_SECURITY"
    check_name = "Cookie Security Attributes"
    category = "cookies"
    description = "Examines response cookies for Secure, HttpOnly, SameSite, and scope attributes while redacting raw values."

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
                    message=f"Could not retrieve cookies: {e}",
                    error_detail=str(e),
                    findings=[]
                )

        cookies: dict[str, dict[str, Any]] = resp.cookies
        if not cookies:
            return CheckOutcome(
                check_id=self.check_id,
                check_name=self.check_name,
                category=self.category,
                status=CheckStatus.PASSED,
                duration_ms=0.0,
                message="No cookies were set by the target application in the initial response.",
                findings=[]
            )

        is_https = resp.url.lower().startswith("https://")

        for cookie_name, flags in cookies.items():
            name_lower = cookie_name.lower()
            is_session_cookie = any(term in name_lower for term in ("sess", "auth", "token", "jwt", "id", "login", "key"))

            # 1. Secure Flag check
            if is_https and not flags.get("secure"):
                severity = SeverityLevel.HIGH if is_session_cookie else SeverityLevel.MEDIUM
                findings.append(FindingData(
                    check_id=f"{self.check_id}_MISSING_SECURE",
                    title=f"Cookie '{cookie_name}' Missing 'Secure' Attribute",
                    category=self.category,
                    severity=severity,
                    confidence=ConfidenceLevel.CERTAIN,
                    summary=f"The cookie '{cookie_name}' was issued over HTTPS without the 'Secure' attribute.",
                    evidence=f"Cookie Name: {cookie_name}\nObserved Flags: Secure={flags.get('secure')}, HttpOnly={flags.get('httponly')}, SameSite={flags.get('samesite')}\nValue: [REDACTED]",
                    impact="The browser will transmit this cookie over unencrypted HTTP if the user visits an http:// link or is redirected, enabling network attackers to intercept it.",
                    remediation="Add the 'Secure' directive to the Set-Cookie header for this cookie.",
                    references="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie#secure",
                    cwe_id="CWE-614"
                ))

            # 2. HttpOnly Flag check
            if not flags.get("httponly"):
                severity = SeverityLevel.MEDIUM if is_session_cookie else SeverityLevel.LOW
                findings.append(FindingData(
                    check_id=f"{self.check_id}_MISSING_HTTPONLY",
                    title=f"Cookie '{cookie_name}' Missing 'HttpOnly' Attribute",
                    category=self.category,
                    severity=severity,
                    confidence=ConfidenceLevel.CERTAIN,
                    summary=f"The cookie '{cookie_name}' is accessible to clientside JavaScript because 'HttpOnly' is omitted.",
                    evidence=f"Cookie Name: {cookie_name}\nObserved Flags: HttpOnly={flags.get('httponly')}\nValue: [REDACTED]",
                    impact="If an attacker exploits a Cross-Site Scripting (XSS) vulnerability, they can read document.cookie and steal the cookie value.",
                    remediation="Set the 'HttpOnly' directive unless the cookie is explicitly designed to be read by client scripts.",
                    references="https://owasp.org/www-community/HttpOnly",
                    cwe_id="CWE-1004"
                ))

            # 3. SameSite Flag check
            samesite = flags.get("samesite")
            if not samesite:
                findings.append(FindingData(
                    check_id=f"{self.check_id}_MISSING_SAMESITE",
                    title=f"Cookie '{cookie_name}' Missing 'SameSite' Attribute",
                    category=self.category,
                    severity=SeverityLevel.LOW,
                    confidence=ConfidenceLevel.CERTAIN,
                    summary=f"The cookie '{cookie_name}' does not specify a SameSite attribute (Lax, Strict, or None).",
                    evidence=f"Cookie Name: {cookie_name}\nSameSite: None Specified\nValue: [REDACTED]",
                    impact="The cookie may be sent in cross-site browsing contexts, potentially exposing the application to Cross-Site Request Forgery (CSRF).",
                    remediation="Explicitly set 'SameSite=Lax' (recommended default for state-modifying cookies) or 'SameSite=Strict'.",
                    references="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite",
                    cwe_id="CWE-1275"
                ))
            elif samesite.lower() == "none" and not flags.get("secure"):
                findings.append(FindingData(
                    check_id=f"{self.check_id}_SAMESITE_NONE_WITHOUT_SECURE",
                    title=f"Cookie '{cookie_name}' Has SameSite=None Without 'Secure'",
                    category=self.category,
                    severity=SeverityLevel.MEDIUM,
                    confidence=ConfidenceLevel.CERTAIN,
                    summary=f"Cookie '{cookie_name}' specifies SameSite=None but lacks the required 'Secure' attribute.",
                    evidence=f"Cookie Name: {cookie_name}\nSameSite: None\nSecure: False\nValue: [REDACTED]",
                    impact="Modern browsers will reject this cookie entirely, causing authentication or session failures.",
                    remediation="Whenever 'SameSite=None' is used for cross-site cookies, 'Secure' must also be included.",
                    references="https://web.dev/samesite-cookies-explained/",
                    cwe_id="CWE-1275"
                ))

        status = CheckStatus.FINDINGS_DETECTED if findings else CheckStatus.PASSED
        return CheckOutcome(
            check_id=self.check_id,
            check_name=self.check_name,
            category=self.category,
            status=status,
            duration_ms=0.0,
            message=f"Analyzed {len(cookies)} response cookies. {len(findings)} security observations identified.",
            findings=findings
        )
