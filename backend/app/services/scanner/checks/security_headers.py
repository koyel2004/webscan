"""
Check B: HTTP Security Response Headers
Evaluates CSP, HSTS, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, and X-Frame-Options.
"""

from app.models.check_result import CheckStatus
from app.models.finding import ConfidenceLevel, SeverityLevel
from app.services.scanner.base import (
    BaseSecurityCheck,
    CheckOutcome,
    FindingData,
    ScanContext,
)


class SecurityHeadersCheck(BaseSecurityCheck):
    check_id = "CHECK_SECURITY_HEADERS"
    check_name = "HTTP Security Headers"
    category = "headers"
    description = "Inspects defensive HTTP response headers to detect missing or misconfigured security policies."

    async def run(self, context: ScanContext) -> CheckOutcome:
        findings: list[FindingData] = []

        # Get response (prefer HTTPS)
        resp = context.https_response
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
                    message=f"Could not retrieve headers: {e}",
                    error_detail=str(e),
                    findings=[]
                )

        headers = {k.lower(): v for k, v in resp.headers.items()}

        # 1. Content-Security-Policy (CSP)
        csp = headers.get("content-security-policy")
        if not csp:
            findings.append(FindingData(
                check_id=f"{self.check_id}_CSP_MISSING",
                title="Missing Content-Security-Policy (CSP) Header",
                category=self.category,
                severity=SeverityLevel.MEDIUM,
                confidence=ConfidenceLevel.CERTAIN,
                summary="The response does not include a Content-Security-Policy header.",
                evidence="Header 'Content-Security-Policy' is absent in the response.",
                impact="Without a CSP, the application lacks defense-in-depth protection against Cross-Site Scripting (XSS), malicious script injection, and clickjacking.",
                remediation="Implement a Content-Security-Policy header that restricts allowed script, style, and media sources (e.g. default-src 'self').",
                references="https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP\nhttps://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html",
                cwe_id="CWE-1021"
            ))
        else:
            csp_lower = csp.lower()
            if "'unsafe-inline'" in csp_lower and "nonce-" not in csp_lower and "sha256-" not in csp_lower:
                findings.append(FindingData(
                    check_id=f"{self.check_id}_CSP_UNSAFE_INLINE",
                    title="Permissive CSP with 'unsafe-inline' Directive",
                    category=self.category,
                    severity=SeverityLevel.LOW,
                    confidence=ConfidenceLevel.CERTAIN,
                    summary="The Content-Security-Policy enables 'unsafe-inline' without cryptographic nonces or hashes.",
                    evidence=f"Content-Security-Policy: {csp[:300]}...",
                    impact="Allowing inline scripts diminishes the effectiveness of CSP against Cross-Site Scripting (XSS) payloads.",
                    remediation="Refactor inline scripts into external files and use cryptographic nonces (nonce-...) or SHA hashes for necessary inline snippets.",
                    references="https://content-security-policy.com/",
                    cwe_id="CWE-79"
                ))
            if "'unsafe-eval'" in csp_lower:
                findings.append(FindingData(
                    check_id=f"{self.check_id}_CSP_UNSAFE_EVAL",
                    title="Permissive CSP with 'unsafe-eval' Directive",
                    category=self.category,
                    severity=SeverityLevel.LOW,
                    confidence=ConfidenceLevel.CERTAIN,
                    summary="The Content-Security-Policy enables 'unsafe-eval', permitting dynamic string-to-code evaluation.",
                    evidence=f"Content-Security-Policy: {csp[:300]}...",
                    impact="Permitting eval() and Function() increases risk if untrusted inputs reach dynamic execution sinks.",
                    remediation="Remove 'unsafe-eval' and eliminate usage of eval() in application JavaScript.",
                    references="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/script-src",
                    cwe_id="CWE-95"
                ))

        # 2. Strict-Transport-Security (HSTS)
        hsts = headers.get("strict-transport-security")
        is_https_target = resp.url.lower().startswith("https://")
        if is_https_target:
            if not hsts:
                findings.append(FindingData(
                    check_id=f"{self.check_id}_HSTS_MISSING",
                    title="Missing HTTP Strict-Transport-Security (HSTS) Header",
                    category=self.category,
                    severity=SeverityLevel.MEDIUM,
                    confidence=ConfidenceLevel.CERTAIN,
                    summary="The HTTPS response does not enforce HSTS.",
                    evidence="Header 'Strict-Transport-Security' is absent in the HTTPS response.",
                    impact="Browsers may attempt unencrypted HTTP connections on future visits, allowing attackers on the local network to perform SSL stripping attacks.",
                    remediation="Send Strict-Transport-Security: max-age=31536000; includeSubDomains; preload on all HTTPS responses.",
                    references="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security",
                    cwe_id="CWE-319"
                ))
            else:
                # Check max-age
                hsts_lower = hsts.lower()
                if "max-age=" in hsts_lower:
                    try:
                        max_age_part = [p.strip() for p in hsts_lower.split(";") if p.strip().startswith("max-age=")][0]
                        max_age_val = int(max_age_part.split("=")[1])
                        if max_age_val < 10368000:  # < 120 days
                            findings.append(FindingData(
                                check_id=f"{self.check_id}_HSTS_SHORT_MAX_AGE",
                                title="Short HSTS max-age Duration",
                                category=self.category,
                                severity=SeverityLevel.LOW,
                                confidence=ConfidenceLevel.CERTAIN,
                                summary=f"HSTS max-age is set to {max_age_val} seconds, which is less than the recommended 1 year (31536000 seconds).",
                                evidence=f"Strict-Transport-Security: {hsts}",
                                impact="Users who do not visit the site frequently may lose HSTS protection.",
                                remediation="Increase max-age to at least 31536000 (1 year) once HTTPS configuration is stable.",
                                references="https://hstspreload.org/",
                                cwe_id="CWE-319"
                            ))
                    except Exception:
                        pass

        # 3. X-Content-Type-Options
        xcto = headers.get("x-content-type-options")
        if not xcto or xcto.lower().strip() != "nosniff":
            findings.append(FindingData(
                check_id=f"{self.check_id}_XCTO_MISSING",
                title="Missing or Invalid X-Content-Type-Options Header",
                category=self.category,
                severity=SeverityLevel.LOW,
                confidence=ConfidenceLevel.CERTAIN,
                summary="The response lacks 'X-Content-Type-Options: nosniff'.",
                evidence=f"Observed value: {xcto or 'Absent'}",
                impact="Browsers may perform MIME-type sniffing, treating text or images as executable script files if MIME types are misconfigured.",
                remediation="Add 'X-Content-Type-Options: nosniff' to all server responses.",
                references="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options",
                cwe_id="CWE-430"
            ))

        # 4. Clickjacking Protection (X-Frame-Options or CSP frame-ancestors)
        xfo = headers.get("x-frame-options")
        has_csp_frame_ancestors = bool(csp and "frame-ancestors" in csp.lower())
        if not xfo and not has_csp_frame_ancestors:
            findings.append(FindingData(
                check_id=f"{self.check_id}_CLICKJACKING_PROTECTION_MISSING",
                title="Missing Anti-Clickjacking Protection (X-Frame-Options / frame-ancestors)",
                category=self.category,
                severity=SeverityLevel.MEDIUM,
                confidence=ConfidenceLevel.CERTAIN,
                summary="The site does not define an X-Frame-Options header or CSP 'frame-ancestors' directive.",
                evidence="Neither 'X-Frame-Options' nor CSP 'frame-ancestors' was found in response headers.",
                impact="Malicious sites can embed this web page inside an invisible iframe and trick authenticated visitors into performing unintended actions (Clickjacking).",
                remediation="Add 'Content-Security-Policy: frame-ancestors 'self'' or 'X-Frame-Options: DENY' / 'SAMEORIGIN'.",
                references="https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html",
                cwe_id="CWE-1021"
            ))

        # 5. Referrer-Policy
        ref_policy = headers.get("referrer-policy")
        if not ref_policy:
            findings.append(FindingData(
                check_id=f"{self.check_id}_REFERRER_POLICY_MISSING",
                title="Missing Referrer-Policy Header",
                category=self.category,
                severity=SeverityLevel.INFORMATIONAL,
                confidence=ConfidenceLevel.CERTAIN,
                summary="The response does not specify a Referrer-Policy header.",
                evidence="Header 'Referrer-Policy' is absent.",
                impact="User navigation away from the site may leak sensitive query parameters or internal URL paths to external origins.",
                remediation="Configure 'Referrer-Policy: strict-origin-when-cross-origin' or 'no-referrer'.",
                references="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy",
                cwe_id="CWE-200"
            ))
        elif ref_policy.lower().strip() == "unsafe-url":
            findings.append(FindingData(
                check_id=f"{self.check_id}_REFERRER_POLICY_UNSAFE",
                title="Insecure Referrer-Policy Set to 'unsafe-url'",
                category=self.category,
                severity=SeverityLevel.LOW,
                confidence=ConfidenceLevel.CERTAIN,
                summary="Referrer-Policy is configured to 'unsafe-url', sending full URL paths even across unencrypted connections.",
                evidence=f"Referrer-Policy: {ref_policy}",
                impact="Sensitive URLs containing tokens, query strings, or internal paths are broadcast to third-party endpoints.",
                remediation="Change policy to 'strict-origin-when-cross-origin' or 'no-referrer'.",
                references="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy",
                cwe_id="CWE-200"
            ))

        # 6. Permissions-Policy
        perm_policy = headers.get("permissions-policy")
        if not perm_policy:
            findings.append(FindingData(
                check_id=f"{self.check_id}_PERMISSIONS_POLICY_MISSING",
                title="Missing Permissions-Policy Header",
                category=self.category,
                severity=SeverityLevel.INFORMATIONAL,
                confidence=ConfidenceLevel.CERTAIN,
                summary="Permissions-Policy header is not set.",
                evidence="Header 'Permissions-Policy' is absent.",
                impact="The browser does not restrict access to sensitive device APIs like geolocation, microphone, or camera inside embedded iframes.",
                remediation="Define a Permissions-Policy header disabling unused browser hardware features (e.g. camera=(), microphone=(), geolocation=()).",
                references="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy",
                cwe_id="CWE-250"
            ))

        status = CheckStatus.FINDINGS_DETECTED if findings else CheckStatus.PASSED
        return CheckOutcome(
            check_id=self.check_id,
            check_name=self.check_name,
            category=self.category,
            status=status,
            duration_ms=0.0,
            message=f"Evaluated security headers: {len(findings)} recommendations identified.",
            findings=findings
        )
