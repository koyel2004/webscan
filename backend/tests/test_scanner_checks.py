"""
Tests for Individual Security Checks using Synthetic Test Fixtures
"""
import httpx
import pytest

from app.models.check_result import CheckStatus
from app.models.finding import SeverityLevel
from app.services.scanner.base import ScanContext
from app.services.scanner.checks.cookie_security import CookieSecurityCheck
from app.services.scanner.checks.cors_config import CORSConfigCheck
from app.services.scanner.checks.info_disclosure import InfoDisclosureCheck
from app.services.scanner.checks.response_hygiene import ResponseHygieneCheck
from app.services.scanner.checks.security_headers import SecurityHeadersCheck
from app.services.scanner.checks.tls_inspection import TLSCertificateCheck
from app.services.scanner.safe_client import SafeHTTPResponse


def make_mock_context(
    url="https://test.example.com",
    hostname="test.example.com",
    headers=None,
    cookies=None,
    text="<html><body>Hello</body></html>",
    history_urls=None,
    status_code=200
):
    ctx = ScanContext(
        target_url=url,
        hostname=hostname,
        port=443,
        resolved_ips=["93.184.216.34"],
        timeout_seconds=5.0
    )
    mock_headers = httpx.Headers(headers or {})
    ctx.https_response = SafeHTTPResponse(
        status_code=status_code,
        headers=mock_headers,
        url=url,
        history_urls=history_urls or [url],
        cookies=cookies or {},
        text=text,
        elapsed_seconds=0.1
    )
    return ctx


@pytest.mark.asyncio
async def test_security_headers_missing_all():
    """When all security headers are missing, multiple findings must be identified."""
    ctx = make_mock_context(headers={})
    check = SecurityHeadersCheck()
    outcome = await check.run(ctx)

    assert outcome.status == CheckStatus.FINDINGS_DETECTED
    check_ids = [f.check_id for f in outcome.findings]
    assert "CHECK_SECURITY_HEADERS_CSP_MISSING" in check_ids
    assert "CHECK_SECURITY_HEADERS_HSTS_MISSING" in check_ids
    assert "CHECK_SECURITY_HEADERS_XCTO_MISSING" in check_ids
    assert "CHECK_SECURITY_HEADERS_CLICKJACKING_PROTECTION_MISSING" in check_ids


@pytest.mark.asyncio
async def test_security_headers_permissive_csp():
    """Permissive CSP with unsafe-inline should trigger a LOW severity finding."""
    headers = {
        "content-security-policy": "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'",
        "strict-transport-security": "max-age=31536000; includeSubDomains",
        "x-content-type-options": "nosniff",
        "x-frame-options": "DENY",
        "referrer-policy": "strict-origin-when-cross-origin",
        "permissions-policy": "camera=(), microphone=()",
    }
    ctx = make_mock_context(headers=headers)
    check = SecurityHeadersCheck()
    outcome = await check.run(ctx)

    check_ids = [f.check_id for f in outcome.findings]
    assert "CHECK_SECURITY_HEADERS_CSP_UNSAFE_INLINE" in check_ids
    assert "CHECK_SECURITY_HEADERS_CSP_UNSAFE_EVAL" in check_ids
    assert "CHECK_SECURITY_HEADERS_HSTS_MISSING" not in check_ids


@pytest.mark.asyncio
async def test_cookie_security_missing_flags_and_redaction():
    """Tests detection of missing Secure/HttpOnly and verifies value redaction."""
    cookies = {
        "auth_session": {
            "name": "auth_session",
            "secure": False,
            "httponly": False,
            "samesite": None,
            "value_length": 32,
            "raw_value_redacted": "[REDACTED]"
        }
    }
    ctx = make_mock_context(cookies=cookies)
    check = CookieSecurityCheck()
    outcome = await check.run(ctx)

    assert outcome.status == CheckStatus.FINDINGS_DETECTED
    check_ids = [f.check_id for f in outcome.findings]
    assert "CHECK_COOKIE_SECURITY_MISSING_SECURE" in check_ids
    assert "CHECK_COOKIE_SECURITY_MISSING_HTTPONLY" in check_ids

    # Verify no raw value leaked
    for f in outcome.findings:
        assert "[REDACTED]" in f.evidence
        assert "auth_session" in f.evidence


@pytest.mark.asyncio
async def test_cors_reflection_with_credentials():
    """Detects critical arbitrary origin reflection with credentials enabled."""
    headers = {
        "access-control-allow-origin": "https://sentinelscan-audit-probe.example.com",
        "access-control-allow-credentials": "true",
    }
    ctx = make_mock_context(headers=headers)
    ctx.cors_response = ctx.https_response
    check = CORSConfigCheck()
    outcome = await check.run(ctx)

    assert outcome.status == CheckStatus.FINDINGS_DETECTED
    assert any("REFLECTED_ORIGIN_WITH_CREDENTIALS" in f.check_id for f in outcome.findings)
    high_findings = [f for f in outcome.findings if f.severity == SeverityLevel.HIGH]
    assert len(high_findings) >= 1


@pytest.mark.asyncio
async def test_tls_certificate_checks():
    """Tests TLS check response parsing for expired and mismatch states."""
    ctx = make_mock_context()
    # Mock TLS info dict on context
    ctx.tls_info = {
        "status": "EXPIRED",
        "hostname_matched": True,
        "is_expired": True,
        "days_remaining": -10,
        "version": "TLSv1.3",
        "cipher": ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256),
        "not_after": "Oct 12 12:00:00 2026 GMT",
        "san": ["test.example.com"],
        "error": None,
    }
    check = TLSCertificateCheck()
    outcome = await check.run(ctx)

    assert outcome.status == CheckStatus.FINDINGS_DETECTED
    assert any("EXPIRED" in f.check_id for f in outcome.findings)


@pytest.mark.asyncio
async def test_info_disclosure_headers():
    """Detects server version disclosure banners."""
    headers = {
        "server": "Apache/2.4.41 (Ubuntu)",
        "x-powered-by": "PHP/8.1.2",
    }
    ctx = make_mock_context(headers=headers)
    check = InfoDisclosureCheck()
    outcome = await check.run(ctx)

    assert outcome.status == CheckStatus.FINDINGS_DETECTED
    check_ids = [f.check_id for f in outcome.findings]
    assert "CHECK_INFO_DISCLOSURE_SERVER_VERSION" in check_ids
    assert "CHECK_INFO_DISCLOSURE_X_POWERED_BY" in check_ids


@pytest.mark.asyncio
async def test_response_hygiene_traceback_and_downgrade():
    """Detects python tracebacks and redirect downgrade from HTTPS to HTTP."""
    text_with_trace = (
        "Something broke!\n"
        "Traceback (most recent call last):\n"
        '  File "/app/views.py", line 42, in index\n'
        "KeyError: 'database_secret'"
    )
    history = ["https://example.com", "http://example.com/insecure"]
    ctx = make_mock_context(text=text_with_trace, history_urls=history)

    check = ResponseHygieneCheck()
    outcome = await check.run(ctx)

    assert outcome.status == CheckStatus.FINDINGS_DETECTED
    check_ids = [f.check_id for f in outcome.findings]
    assert "CHECK_RESPONSE_HYGIENE_STACK_TRACE_EXPOSURE" in check_ids
    assert "CHECK_RESPONSE_HYGIENE_PROTOCOL_DOWNGRADE" in check_ids
