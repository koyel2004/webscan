"""
Development Seed Data Generator
Inserts clearly marked demonstration scan records with realistic security findings.
"""
from datetime import UTC, datetime, timedelta

from sqlalchemy.orm import Session

from app.core.logging import logger
from app.models.finding import ConfidenceLevel, Finding, SeverityLevel
from app.models.scan import Scan, ScanStatus


def seed_demo_data(db: Session) -> int:
    """Inserts mock scans with realistic vulnerability profiles for local evaluation."""
    now = datetime.now(UTC)

    # 1. Target with high/critical findings: insecure-demo.sentinelscan.test
    scan_1 = Scan(
        id="demo-scan-alpha-001",
        target_url="https://insecure-demo.sentinelscan.test",
        target_hostname="insecure-demo.sentinelscan.test",
        target_ip="93.184.216.34",
        status=ScanStatus.COMPLETED,
        profile="safe_default",
        timeout_seconds=10.0,
        user_authorized=True,
        created_at=now - timedelta(hours=3),
        started_at=now - timedelta(hours=3),
        completed_at=now - timedelta(hours=3) + timedelta(seconds=8.4),
        duration_seconds=8.4,
        total_checks=7,
        passed_checks=2,
        failed_checks=5,
        inconclusive_checks=0,
        total_findings=5,
        critical_count=1,
        high_count=2,
        medium_count=1,
        low_count=1,
        info_count=0,
    )
    db.add(scan_1)

    f1_1 = Finding(
        scan_id=scan_1.id,
        check_id="CHECK_TLS_CERTIFICATE_EXPIRED",
        title="TLS Certificate is Expired",
        category="tls",
        severity=SeverityLevel.CRITICAL,
        confidence=ConfidenceLevel.CERTAIN,
        hostname=scan_1.target_hostname,
        summary="The TLS certificate expired 14 days ago on 2026-10-08 GMT.",
        evidence="Certificate Not-After: Oct 08 12:00:00 2026 GMT\nDays Remaining: -14",
        impact="Browsers terminate connection to the site and display intrusive full-page security warnings to users.",
        remediation="Renew and deploy a valid certificate immediately via Let's Encrypt or your Certificate Authority.",
        references="https://www.eff.org/deeplinks/2016/11/how-tls-certificates-work",
        cwe_id="CWE-298",
        created_at=now - timedelta(hours=3),
    )
    f1_2 = Finding(
        scan_id=scan_1.id,
        check_id="CHECK_CORS_CONFIG_REFLECTED_ORIGIN_WITH_CREDENTIALS",
        title="Critical CORS Misconfiguration: Arbitrary Origin Reflection with Credentials",
        category="cors",
        severity=SeverityLevel.HIGH,
        confidence=ConfidenceLevel.CERTAIN,
        hostname=scan_1.target_hostname,
        summary="Server reflected the arbitrary probe origin 'https://sentinelscan-audit-probe.example.com' with credentials enabled.",
        evidence="Origin: https://sentinelscan-audit-probe.example.com\nAccess-Control-Allow-Origin: https://sentinelscan-audit-probe.example.com\nAccess-Control-Allow-Credentials: true",
        impact="Third-party malicious websites can make authenticated API requests and read private user information.",
        remediation="Maintain a strict whitelist of approved origins instead of blindly reflecting the incoming Origin header.",
        references="https://portswigger.net/web-security/cors",
        cwe_id="CWE-346",
        created_at=now - timedelta(hours=3),
    )
    f1_3 = Finding(
        scan_id=scan_1.id,
        check_id="CHECK_COOKIE_SECURITY_MISSING_SECURE",
        title="Cookie 'session_id' Missing 'Secure' Attribute",
        category="cookies",
        severity=SeverityLevel.HIGH,
        confidence=ConfidenceLevel.CERTAIN,
        hostname=scan_1.target_hostname,
        summary="Session cookie was issued over HTTPS without the 'Secure' flag.",
        evidence="Cookie Name: session_id\nFlags: HttpOnly=True, SameSite=Lax, Secure=False\nValue: [REDACTED]",
        impact="The session identifier can be transmitted over plain HTTP if the user navigates to an unencrypted link.",
        remediation="Ensure the 'Secure' directive is appended to Set-Cookie for all authentication tokens.",
        references="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie#secure",
        cwe_id="CWE-614",
        created_at=now - timedelta(hours=3),
    )
    f1_4 = Finding(
        scan_id=scan_1.id,
        check_id="CHECK_SECURITY_HEADERS_CSP_MISSING",
        title="Missing Content-Security-Policy (CSP) Header",
        category="headers",
        severity=SeverityLevel.MEDIUM,
        confidence=ConfidenceLevel.CERTAIN,
        hostname=scan_1.target_hostname,
        summary="The HTTP response headers do not define a Content-Security-Policy.",
        evidence="Header 'Content-Security-Policy' is absent in response.",
        impact="Application lacks defense-in-depth protection against script injection and XSS.",
        remediation="Implement a Content-Security-Policy restricting script sources (e.g. default-src 'self').",
        references="https://content-security-policy.com/",
        cwe_id="CWE-1021",
        created_at=now - timedelta(hours=3),
    )
    f1_5 = Finding(
        scan_id=scan_1.id,
        check_id="CHECK_INFO_DISCLOSURE_SERVER_VERSION",
        title="Detailed Web Server Software and Version Disclosed",
        category="info_disclosure",
        severity=SeverityLevel.LOW,
        confidence=ConfidenceLevel.CERTAIN,
        hostname=scan_1.target_hostname,
        summary="The 'Server' header exposes detailed software versions: 'Apache/2.4.41 (Ubuntu)'.",
        evidence="Server: Apache/2.4.41 (Ubuntu)",
        impact="Provides attackers with actionable information about installed software versions.",
        remediation="Configure ServerTokens Prod in Apache httpd configuration.",
        references="https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server",
        cwe_id="CWE-200",
        created_at=now - timedelta(hours=3),
    )
    db.add_all([f1_1, f1_2, f1_3, f1_4, f1_5])

    # 2. Hardened Target: hardened-demo.sentinelscan.test
    scan_2 = Scan(
        id="demo-scan-bravo-002",
        target_url="https://hardened-demo.sentinelscan.test",
        target_hostname="hardened-demo.sentinelscan.test",
        target_ip="104.21.45.12",
        status=ScanStatus.COMPLETED,
        profile="safe_default",
        timeout_seconds=10.0,
        user_authorized=True,
        created_at=now - timedelta(hours=1),
        started_at=now - timedelta(hours=1),
        completed_at=now - timedelta(hours=1) + timedelta(seconds=4.2),
        duration_seconds=4.2,
        total_checks=7,
        passed_checks=6,
        failed_checks=1,
        inconclusive_checks=0,
        total_findings=1,
        critical_count=0,
        high_count=0,
        medium_count=0,
        low_count=0,
        info_count=1,
    )
    db.add(scan_2)

    f2_1 = Finding(
        scan_id=scan_2.id,
        check_id="CHECK_SECURITY_HEADERS_PERMISSIONS_POLICY_MISSING",
        title="Missing Permissions-Policy Header",
        category="headers",
        severity=SeverityLevel.INFORMATIONAL,
        confidence=ConfidenceLevel.CERTAIN,
        hostname=scan_2.target_hostname,
        summary="The site does not define a Permissions-Policy header.",
        evidence="Header 'Permissions-Policy' is absent in response.",
        impact="Embedded iframes retain default browser permission policies for sensors and media.",
        remediation="Add Permissions-Policy: camera=(), microphone=(), geolocation=() to lock down hardware access.",
        references="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy",
        cwe_id="CWE-250",
        created_at=now - timedelta(hours=1),
    )
    db.add(f2_1)

    db.commit()
    logger.info("Successfully seeded demo scan records.")
    return 2
