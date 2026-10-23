"""
Registry of all security checks
"""
from app.services.scanner.base import BaseSecurityCheck
from app.services.scanner.checks.cookie_security import CookieSecurityCheck
from app.services.scanner.checks.cors_config import CORSConfigCheck
from app.services.scanner.checks.https_redirect import HTTPSRedirectCheck
from app.services.scanner.checks.info_disclosure import InfoDisclosureCheck
from app.services.scanner.checks.response_hygiene import ResponseHygieneCheck
from app.services.scanner.checks.security_headers import SecurityHeadersCheck
from app.services.scanner.checks.tls_inspection import TLSCertificateCheck

ALL_CHECKS: list[BaseSecurityCheck] = [
    HTTPSRedirectCheck(),
    SecurityHeadersCheck(),
    CookieSecurityCheck(),
    CORSConfigCheck(),
    TLSCertificateCheck(),
    InfoDisclosureCheck(),
    ResponseHygieneCheck(),
]

__all__ = [
    "ALL_CHECKS",
    "CORSConfigCheck",
    "CookieSecurityCheck",
    "HTTPSRedirectCheck",
    "InfoDisclosureCheck",
    "ResponseHygieneCheck",
    "SecurityHeadersCheck",
    "TLSCertificateCheck",
]
