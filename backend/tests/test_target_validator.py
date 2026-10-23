"""
Tests for Target Validation and SSRF Protections
"""
import ipaddress

import pytest

from app.core.exceptions import SSRFSecurityViolation, TargetValidationError
from app.services.scanner.target_validator import (
    is_prohibited_ip,
    resolve_and_validate_hostname,
    validate_redirect_target,
    validate_url_syntax,
)


def test_valid_urls():
    """Tests normal, valid URLs parse and normalize correctly."""
    url, host, port, path = validate_url_syntax("https://example.com")
    assert url == "https://example.com/"
    assert host == "example.com"
    assert port == 443

    # With path and query
    url, host, port, path = validate_url_syntax("http://sub.example.org:8080/api/v1?test=1")
    assert host == "sub.example.org"
    assert port == 8080
    assert "test=1" in url


def test_scheme_enforcement():
    """Only HTTP and HTTPS are permitted."""
    with pytest.raises(TargetValidationError):
        validate_url_syntax("ftp://example.com")

    with pytest.raises(TargetValidationError):
        validate_url_syntax("file:///etc/passwd")

    with pytest.raises(TargetValidationError):
        validate_url_syntax("gopher://example.com")

    with pytest.raises(TargetValidationError):
        validate_url_syntax("javascript:alert(1)")


def test_reject_embedded_credentials():
    """Embedded user:pass credentials must be blocked."""
    with pytest.raises(TargetValidationError, match="embedded user credentials"):
        validate_url_syntax("https://admin:secret@example.com")

    with pytest.raises(TargetValidationError, match="embedded user credentials"):
        validate_url_syntax("http://user@example.com")


def test_reject_blocked_ports():
    """Database, SSH, and internal service ports must be blocked."""
    with pytest.raises(TargetValidationError, match="restricted for security reasons"):
        validate_url_syntax("https://example.com:22")

    with pytest.raises(TargetValidationError, match="restricted for security reasons"):
        validate_url_syntax("http://example.com:3306")

    with pytest.raises(TargetValidationError, match="restricted for security reasons"):
        validate_url_syntax("http://example.com:6379")


def test_prohibited_hostnames():
    """Localhost and cloud metadata hostnames must be rejected immediately."""
    with pytest.raises(SSRFSecurityViolation):
        validate_url_syntax("http://localhost")

    with pytest.raises(SSRFSecurityViolation):
        validate_url_syntax("http://metadata.google.internal")

    with pytest.raises(SSRFSecurityViolation):
        validate_url_syntax("http://app.internal")

    with pytest.raises(SSRFSecurityViolation):
        validate_url_syntax("http://service.local")


def test_prohibited_ip_ranges():
    """Private, loopback, link-local, and cloud metadata IPs must be flagged."""
    assert is_prohibited_ip(ipaddress.ip_address("127.0.0.1")) is True
    assert is_prohibited_ip(ipaddress.ip_address("127.0.1.5")) is True
    assert is_prohibited_ip(ipaddress.ip_address("::1")) is True

    # RFC 1918 Private ranges
    assert is_prohibited_ip(ipaddress.ip_address("10.0.0.1")) is True
    assert is_prohibited_ip(ipaddress.ip_address("172.16.0.1")) is True
    assert is_prohibited_ip(ipaddress.ip_address("192.168.1.1")) is True

    # Cloud metadata
    assert is_prohibited_ip(ipaddress.ip_address("169.254.169.254")) is True
    assert is_prohibited_ip(ipaddress.ip_address("100.100.100.200")) is True

    # Public IP should NOT be prohibited
    assert is_prohibited_ip(ipaddress.ip_address("93.184.216.34")) is False
    assert is_prohibited_ip(ipaddress.ip_address("8.8.8.8")) is False


def test_direct_private_ip_resolution_rejection():
    """Direct private IP literals must fail resolve_and_validate_hostname."""
    with pytest.raises(SSRFSecurityViolation):
        resolve_and_validate_hostname("127.0.0.1")

    with pytest.raises(SSRFSecurityViolation):
        resolve_and_validate_hostname("169.254.169.254")

    with pytest.raises(SSRFSecurityViolation):
        resolve_and_validate_hostname("10.10.10.10")


def test_redirect_validation_rejection():
    """Redirects to loopback or private ranges must be blocked."""
    with pytest.raises(SSRFSecurityViolation):
        validate_redirect_target("https://example.com", "http://127.0.0.1/admin")

    with pytest.raises(SSRFSecurityViolation):
        validate_redirect_target("https://example.com", "http://169.254.169.254/latest/meta-data/")
