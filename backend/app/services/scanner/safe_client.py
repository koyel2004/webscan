"""
Safe Controlled HTTP Client and TLS Probe for SentinelScan
Enforces granular timeouts, redirect validation, response size bounds,
and safe certificate inspection.
"""
import socket
import ssl
from datetime import UTC, datetime
from typing import Any

import httpx

from app.core.config import settings
from app.core.exceptions import ScanExecutionError, SSRFSecurityViolation
from app.core.logging import logger
from app.services.scanner.target_validator import (
    resolve_and_validate_hostname,
    validate_redirect_target,
    validate_url_syntax,
)


class SafeHTTPResponse:
    """Wrapper for controlled HTTP responses."""
    def __init__(
        self,
        status_code: int,
        headers: httpx.Headers,
        url: str,
        history_urls: list[str],
        cookies: dict[str, dict[str, Any]],
        text: str,
        elapsed_seconds: float
    ):
        self.status_code = status_code
        self.headers = headers
        self.url = url
        self.history_urls = history_urls
        self.cookies = cookies
        self.text = text
        self.elapsed_seconds = elapsed_seconds


class SafeClient:
    """
    Controlled HTTP client that prevents SSRF, enforces size limits,
    validates every redirect hop, and captures cookie attributes securely.
    """

    def __init__(self, timeout_seconds: float = 10.0):
        self.timeout = min(timeout_seconds, settings.SCAN_MAX_TIMEOUT_SECONDS)
        self.max_redirects = settings.SCAN_MAX_REDIRECTS
        self.max_bytes = settings.SCAN_MAX_RESPONSE_BYTES

    async def get(
        self,
        url: str,
        headers: dict[str, str] | None = None,
        follow_redirects: bool = True
    ) -> SafeHTTPResponse:
        """
        Executes a controlled HTTP GET request with manual redirect validation.
        """
        current_url, hostname, port, _ = validate_url_syntax(url)
        resolve_and_validate_hostname(hostname)

        req_headers = {
            "User-Agent": "SentinelScan-Security-Auditor/1.0 (+https://github.com/sentinelscan)",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Encoding": "gzip, deflate",
        }
        if headers:
            req_headers.update(headers)

        history_urls: list[str] = []
        cookies_captured: dict[str, dict[str, Any]] = {}

        transport = httpx.AsyncHTTPTransport(verify=True)
        async with httpx.AsyncClient(
            transport=transport,
            timeout=httpx.Timeout(self.timeout, connect=min(5.0, self.timeout)),
            follow_redirects=False,
        ) as client:
            hops = 0
            while True:
                start_time = datetime.now(UTC)
                try:
                    response = await client.get(current_url, headers=req_headers)
                except httpx.TimeoutException as e:
                    raise ScanExecutionError(f"Connection timed out after {self.timeout}s: {e}")
                except httpx.ConnectError as e:
                    raise ScanExecutionError(f"Failed to connect to target '{current_url}': {e}")
                except Exception as e:
                    raise ScanExecutionError(f"HTTP request failed for '{current_url}': {e}")

                elapsed = (datetime.now(UTC) - start_time).total_seconds()
                history_urls.append(current_url)

                # Capture cookies with security attributes (without persisting raw values)
                for header_key, header_val in response.headers.multi_items():
                    if header_key.lower() == "set-cookie":
                        self._parse_set_cookie(header_val, current_url, cookies_captured)

                # Check redirect
                if follow_redirects and response.is_redirect and "location" in response.headers:
                    if hops >= self.max_redirects:
                        logger.warning(f"Exceeded max redirects ({self.max_redirects}) for '{url}'")
                        break

                    redirect_location = response.headers["location"]
                    try:
                        next_url = validate_redirect_target(current_url, redirect_location)
                    except (SSRFSecurityViolation, Exception) as e:
                        logger.warning(f"Blocked dangerous redirect to '{redirect_location}': {e}")
                        break

                    current_url = next_url
                    hops += 1
                    continue

                # Stream and cap body text length
                body_bytes = response.content[:self.max_bytes]
                body_text = body_bytes.decode("utf-8", errors="replace")

                return SafeHTTPResponse(
                    status_code=response.status_code,
                    headers=response.headers,
                    url=str(response.url),
                    history_urls=history_urls,
                    cookies=cookies_captured,
                    text=body_text,
                    elapsed_seconds=elapsed,
                )

    def _parse_set_cookie(self, raw_cookie: str, request_url: str, cookies_dict: dict[str, dict[str, Any]]) -> None:
        """
        Parses Set-Cookie header into metadata and flags, redacting raw cookie value.
        """
        parts = [p.strip() for p in raw_cookie.split(";") if p.strip()]
        if not parts:
            return

        first_part = parts[0]
        if "=" in first_part:
            name, _ = first_part.split("=", 1)
        else:
            name = first_part

        flags: dict[str, Any] = {
            "name": name.strip(),
            "secure": False,
            "httponly": False,
            "samesite": None,
            "domain": None,
            "path": None,
            "expires": None,
            "max_age": None,
            "value_length": len(first_part.split("=", 1)[1]) if "=" in first_part else 0,
            "raw_value_redacted": "[REDACTED]",
        }

        for attr in parts[1:]:
            attr_lower = attr.lower()
            if attr_lower == "secure":
                flags["secure"] = True
            elif attr_lower == "httponly":
                flags["httponly"] = True
            elif attr_lower.startswith("samesite"):
                if "=" in attr:
                    flags["samesite"] = attr.split("=", 1)[1].strip()
                else:
                    flags["samesite"] = "None"
            elif attr_lower.startswith("domain"):
                if "=" in attr:
                    flags["domain"] = attr.split("=", 1)[1].strip()
            elif attr_lower.startswith("path"):
                if "=" in attr:
                    flags["path"] = attr.split("=", 1)[1].strip()
            elif attr_lower.startswith("expires"):
                if "=" in attr:
                    flags["expires"] = attr.split("=", 1)[1].strip()
            elif attr_lower.startswith("max-age"):
                if "=" in attr:
                    flags["max_age"] = attr.split("=", 1)[1].strip()

        cookies_dict[name.strip()] = flags


def inspect_tls_certificate(hostname: str, port: int = 443, timeout_seconds: float = 10.0) -> dict[str, Any]:
    """
    Connects to target via standard Python SSL library and extracts TLS details.
    Does not disable certificate verification.
    """
    # Validate hostname & resolve safe IPs first
    resolve_and_validate_hostname(hostname)

    context = ssl.create_default_context()
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED

    result: dict[str, Any] = {
        "status": "VALID",
        "hostname_matched": True,
        "is_expired": False,
        "days_remaining": None,
        "version": None,
        "cipher": None,
        "subject": {},
        "issuer": {},
        "san": [],
        "not_before": None,
        "not_after": None,
        "error": None,
    }

    try:
        with socket.create_connection((hostname, port), timeout=timeout_seconds) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                result["version"] = ssock.version()
                result["cipher"] = ssock.cipher()

                if cert:
                    # Subject
                    for rdn in cert.get("subject", ()):
                        for key, val in rdn:
                            result["subject"][key] = val

                    # Issuer
                    for rdn in cert.get("issuer", ()):
                        for key, val in rdn:
                            result["issuer"][key] = val

                    # Subject Alternative Names (SAN)
                    san_list = [entry[1] for entry in cert.get("subjectAltName", ()) if len(entry) > 1]
                    result["san"] = san_list

                    # Validity dates
                    not_after_str = cert.get("notAfter")
                    not_before_str = cert.get("notBefore")
                    result["not_before"] = not_before_str
                    result["not_after"] = not_after_str

                    if not_after_str:
                        # Format example: 'May 15 12:00:00 2027 GMT'
                        expiry_date = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=UTC)
                        now_utc = datetime.now(UTC)
                        delta = (expiry_date - now_utc).days
                        result["days_remaining"] = delta
                        if delta < 0:
                            result["is_expired"] = True
                            result["status"] = "EXPIRED"

    except ssl.SSLCertVerificationError as e:
        result["status"] = "VERIFICATION_FAILED"
        result["error"] = f"SSL Certificate Verification Failed: {e.verify_message or str(e)}"
        if "hostname" in str(e).lower():
            result["hostname_matched"] = False
        if "expired" in str(e).lower():
            result["is_expired"] = True
    except TimeoutError:
        result["status"] = "CONNECTION_TIMEOUT"
        result["error"] = f"TLS handshake connection timed out after {timeout_seconds}s"
    except Exception as e:
        result["status"] = "ERROR"
        result["error"] = f"TLS connection error: {e!s}"

    return result
