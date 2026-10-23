"""
Target Validation and SSRF Protection Engine
Enforces strict URL parsing, hostname sanitization, DNS resolution checks,
IP address blacklisting (private, loopback, link-local, multicast, cloud metadata),
and redirect policy verification.
"""
import ipaddress
import socket
from urllib.parse import urljoin, urlsplit

from app.core.config import settings
from app.core.exceptions import SSRFSecurityViolation, TargetValidationError
from app.core.logging import logger

# Prohibited hostnames (cloud metadata, internal aliases, local domains)
PROHIBITED_HOSTNAMES = {
    "localhost",
    "localhost.localdomain",
    "metadata.google.internal",
    "instance-data",
    "metadata",
    "kubernetes.default",
    "kubernetes.default.svc",
}

# Explicit cloud metadata IPs
CLOUD_METADATA_IPS = {
    "169.254.169.254",   # AWS, GCP, Azure, OpenStack
    "169.254.169.253",
    "100.100.100.200",   # Alibaba Cloud
    "fd00:ec2::254",     # AWS IPv6
}

# Carrier Grade NAT (100.64.0.0/10)
CGNAT_NET = ipaddress.ip_network("100.64.0.0/10")


def is_prohibited_ip(ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Checks whether an IP address belongs to any non-public or dangerous range."""
    ip_str = str(ip_obj)

    if ip_str in CLOUD_METADATA_IPS:
        return True

    if ip_obj.is_loopback:
        return True
    if ip_obj.is_private:
        return True
    if ip_obj.is_link_local:
        return True
    if ip_obj.is_multicast:
        return True
    if ip_obj.is_reserved:
        return True
    if ip_obj.is_unspecified:
        return True

    # Carrier-grade NAT
    if ip_obj.version == 4 and ip_obj in CGNAT_NET:
        return True

    # IPv4 mapped IPv6 (e.g. ::ffff:127.0.0.1)
    if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj.ipv4_mapped:
        return is_prohibited_ip(ip_obj.ipv4_mapped)

    return False


def validate_url_syntax(url_str: str) -> tuple[str, str, int, str]:
    """
    Validates URL scheme, credentials, hostnames, and ports.
    Returns: (normalized_url, hostname, port, path)
    """
    if not url_str or not isinstance(url_str, str):
        raise TargetValidationError("Target URL must be a non-empty string.")

    cleaned_url = url_str.strip()
    parsed_initial = urlsplit(cleaned_url)
    if parsed_initial.scheme:
        if parsed_initial.scheme.lower() not in ("http", "https"):
            raise TargetValidationError(f"Invalid URL scheme '{parsed_initial.scheme}'. Only HTTP and HTTPS are permitted.")
    elif not cleaned_url.startswith(("http://", "https://")):
        cleaned_url = "https://" + cleaned_url

    parsed = urlsplit(cleaned_url)

    if parsed.scheme.lower() not in ("http", "https"):
        raise TargetValidationError(f"Invalid URL scheme '{parsed.scheme}'. Only HTTP and HTTPS are permitted.")

    # Reject embedded credentials (e.g. http://user:pass@host)
    if parsed.username or parsed.password or ("@" in parsed.netloc):
        raise TargetValidationError("URLs with embedded user credentials (user:pass@) are strictly prohibited.")

    hostname = parsed.hostname
    if not hostname:
        raise TargetValidationError("Invalid URL: missing target hostname.")

    hostname = hostname.rstrip(".").lower()

    # Reject prohibited special hostnames
    if hostname in PROHIBITED_HOSTNAMES:
        raise SSRFSecurityViolation(f"Target hostname '{hostname}' is a reserved internal or metadata host.")

    if hostname.endswith((".local", ".internal", ".localhost", ".lan")):
        raise SSRFSecurityViolation(f"Target domain '{hostname}' belongs to a non-public internal namespace.")

    # Determine port
    if parsed.port:
        port = parsed.port
    else:
        port = 443 if parsed.scheme.lower() == "https" else 80

    if port in settings.BLOCKED_PORTS:
        raise TargetValidationError(f"Port {port} is restricted for security reasons.")

    if port not in settings.ALLOWED_PORTS:
        raise TargetValidationError(f"Port {port} is not permitted. Allowed ports: {settings.ALLOWED_PORTS}")

    path = parsed.path if parsed.path else "/"
    normalized_url = f"{parsed.scheme.lower()}://{hostname}:{port}{path}"
    if (parsed.scheme.lower() == "https" and port == 443) or (parsed.scheme.lower() == "http" and port == 80):
        normalized_url = f"{parsed.scheme.lower()}://{hostname}{path}"

    if parsed.query:
        normalized_url += f"?{parsed.query}"

    return normalized_url, hostname, port, path


def resolve_and_validate_hostname(hostname: str) -> list[str]:
    """
    Resolves hostname to IP addresses and checks every address against SSRF rules.
    Returns list of safe resolved IP strings.
    """
    # Direct IP literal check
    try:
        ip_direct = ipaddress.ip_address(hostname)
        if not settings.ALLOW_PRIVATE_IPS and is_prohibited_ip(ip_direct):
            raise SSRFSecurityViolation(
                f"Direct target IP '{hostname}' belongs to a private, loopback, or cloud-metadata range."
            )
        return [str(ip_direct)]
    except ValueError:
        # Hostname is a domain name, proceed to DNS resolution
        pass

    try:
        addr_infos = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except socket.gaierror as e:
        raise TargetValidationError(f"Could not resolve target hostname '{hostname}': {e}")

    if not addr_infos:
        raise TargetValidationError(f"No IP address records found for hostname '{hostname}'.")

    safe_ips: list[str] = []
    for info in addr_infos:
        sockaddr = info[4]
        ip_str = sockaddr[0]
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            if not settings.ALLOW_PRIVATE_IPS and is_prohibited_ip(ip_obj):
                logger.warning(f"SSRF violation: Hostname '{hostname}' resolved to prohibited IP '{ip_str}'")
                raise SSRFSecurityViolation(
                    f"Hostname '{hostname}' resolved to prohibited IP '{ip_str}' (private/loopback/cloud metadata)."
                )
            if ip_str not in safe_ips:
                safe_ips.append(ip_str)
        except ValueError:
            raise TargetValidationError(f"Invalid resolved IP '{ip_str}' for hostname '{hostname}'.")

    if not safe_ips:
        raise TargetValidationError(f"No valid public IP addresses found for hostname '{hostname}'.")

    return safe_ips


def validate_redirect_target(current_url: str, redirect_target: str) -> str:
    """
    Validates a redirect URL against scope and SSRF rules.
    Returns validated absolute redirect URL.
    """
    absolute_url = urljoin(current_url, redirect_target)
    normalized_url, hostname, port, _ = validate_url_syntax(absolute_url)
    resolve_and_validate_hostname(hostname)
    return normalized_url
