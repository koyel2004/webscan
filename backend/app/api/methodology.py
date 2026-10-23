"""
Methodology API Router
Provides documented assessment standards, check descriptions, and severity scoring rules.
"""
from fastapi import APIRouter

from app.services.scanner.checks import ALL_CHECKS

router = APIRouter(prefix="/methodology", tags=["Methodology"])


@router.get("")
def get_security_methodology():
    """Returns the defensive security audit methodology and scoring principles."""
    checks_documented = [
        {
            "check_id": c.check_id,
            "name": c.check_name,
            "category": c.category,
            "description": c.description,
        }
        for c in ALL_CHECKS
    ]

    severity_rules = [
        {
            "severity": "CRITICAL",
            "criteria": "Direct, severe security exposure allowing immediate exploitation, expired TLS certificates causing outages, or arbitrary CORS origin reflection with credentials.",
            "sla": "Remediate within 24 hours.",
        },
        {
            "severity": "HIGH",
            "criteria": "Missing essential cryptographic protections, missing Secure flag on session cookies, TLS hostname mismatch, or untrusted root certificate authorities.",
            "sla": "Remediate within 7 days.",
        },
        {
            "severity": "MEDIUM",
            "criteria": "Missing Content-Security-Policy (CSP), absent anti-clickjacking protection (X-Frame-Options), missing HSTS on HTTPS targets, or unencrypted HTTP without automatic redirect.",
            "sla": "Remediate in next development release.",
        },
        {
            "severity": "LOW",
            "criteria": "Permissive CSP directives (unsafe-inline/unsafe-eval), missing X-Content-Type-Options: nosniff, short HSTS max-age, or server banner version disclosures.",
            "sla": "Address during scheduled maintenance.",
        },
        {
            "severity": "INFORMATIONAL",
            "criteria": "Missing Permissions-Policy, Referrer-Policy, or general defense-in-depth posture improvements.",
            "sla": "Adopt as security best practice.",
        },
    ]

    boundaries = {
        "non_destructive": "SentinelScan only performs safe, read-only HTTP probes and TLS handshakes. It never attempts SQL injection, credential brute-forcing, directory traversal, or file upload exploitation.",
        "ssrf_defense": "Targets are validated at both the URL parsing and DNS resolution levels. Requests to private networks (RFC 1918), loopback (127.0.0.0/8), link-local, and cloud metadata (169.254.169.254) are strictly blocked.",
        "authorization": "All assessments require explicit confirmation of target ownership or authorization. Testing unauthorized external targets is strictly prohibited.",
        "limitations": "Automated external configuration checks cannot replace authenticated internal application security reviews, threat modeling, or manual penetration testing.",
    }

    return {
        "title": "SentinelScan Web Security Assessment Methodology",
        "version": "1.0",
        "checks": checks_documented,
        "severity_model": severity_rules,
        "operational_boundaries": boundaries,
    }
