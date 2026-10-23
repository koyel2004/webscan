"""
JSON Report Generator for SentinelScan
Exports complete scan results, metrics, check outcomes, and findings as structured JSON.
"""
from datetime import UTC, datetime
from typing import Any

from app.models.scan import Scan


class JSONReportGenerator:
    """Generates standardized, schema-compliant JSON reports from database scan records."""

    @classmethod
    def generate(cls, scan: Scan) -> dict[str, Any]:
        """Builds sanitized JSON security report dictionary."""
        report_data: dict[str, Any] = {
            "report_version": "1.0",
            "platform": "SentinelScan Web Security Assessment Platform",
            "generated_at": datetime.now(UTC).isoformat(),
            "disclaimer": (
                "SentinelScan performs automated defensive web security audits and configuration checks. "
                "This report does not guarantee absolute security and is not a substitute for manual penetration "
                "testing or comprehensive source code reviews."
            ),
            "scan_metadata": {
                "scan_id": scan.id,
                "target_url": scan.target_url,
                "target_hostname": scan.target_hostname,
                "target_ip": scan.target_ip,
                "status": scan.status.value if hasattr(scan.status, "value") else str(scan.status),
                "profile": scan.profile,
                "user_authorized": scan.user_authorized,
                "timeout_seconds": scan.timeout_seconds,
                "created_at": scan.created_at.isoformat() if scan.created_at else None,
                "started_at": scan.started_at.isoformat() if scan.started_at else None,
                "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
                "duration_seconds": scan.duration_seconds,
                "error_message": scan.error_message,
            },
            "executive_summary": {
                "total_checks": scan.total_checks,
                "passed_checks": scan.passed_checks,
                "failed_checks": scan.failed_checks,
                "inconclusive_checks": scan.inconclusive_checks,
                "total_findings": scan.total_findings,
                "severity_breakdown": {
                    "critical": scan.critical_count,
                    "high": scan.high_count,
                    "medium": scan.medium_count,
                    "low": scan.low_count,
                    "informational": scan.info_count,
                },
                "security_grade": cls._compute_grade(scan),
            },
            "check_results": [
                {
                    "check_id": cr.check_id,
                    "check_name": cr.check_name,
                    "category": cr.category,
                    "status": cr.status.value if hasattr(cr.status, "value") else str(cr.status),
                    "duration_ms": cr.duration_ms,
                    "message": cr.message,
                    "error_detail": cr.error_detail,
                }
                for cr in scan.check_results
            ],
            "findings": [
                {
                    "finding_id": f.id,
                    "check_id": f.check_id,
                    "title": f.title,
                    "category": f.category,
                    "severity": f.severity.value if hasattr(f.severity, "value") else str(f.severity),
                    "confidence": f.confidence.value if hasattr(f.confidence, "value") else str(f.confidence),
                    "status": f.status.value if hasattr(f.status, "value") else str(f.status),
                    "hostname": f.hostname,
                    "summary": f.summary,
                    "evidence": f.evidence,
                    "impact": f.impact,
                    "remediation": f.remediation,
                    "references": f.references.split("\n") if f.references else [],
                    "cwe_id": f.cwe_id,
                    "created_at": f.created_at.isoformat() if f.created_at else None,
                }
                for f in scan.findings
            ],
        }
        return report_data

    @classmethod
    def _compute_grade(cls, scan: Scan) -> str:
        if scan.critical_count > 0:
            return "F"
        if scan.high_count > 2:
            return "D"
        if scan.high_count > 0 or scan.medium_count > 3:
            return "C"
        if scan.medium_count > 0 or scan.low_count > 2:
            return "B"
        return "A"
