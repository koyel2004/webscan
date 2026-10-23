"""
Scanner Orchestrator
Coordinates target validation, bounded check execution, cancellation checks,
metric aggregation, and database persistence.
"""
import asyncio
import time
from datetime import UTC, datetime

from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.exceptions import (
    ScanCancelledError,
    SSRFSecurityViolation,
    TargetValidationError,
)
from app.core.logging import logger
from app.database.session import SessionLocal
from app.models.check_result import CheckStatus, ScanCheckResult
from app.models.finding import Finding, SeverityLevel
from app.models.scan import Scan, ScanStatus
from app.services.scanner.base import CheckOutcome, ScanContext
from app.services.scanner.checks import ALL_CHECKS
from app.services.scanner.explanation_engine import ExplanationEngine
from app.services.scanner.target_validator import (
    resolve_and_validate_hostname,
    validate_url_syntax,
)

# Concurrency limiter across simultaneous scans
SCAN_SEMAPHORE = asyncio.Semaphore(settings.MAX_CONCURRENT_SCANS)


class ScanOrchestrator:
    """Orchestrates execution of an authorized security scan."""

    @classmethod
    async def run_scan(cls, scan_id: str) -> None:
        """
        Main entrypoint executed asynchronously for a given scan record.
        """
        async with SCAN_SEMAPHORE:
            db: Session = SessionLocal()
            try:
                scan = db.query(Scan).filter(Scan.id == scan_id).first()
                if not scan:
                    logger.error(f"Scan {scan_id} not found in database.")
                    return

                if scan.status == ScanStatus.CANCELLED:
                    logger.info(f"Scan {scan_id} was cancelled before starting.")
                    return

                # Mark as RUNNING
                scan.status = ScanStatus.RUNNING
                scan.started_at = datetime.now(UTC)
                db.commit()

                # Step 1: Target Validation and SSRF Checks
                try:
                    norm_url, hostname, port, _ = validate_url_syntax(scan.target_url)
                    resolved_ips = resolve_and_validate_hostname(hostname)
                    scan.target_url = norm_url
                    scan.target_hostname = hostname
                    scan.target_ip = resolved_ips[0] if resolved_ips else None
                    db.commit()
                except (TargetValidationError, SSRFSecurityViolation) as e:
                    scan.status = ScanStatus.FAILED
                    scan.error_message = f"Security validation failed: {e!s}"
                    scan.completed_at = datetime.now(UTC)
                    db.commit()
                    logger.warning(f"Scan {scan_id} failed target validation: {e}")
                    return

                # Step 2: Build Scan Context
                context = ScanContext(
                    target_url=norm_url,
                    hostname=hostname,
                    port=port,
                    resolved_ips=resolved_ips,
                    timeout_seconds=scan.timeout_seconds
                )

                # Step 3: Run Checks
                start_clock = time.perf_counter()
                check_outcomes: list[CheckOutcome] = []

                for check in ALL_CHECKS:
                    # Check for cancellation between checks
                    db.refresh(scan)
                    if scan.status == ScanStatus.CANCELLED:
                        raise ScanCancelledError("Scan was cancelled by user.")

                    outcome = await check.execute(context)
                    check_outcomes.append(outcome)

                elapsed = round(time.perf_counter() - start_clock, 2)

                # Step 4: Persist Results and Findings
                cls._persist_results(db, scan, check_outcomes, elapsed)

            except ScanCancelledError:
                logger.info(f"Scan {scan_id} execution aborted due to cancellation.")
                if scan:
                    scan.status = ScanStatus.CANCELLED
                    scan.completed_at = datetime.now(UTC)
                    db.commit()
            except Exception as e:
                logger.exception(f"Unexpected error in scan orchestrator for scan {scan_id}: {e}")
                if scan:
                    scan.status = ScanStatus.FAILED
                    scan.error_message = f"Scan failed due to runtime error: {e!s}"
                    scan.completed_at = datetime.now(UTC)
                    db.commit()
            finally:
                db.close()

    @classmethod
    def _persist_results(
        cls,
        db: Session,
        scan: Scan,
        outcomes: list[CheckOutcome],
        duration_seconds: float
    ) -> None:
        """Processes check outcomes and saves check results and findings."""
        scan.completed_at = datetime.now(UTC)
        scan.duration_seconds = duration_seconds
        scan.total_checks = len(outcomes)

        passed = 0
        failed = 0
        inconclusive = 0

        crit_count = 0
        high_count = 0
        med_count = 0
        low_count = 0
        info_count = 0
        all_findings: list[Finding] = []

        for outcome in outcomes:
            # Check Result Record
            cr = ScanCheckResult(
                scan_id=scan.id,
                check_id=outcome.check_id,
                check_name=outcome.check_name,
                category=outcome.category,
                status=outcome.status,
                duration_ms=outcome.duration_ms,
                message=outcome.message,
                error_detail=outcome.error_detail,
                executed_at=datetime.now(UTC)
            )
            db.add(cr)

            if outcome.status == CheckStatus.PASSED:
                passed += 1
            elif outcome.status == CheckStatus.FINDINGS_DETECTED:
                failed += 1
            elif outcome.status in (CheckStatus.INCONCLUSIVE, CheckStatus.ERROR):
                inconclusive += 1

            # Process Findings
            for f_data in outcome.findings:
                # Enhance with explanation engine
                enhanced = ExplanationEngine.enhance_finding(
                    check_id=f_data.check_id,
                    title=f_data.title,
                    category=f_data.category,
                    severity=f_data.severity,
                    observed_evidence=f_data.evidence,
                    hostname=scan.target_hostname
                )

                # Format remediation with verification steps
                full_remediation = f"{f_data.remediation}\n\nVerification:\n{enhanced['verification_steps']}"

                finding = Finding(
                    scan_id=scan.id,
                    check_id=f_data.check_id,
                    title=f_data.title,
                    category=f_data.category,
                    severity=f_data.severity,
                    confidence=f_data.confidence,
                    hostname=scan.target_hostname,
                    summary=f_data.summary,
                    evidence=f_data.evidence,
                    impact=f_data.impact,
                    remediation=full_remediation,
                    references=f_data.references,
                    cwe_id=f_data.cwe_id,
                )
                db.add(finding)
                all_findings.append(finding)

                # Counters
                if f_data.severity == SeverityLevel.CRITICAL:
                    crit_count += 1
                elif f_data.severity == SeverityLevel.HIGH:
                    high_count += 1
                elif f_data.severity == SeverityLevel.MEDIUM:
                    med_count += 1
                elif f_data.severity == SeverityLevel.LOW:
                    low_count += 1
                elif f_data.severity == SeverityLevel.INFORMATIONAL:
                    info_count += 1

        scan.passed_checks = passed
        scan.failed_checks = failed
        scan.inconclusive_checks = inconclusive

        scan.total_findings = len(all_findings)
        scan.critical_count = crit_count
        scan.high_count = high_count
        scan.medium_count = med_count
        scan.low_count = low_count
        scan.info_count = info_count

        scan.status = ScanStatus.COMPLETED
        db.commit()
        logger.info(f"Scan {scan.id} completed in {duration_seconds}s with {len(all_findings)} findings.")
