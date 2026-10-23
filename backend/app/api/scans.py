"""
Scans API Router
Handles scan creation, execution lifecycle, cancellation, status polling, and deletion.
"""
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, status
from sqlalchemy import desc
from sqlalchemy.orm import Session

from app.core.exceptions import SSRFSecurityViolation, TargetValidationError
from app.core.logging import logger
from app.database.session import get_db
from app.models.scan import Scan, ScanStatus
from app.schemas.finding import FindingResponse
from app.schemas.scan import (
    ScanCreateRequest,
    ScanDetailResponse,
    ScanListResponse,
    ScanResponse,
)
from app.services.scanner.orchestrator import ScanOrchestrator
from app.services.scanner.target_validator import (
    resolve_and_validate_hostname,
    validate_url_syntax,
)

router = APIRouter(prefix="/scans", tags=["Scans"])


@router.post("", response_model=ScanResponse, status_code=status.HTTP_201_CREATED)
def create_scan(
    request: ScanCreateRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    """
    Submits a new target website URL for security assessment.
    Performs immediate pre-flight syntax and SSRF checks before queueing.
    """
    if not request.user_authorized:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Explicit user authorization is required to initiate an assessment."
        )

    # Pre-flight URL and SSRF validation
    try:
        norm_url, hostname, port, _ = validate_url_syntax(request.target_url)
        resolved_ips = resolve_and_validate_hostname(hostname)
    except (TargetValidationError, SSRFSecurityViolation) as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Target validation failed: {e}")

    # Create scan record
    new_scan = Scan(
        target_url=norm_url,
        target_hostname=hostname,
        target_ip=resolved_ips[0] if resolved_ips else None,
        status=ScanStatus.PENDING,
        profile=request.profile,
        timeout_seconds=request.timeout_seconds,
        user_authorized=request.user_authorized,
    )
    db.add(new_scan)
    db.commit()
    db.refresh(new_scan)

    # Queue asynchronous execution
    background_tasks.add_task(ScanOrchestrator.run_scan, new_scan.id)
    logger.info(f"Created scan {new_scan.id} for target {hostname}")

    return new_scan


@router.get("", response_model=ScanListResponse)
def list_scans(
    page: int = Query(1, ge=1),
    limit: int = Query(10, ge=1, le=100),
    status_filter: ScanStatus | None = Query(None, alias="status"),
    hostname: str | None = Query(None),
    db: Session = Depends(get_db)
):
    """Retrieves paginated scan history."""
    query = db.query(Scan)

    if status_filter:
        query = query.filter(Scan.status == status_filter)
    if hostname:
        query = query.filter(Scan.target_hostname.ilike(f"%{hostname}%"))

    total = query.count()
    total_pages = max(1, (total + limit - 1) // limit)
    offset = (page - 1) * limit

    items = query.order_by(desc(Scan.created_at)).offset(offset).limit(limit).all()

    return ScanListResponse(
        items=items,
        total=total,
        page=page,
        limit=limit,
        total_pages=total_pages
    )


@router.get("/{scan_id}", response_model=ScanDetailResponse)
def get_scan(scan_id: str, db: Session = Depends(get_db)):
    """Retrieves detailed scan execution status, check results, and findings."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found.")
    return scan


@router.get("/{scan_id}/findings", response_model=list[FindingResponse])
def get_scan_findings(scan_id: str, db: Session = Depends(get_db)):
    """Retrieves all findings discovered in a specific scan."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found.")
    return scan.findings


@router.post("/{scan_id}/cancel", response_model=ScanResponse)
def cancel_scan(scan_id: str, db: Session = Depends(get_db)):
    """Cancels a pending or active scan."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found.")

    if scan.status in (ScanStatus.COMPLETED, ScanStatus.FAILED, ScanStatus.CANCELLED):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Scan cannot be cancelled because it is already in state {scan.status}."
        )

    scan.status = ScanStatus.CANCELLED
    db.commit()
    db.refresh(scan)
    logger.info(f"Scan {scan_id} was requested to cancel.")
    return scan


@router.delete("/{scan_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_scan(scan_id: str, db: Session = Depends(get_db)):
    """Deletes a historical scan record and all cascaded findings and check results."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found.")

    db.delete(scan)
    db.commit()
    logger.info(f"Scan {scan_id} deleted successfully.")
