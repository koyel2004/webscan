"""
Findings API Router
Provides cross-scan search, filtering, and detail endpoints for security findings.
"""

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import desc, or_
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.models.finding import Finding, SeverityLevel
from app.schemas.finding import FindingListResponse, FindingResponse

router = APIRouter(prefix="/findings", tags=["Findings"])


@router.get("", response_model=FindingListResponse)
def list_findings(
    page: int = Query(1, ge=1),
    limit: int = Query(10, ge=1, le=100),
    search: str | None = Query(None, description="Search by title, summary, or CWE ID"),
    severity: SeverityLevel | None = Query(None, description="Filter by severity level"),
    category: str | None = Query(None, description="Filter by check category"),
    hostname: str | None = Query(None, description="Filter by target hostname"),
    scan_id: str | None = Query(None, description="Filter by specific scan ID"),
    db: Session = Depends(get_db)
):
    """Retrieves paginated findings with search and multi-attribute filters."""
    query = db.query(Finding)

    if scan_id:
        query = query.filter(Finding.scan_id == scan_id)
    if severity:
        query = query.filter(Finding.severity == severity)
    if category:
        query = query.filter(Finding.category == category)
    if hostname:
        query = query.filter(Finding.hostname.ilike(f"%{hostname}%"))
    if search:
        search_filter = or_(
            Finding.title.ilike(f"%{search}%"),
            Finding.summary.ilike(f"%{search}%"),
            Finding.cwe_id.ilike(f"%{search}%")
        )
        query = query.filter(search_filter)

    total = query.count()
    total_pages = max(1, (total + limit - 1) // limit)
    offset = (page - 1) * limit

    items = query.order_by(desc(Finding.created_at)).offset(offset).limit(limit).all()

    return FindingListResponse(
        items=items,
        total=total,
        page=page,
        limit=limit,
        total_pages=total_pages
    )


@router.get("/{finding_id}", response_model=FindingResponse)
def get_finding(finding_id: str, db: Session = Depends(get_db)):
    """Retrieves detailed information, evidence, and remediation for a specific finding."""
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found.")
    return finding
