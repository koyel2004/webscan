"""
Dashboard Analytics API Router
Provides aggregated security metrics, severity breakdown, trend analytics, and seed trigger.
"""
from typing import Any

from fastapi import APIRouter, Depends, status
from sqlalchemy import desc, func
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.models.finding import Finding, SeverityLevel
from app.models.scan import Scan, ScanStatus
from app.schemas.dashboard import DashboardSummaryResponse
from app.schemas.scan import ScanResponse
from app.services.seed_data import seed_demo_data

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])


@router.get("/summary", response_model=DashboardSummaryResponse)
def get_dashboard_summary(db: Session = Depends(get_db)):
    """Computes comprehensive dashboard metrics from active database records."""
    total_scans = db.query(Scan).count()
    completed_scans = db.query(Scan).filter(Scan.status == ScanStatus.COMPLETED).count()

    total_findings = db.query(Finding).count()
    crit_count = db.query(Finding).filter(Finding.severity == SeverityLevel.CRITICAL).count()
    high_count = db.query(Finding).filter(Finding.severity == SeverityLevel.HIGH).count()
    med_count = db.query(Finding).filter(Finding.severity == SeverityLevel.MEDIUM).count()
    low_count = db.query(Finding).filter(Finding.severity == SeverityLevel.LOW).count()
    info_count = db.query(Finding).filter(Finding.severity == SeverityLevel.INFORMATIONAL).count()

    severity_dist: dict[str, int] = {
        "CRITICAL": crit_count,
        "HIGH": high_count,
        "MEDIUM": med_count,
        "LOW": low_count,
        "INFORMATIONAL": info_count,
    }

    # Category distribution
    cat_counts = (
        db.query(Finding.category, func.count(Finding.id))
        .group_by(Finding.category)
        .all()
    )
    category_dist: dict[str, int] = {cat: count for cat, count in cat_counts}

    # Recent scans (up to 5)
    recent_scans_db = (
        db.query(Scan)
        .order_by(desc(Scan.created_at))
        .limit(5)
        .all()
    )
    recent_scans = [ScanResponse.model_validate(s) for s in recent_scans_db]

    # Common misconfigurations (top 6 by occurrence)
    top_findings = (
        db.query(Finding.title, Finding.severity, Finding.category, func.count(Finding.id).label("occurrence_count"))
        .group_by(Finding.title, Finding.severity, Finding.category)
        .order_by(desc("occurrence_count"))
        .limit(6)
        .all()
    )
    common_misconfigs: list[dict[str, Any]] = [
        {
            "title": item[0],
            "severity": item[1].value if hasattr(item[1], "value") else str(item[1]),
            "category": item[2],
            "count": item[3],
        }
        for item in top_findings
    ]

    # Historical trends (from completed scans)
    completed_scans_db = (
        db.query(Scan)
        .filter(Scan.status == ScanStatus.COMPLETED)
        .order_by(Scan.created_at.asc())
        .limit(10)
        .all()
    )
    trends: list[dict[str, Any]] = [
        {
            "date": s.created_at.strftime("%b %d, %H:%M") if s.created_at else "N/A",
            "hostname": s.target_hostname,
            "critical": s.critical_count,
            "high": s.high_count,
            "medium": s.medium_count,
            "low": s.low_count,
            "informational": s.info_count,
            "total": s.total_findings,
        }
        for s in completed_scans_db
    ]

    return DashboardSummaryResponse(
        total_scans=total_scans,
        completed_scans=completed_scans,
        total_findings=total_findings,
        critical_findings=crit_count,
        high_findings=high_count,
        medium_findings=med_count,
        low_findings=low_count,
        info_findings=info_count,
        severity_distribution=severity_dist,
        category_distribution=category_dist,
        recent_scans=recent_scans,
        common_misconfigurations=common_misconfigs,
        historical_trends=trends,
    )


@router.post("/seed", status_code=status.HTTP_201_CREATED)
@router.post("/seed-demo", status_code=status.HTTP_201_CREATED)
def trigger_seed_demo_data(db: Session = Depends(get_db)):
    """Inserts mock scans and realistic security findings for demonstration."""
    count = seed_demo_data(db)
    return {"message": f"Successfully seeded {count} demo scans with security findings."}
