"""
Reports API Router
Generates and serves downloadable PDF and structured JSON reports.
"""
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import JSONResponse, Response
from sqlalchemy.orm import Session

from app.core.logging import logger
from app.database.session import get_db
from app.models.scan import Scan
from app.reports.json_generator import JSONReportGenerator
from app.reports.pdf_generator import PDFReportGenerator

router = APIRouter(tags=["Reports"])


def _serve_pdf(scan_id: str, db: Session) -> Response:
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found.")

    try:
        pdf_bytes = PDFReportGenerator.generate_pdf(scan)
        filename = f"SentinelScan_Report_{scan.target_hostname}_{scan.id[:8]}.pdf"
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'}
        )
    except Exception as e:
        logger.exception(f"Error generating PDF report for scan {scan_id}: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"PDF generation failed: {e}")


def _serve_json(scan_id: str, db: Session) -> JSONResponse:
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found.")

    try:
        report_data = JSONReportGenerator.generate(scan)
        return JSONResponse(
            content=report_data,
            headers={
                "Content-Disposition": f'attachment; filename="SentinelScan_Report_{scan.target_hostname}_{scan.id[:8]}.json"'
            }
        )
    except Exception as e:
        logger.exception(f"Error generating JSON report for scan {scan_id}: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"JSON generation failed: {e}")


@router.get("/scans/{scan_id}/report.pdf")
@router.get("/scans/{scan_id}/pdf")
@router.get("/reports/{scan_id}/pdf")
def download_pdf_report(scan_id: str, db: Session = Depends(get_db)):
    """Generates and serves a formatted PDF assessment report."""
    return _serve_pdf(scan_id, db)


@router.get("/scans/{scan_id}/report.json")
@router.get("/scans/{scan_id}/json")
@router.get("/reports/{scan_id}/json")
def download_json_report(scan_id: str, db: Session = Depends(get_db)):
    """Generates and serves a structured JSON assessment report."""
    return _serve_json(scan_id, db)
