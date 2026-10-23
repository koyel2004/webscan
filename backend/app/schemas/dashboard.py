"""
Pydantic Schemas for Dashboard and Analytics
"""
from typing import Any

from pydantic import BaseModel

from app.schemas.scan import ScanResponse


class DashboardSummaryResponse(BaseModel):
    total_scans: int
    completed_scans: int
    total_findings: int
    critical_findings: int
    high_findings: int
    medium_findings: int
    low_findings: int
    info_findings: int

    severity_distribution: dict[str, int]
    category_distribution: dict[str, int]
    recent_scans: list[ScanResponse]
    common_misconfigurations: list[dict[str, Any]]
    historical_trends: list[dict[str, Any]]
