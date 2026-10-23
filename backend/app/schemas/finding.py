"""
Pydantic Schemas for Findings
"""
from datetime import datetime

from pydantic import BaseModel, ConfigDict

from app.models.finding import ConfidenceLevel, FindingStatus, SeverityLevel


class FindingResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    scan_id: str
    check_id: str
    title: str
    category: str
    severity: SeverityLevel
    confidence: ConfidenceLevel
    status: FindingStatus
    hostname: str
    summary: str
    evidence: str | None = None
    impact: str
    remediation: str
    references: str | None = None
    cwe_id: str | None = None
    first_observed_at: datetime
    created_at: datetime


class FindingListResponse(BaseModel):
    items: list[FindingResponse]
    total: int
    page: int
    limit: int
    total_pages: int
