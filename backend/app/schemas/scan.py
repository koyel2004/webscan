"""
Pydantic Schemas for Scans
"""
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from app.models.scan import ScanStatus
from app.schemas.check_result import CheckResultResponse
from app.schemas.finding import FindingResponse


class ScanCreateRequest(BaseModel):
    target_url: str = Field(..., description="Target website URL (e.g. https://example.com)")
    user_authorized: bool = Field(
        ...,
        description="Explicit confirmation that user is authorized to assess the target system."
    )
    profile: str = Field(default="safe_default", description="Scan profile (safe_default, passive_strict)")
    timeout_seconds: float = Field(default=10.0, ge=1.0, le=30.0, description="Per-request timeout in seconds")


class ScanResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    target_url: str
    target_hostname: str
    target_ip: str | None = None
    status: ScanStatus
    profile: str
    timeout_seconds: float
    user_authorized: bool

    created_at: datetime
    started_at: datetime | None = None
    completed_at: datetime | None = None
    duration_seconds: float | None = None

    total_checks: int
    passed_checks: int
    failed_checks: int
    inconclusive_checks: int

    total_findings: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    info_count: int

    error_message: str | None = None


class ScanDetailResponse(ScanResponse):
    findings: list[FindingResponse] = []
    check_results: list[CheckResultResponse] = []


class ScanListResponse(BaseModel):
    items: list[ScanResponse]
    total: int
    page: int
    limit: int
    total_pages: int
