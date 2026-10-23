"""
Pydantic Schemas for Scan Check Results
"""
from datetime import datetime

from pydantic import BaseModel, ConfigDict

from app.models.check_result import CheckStatus


class CheckResultResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    scan_id: str
    check_id: str
    check_name: str
    category: str
    status: CheckStatus
    duration_ms: float
    message: str
    error_detail: str | None = None
    executed_at: datetime
