"""
Pydantic Schemas for Report Metadata
"""
from datetime import datetime

from pydantic import BaseModel, ConfigDict

from app.models.report import ReportType


class ReportMetadataResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    scan_id: str
    report_type: ReportType
    file_path: str | None = None
    file_size_bytes: int
    sha256_hash: str | None = None
    generated_at: datetime
