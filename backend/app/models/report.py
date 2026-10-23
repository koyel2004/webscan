"""
Report Metadata SQLAlchemy Model
"""
import enum
import uuid
from datetime import UTC, datetime

from sqlalchemy import Column, DateTime, ForeignKey, Integer, String
from sqlalchemy import Enum as SQLEnum
from sqlalchemy.orm import relationship

from app.database.session import Base


class ReportType(str, enum.Enum):
    PDF = "PDF"
    JSON = "JSON"


class ReportMetadata(Base):
    __tablename__ = "report_metadata"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id = Column(String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    report_type = Column(SQLEnum(ReportType), nullable=False)
    file_path = Column(String(512), nullable=True)
    file_size_bytes = Column(Integer, nullable=False, default=0)
    sha256_hash = Column(String(64), nullable=True)
    generated_at = Column(DateTime, nullable=False, default=lambda: datetime.now(UTC))

    # Relationship
    scan = relationship("Scan", back_populates="reports")
