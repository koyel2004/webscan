"""
Scan Check Result SQLAlchemy Model
Records execution outcome and timing for each individual security check.
"""
import enum
import uuid
from datetime import UTC, datetime

from sqlalchemy import Column, DateTime, Float, ForeignKey, String, Text
from sqlalchemy import Enum as SQLEnum
from sqlalchemy.orm import relationship

from app.database.session import Base


class CheckStatus(str, enum.Enum):
    PASSED = "PASSED"
    FINDINGS_DETECTED = "FINDINGS_DETECTED"
    INCONCLUSIVE = "INCONCLUSIVE"
    ERROR = "ERROR"
    SKIPPED = "SKIPPED"


class ScanCheckResult(Base):
    __tablename__ = "scan_check_results"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id = Column(String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    check_id = Column(String(64), nullable=False)
    check_name = Column(String(255), nullable=False)
    category = Column(String(50), nullable=False)
    status = Column(SQLEnum(CheckStatus), nullable=False, default=CheckStatus.PASSED)
    duration_ms = Column(Float, nullable=False, default=0.0)
    message = Column(Text, nullable=False)
    error_detail = Column(Text, nullable=True)
    executed_at = Column(DateTime, nullable=False, default=lambda: datetime.now(UTC))

    # Relationship
    scan = relationship("Scan", back_populates="check_results")
