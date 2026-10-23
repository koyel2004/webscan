"""
Finding SQLAlchemy Model
"""
import enum
import uuid
from datetime import UTC, datetime

from sqlalchemy import Column, DateTime, ForeignKey, String, Text
from sqlalchemy import Enum as SQLEnum
from sqlalchemy.orm import relationship

from app.database.session import Base


class SeverityLevel(str, enum.Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"


class ConfidenceLevel(str, enum.Enum):
    CERTAIN = "CERTAIN"
    FIRM = "FIRM"
    TENTATIVE = "TENTATIVE"


class FindingStatus(str, enum.Enum):
    DETECTED = "DETECTED"
    VERIFIED = "VERIFIED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    RESOLVED = "RESOLVED"


class Finding(Base):
    __tablename__ = "findings"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id = Column(String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    check_id = Column(String(64), nullable=False, index=True)
    title = Column(String(255), nullable=False)
    category = Column(String(50), nullable=False, index=True)
    severity = Column(SQLEnum(SeverityLevel), nullable=False, default=SeverityLevel.INFORMATIONAL, index=True)
    confidence = Column(SQLEnum(ConfidenceLevel), nullable=False, default=ConfidenceLevel.FIRM)
    status = Column(SQLEnum(FindingStatus), nullable=False, default=FindingStatus.DETECTED)
    hostname = Column(String(255), nullable=False, index=True)

    summary = Column(Text, nullable=False)
    evidence = Column(Text, nullable=True)  # JSON or redacted text representation
    impact = Column(Text, nullable=False)
    remediation = Column(Text, nullable=False)
    references = Column(Text, nullable=True)  # JSON array or newline-separated URLs
    cwe_id = Column(String(32), nullable=True)

    first_observed_at = Column(DateTime, nullable=False, default=lambda: datetime.now(UTC))
    created_at = Column(DateTime, nullable=False, default=lambda: datetime.now(UTC))

    # Relationships
    scan = relationship("Scan", back_populates="findings")
