"""
Scan SQLAlchemy Model
"""
import enum
import uuid
from datetime import UTC, datetime

from sqlalchemy import Boolean, Column, DateTime, Float, Integer, String, Text
from sqlalchemy import Enum as SQLEnum
from sqlalchemy.orm import relationship

from app.database.session import Base


class ScanStatus(str, enum.Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class Scan(Base):
    __tablename__ = "scans"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    target_url = Column(String(2048), nullable=False)
    target_hostname = Column(String(255), nullable=False, index=True)
    target_ip = Column(String(45), nullable=True)  # IPv4 or IPv6
    status = Column(SQLEnum(ScanStatus), nullable=False, default=ScanStatus.PENDING, index=True)
    profile = Column(String(50), nullable=False, default="safe_default")
    timeout_seconds = Column(Float, nullable=False, default=10.0)
    user_authorized = Column(Boolean, nullable=False, default=True)

    # Timestamps
    created_at = Column(DateTime, nullable=False, default=lambda: datetime.now(UTC))
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    duration_seconds = Column(Float, nullable=True)

    # Check metrics
    total_checks = Column(Integer, nullable=False, default=0)
    passed_checks = Column(Integer, nullable=False, default=0)
    failed_checks = Column(Integer, nullable=False, default=0)
    inconclusive_checks = Column(Integer, nullable=False, default=0)

    # Finding severities
    total_findings = Column(Integer, nullable=False, default=0)
    critical_count = Column(Integer, nullable=False, default=0)
    high_count = Column(Integer, nullable=False, default=0)
    medium_count = Column(Integer, nullable=False, default=0)
    low_count = Column(Integer, nullable=False, default=0)
    info_count = Column(Integer, nullable=False, default=0)

    # Errors & notes
    error_message = Column(Text, nullable=True)

    # Relationships
    findings = relationship(
        "Finding",
        back_populates="scan",
        cascade="all, delete-orphan",
        order_by="Finding.created_at.desc()"
    )
    check_results = relationship(
        "ScanCheckResult",
        back_populates="scan",
        cascade="all, delete-orphan",
        order_by="ScanCheckResult.executed_at.asc()"
    )
    reports = relationship(
        "ReportMetadata",
        back_populates="scan",
        cascade="all, delete-orphan"
    )
