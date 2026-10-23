"""
Base Interfaces and Data Structures for Security Checks
"""
import abc
import time
from typing import Any

from pydantic import BaseModel

from app.models.check_result import CheckStatus
from app.models.finding import ConfidenceLevel, SeverityLevel
from app.services.scanner.safe_client import SafeClient, SafeHTTPResponse


class FindingData(BaseModel):
    check_id: str
    title: str
    category: str
    severity: SeverityLevel
    confidence: ConfidenceLevel
    summary: str
    evidence: str
    impact: str
    remediation: str
    references: str
    cwe_id: str | None = None


class CheckOutcome(BaseModel):
    check_id: str
    check_name: str
    category: str
    status: CheckStatus
    duration_ms: float
    message: str
    error_detail: str | None = None
    findings: list[FindingData] = []


class ScanContext:
    """Holds target metadata, safe HTTP client, and cached responses."""

    def __init__(
        self,
        target_url: str,
        hostname: str,
        port: int,
        resolved_ips: list[str],
        timeout_seconds: float = 10.0
    ):
        self.target_url = target_url
        self.hostname = hostname
        self.port = port
        self.resolved_ips = resolved_ips
        self.timeout_seconds = timeout_seconds
        self.client = SafeClient(timeout_seconds=timeout_seconds)

        # Cached responses
        self.https_response: SafeHTTPResponse | None = None
        self.http_response: SafeHTTPResponse | None = None
        self.tls_info: dict[str, Any] | None = None
        self.cors_response: SafeHTTPResponse | None = None


class BaseSecurityCheck(abc.ABC):
    """Abstract base class for all modular security audit checks."""

    check_id: str = "BASE_CHECK"
    check_name: str = "Base Security Check"
    category: str = "general"
    description: str = ""

    async def execute(self, context: ScanContext) -> CheckOutcome:
        """Executes the check with timing and failure isolation."""
        start_time = time.perf_counter()
        try:
            outcome = await self.run(context)
            outcome.duration_ms = round((time.perf_counter() - start_time) * 1000, 2)
            return outcome
        except Exception as e:
            duration = round((time.perf_counter() - start_time) * 1000, 2)
            return CheckOutcome(
                check_id=self.check_id,
                check_name=self.check_name,
                category=self.category,
                status=CheckStatus.ERROR,
                duration_ms=duration,
                message=f"Check encountered unexpected runtime error: {e!s}",
                error_detail=str(e),
                findings=[]
            )

    @abc.abstractmethod
    async def run(self, context: ScanContext) -> CheckOutcome:
        """Check-specific evaluation logic."""
