"""
Custom Application Exceptions for SentinelScan
"""
from typing import Any


class SentinelScanException(Exception):
    """Base exception for all SentinelScan errors."""
    def __init__(self, message: str, details: dict[str, Any] | None = None):
        super().__init__(message)
        self.message = message
        self.details = details or {}


class TargetValidationError(SentinelScanException):
    """Raised when a target URL fails schema, syntax, or scope validation."""


class SSRFSecurityViolation(SentinelScanException):
    """Raised when a target URL or resolved IP attempts SSRF / private IP access."""


class ScanExecutionError(SentinelScanException):
    """Raised when an error interrupts scan orchestration."""


class ScanNotFoundError(SentinelScanException):
    """Raised when a requested scan ID does not exist."""


class FindingNotFoundError(SentinelScanException):
    """Raised when a requested finding ID does not exist."""


class ScanCancelledError(SentinelScanException):
    """Raised when a scan was cancelled by user request."""


class ReportGenerationError(SentinelScanException):
    """Raised when PDF or JSON report generation fails."""
