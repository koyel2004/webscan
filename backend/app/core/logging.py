"""
SentinelScan Structured Logging with Sensitive Data Redaction
"""
import logging
import re
import sys
from typing import Any

# Regex patterns to scrub sensitive data from log records
REDACT_PATTERNS = [
    (re.compile(r'(cookie:\s*)[^\r\n;]+', re.IGNORECASE), r'\1[REDACTED]'),
    (re.compile(r'(set-cookie:\s*[^=]+=)[^\r\n;]+', re.IGNORECASE), r'\1[REDACTED]'),
    (re.compile(r'(authorization:\s*(?:bearer|basic)\s+)[^\r\n]+', re.IGNORECASE), r'\1[REDACTED]'),
    (re.compile(r'((?:api[_-]?key|secret|password|token)\s*[:=]\s*["\']?)[^"\'\s&]+(["\']?)', re.IGNORECASE), r'\1[REDACTED]\2'),
]


class SensitiveDataFilter(logging.Filter):
    """Filter that scrubs credentials, cookie values, and secrets from log messages."""

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = self.scrub(record.msg)
        if record.args:
            if isinstance(record.args, dict):
                record.args = {k: self.scrub_val(v) for k, v in record.args.items()}
            elif isinstance(record.args, tuple):
                record.args = tuple(self.scrub_val(a) for a in record.args)
        return True

    @staticmethod
    def scrub(text: str) -> str:
        for pattern, replacement in REDACT_PATTERNS:
            text = pattern.sub(replacement, text)
        return text

    @classmethod
    def scrub_val(cls, val: Any) -> Any:
        if isinstance(val, str):
            return cls.scrub(val)
        return val


def setup_logging(debug: bool = False) -> logging.Logger:
    """Configures structured, redacted logging for the application."""
    log_level = logging.DEBUG if debug else logging.INFO
    logger = logging.getLogger("sentinelscan")
    logger.setLevel(log_level)

    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setLevel(log_level)
        formatter = logging.Formatter(
            fmt="%(asctime)s [%(levelname)s] [%(name)s.%(module)s]: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )
        handler.setFormatter(formatter)
        handler.addFilter(SensitiveDataFilter())
        logger.addHandler(handler)

    return logger


logger = setup_logging()
