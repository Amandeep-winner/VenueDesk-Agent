"""Structured logging setup with token and secret redaction."""
import json
import logging
import re
from typing import Any

TOKEN_PATTERN = re.compile(r"PAIR-[A-Za-z0-9_-]+")
HEX_KEY_PATTERN = re.compile(r"[0-9a-fA-F]{64}")


class RedactingFilter(logging.Filter):
    """Filter that redacts sensitive pairing tokens and raw keys from log records."""

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = self.redact(record.msg)
        if record.args:
            if isinstance(record.args, dict):
                record.args = {k: self.redact(v) if isinstance(v, str) else v for k, v in record.args.items()}
            elif isinstance(record.args, (list, tuple)):
                record.args = tuple(self.redact(v) if isinstance(v, str) else v for v in record.args)
        return True

    @classmethod
    def redact(cls, text: str) -> str:
        text = TOKEN_PATTERN.sub("PAIR-[REDACTED]", text)
        return text


class JsonFormatter(logging.Formatter):
    """Structured JSON formatter."""

    def format(self, record: logging.LogRecord) -> str:
        data: dict[str, Any] = {
            "timestamp": self.formatTime(record, self.datefmt),
            "level": record.levelname,
            "name": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            data["exception"] = self.formatException(record.exc_info)
        return json.dumps(data)


def setup_logging(log_level: str = "INFO", json_format: bool = False) -> None:
    """Configure root logging with redaction filter."""
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, log_level.upper(), logging.INFO))

    # Remove existing handlers to avoid duplicates
    for handler in list(root_logger.handlers):
        root_logger.removeHandler(handler)

    handler = logging.StreamHandler()
    if json_format:
        handler.setFormatter(JsonFormatter())
    else:
        handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s"))

    handler.addFilter(RedactingFilter())
    root_logger.addHandler(handler)
