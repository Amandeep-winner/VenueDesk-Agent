"""Logging filters for sensitive token and credential redaction."""
import logging
import re
from typing import Any

PAIR_TOKEN_PATTERN = re.compile(r"PAIR-[A-Za-z0-9_-]+")
X_SIGNATURE_PATTERN = re.compile(r"(?i)(?:X-Signature[:=]\s*['\"]?)([A-Za-z0-9+/=]{40,})['\"]?")
BASE64_LONG_BLOB = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")
SENSITIVE_KEY_PATTERN = re.compile(r"(?i)(token|key|secret|signature|password)")


class RedactingFilter(logging.Filter):
    """Filter that redacts pairing tokens, signatures, and secrets from log records."""

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = self.redact(record.msg)
        if record.args:
            if isinstance(record.args, dict):
                record.args = {k: self._redact_dict_entry(k, v) for k, v in record.args.items()}
            elif isinstance(record.args, (list, tuple)):
                record.args = tuple(self.redact(v) if isinstance(v, str) else v for v in record.args)
        return True

    @classmethod
    def redact(cls, text: str) -> str:
        text = PAIR_TOKEN_PATTERN.sub("PAIR-[REDACTED]", text)
        text = X_SIGNATURE_PATTERN.sub(r"X-Signature: [REDACTED]", text)
        return text

    @classmethod
    def _redact_dict_entry(cls, key: Any, val: Any) -> Any:
        key_str = str(key).lower()
        if SENSITIVE_KEY_PATTERN.search(key_str):
            if isinstance(val, str):
                if len(val) > 40 or PAIR_TOKEN_PATTERN.search(val) or BASE64_LONG_BLOB.search(val):
                    return "[REDACTED]"
            elif val is not None:
                return "[REDACTED]"
        if isinstance(val, str):
            return cls.redact(val)
        return val
