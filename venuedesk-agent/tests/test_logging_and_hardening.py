"""Tests for Phase 11: Logging redaction, security filters, and HTTPS enforcement."""
import logging

import pytest

from agent.communication.client import AuthenticatedClient
from agent.config import AgentConfig
from agent.logging_setup import RedactingFilter


def test_redacting_filter_sanitizes_message_and_args():
    """Test RedactingFilter strips pairing tokens and secrets from strings, tuples, and dicts."""
    log_filter = RedactingFilter()

    # 1. Plain string message
    record1 = logging.LogRecord(
        name="test",
        level=logging.INFO,
        pathname="test.py",
        lineno=10,
        msg="Enrolled with PAIR-1234567890abcdef and Bearer secret_pass_9999",
        args=(),
        exc_info=None,
    )
    log_filter.filter(record1)
    assert "PAIR-1234567890abcdef" not in record1.msg
    assert "PAIR-[REDACTED]" in record1.msg
    assert "secret_pass_9999" not in record1.msg
    assert "[REDACTED]" in record1.msg

    # 2. Formatted args (tuple)
    record2 = logging.LogRecord(
        name="test",
        level=logging.INFO,
        pathname="test.py",
        lineno=20,
        msg="Using token %s for endpoint %s",
        args=("PAIR-abcdef1234567890", "VD-DEVICE-01"),
        exc_info=None,
    )
    log_filter.filter(record2)
    assert record2.args[0] == "PAIR-[REDACTED]"
    assert record2.args[1] == "VD-DEVICE-01"

    # 3. Formatted args (dict)
    record3 = logging.LogRecord(
        name="test",
        level=logging.INFO,
        pathname="test.py",
        lineno=30,
        msg="Config payload",
        args={"token": "PAIR-token_in_dict_123", "password": "supersecretpassword1"},
        exc_info=None,
    )
    log_filter.filter(record3)
    assert record3.args["token"] == "PAIR-[REDACTED]"
    assert "supersecretpassword1" not in record3.args["password"]


def test_insecure_http_url_rejection(tmp_path):
    """Security check: Agent refuses plain http:// URLs unless allow_insecure_dev is true."""
    # 1. Insecure HTTP without override -> ValueError
    cfg_insecure = AgentConfig(
        server_url="http://control.venue.internal:5001",
        allow_insecure_dev=False,
        state_dir=str(tmp_path),
    )
    with pytest.raises(ValueError, match="Insecure HTTP server URLs are rejected"):
        AuthenticatedClient(cfg_insecure)

    # 2. Insecure HTTP with allow_insecure_dev = true -> Allowed
    cfg_dev = AgentConfig(
        server_url="http://127.0.0.1:5001",
        allow_insecure_dev=True,
        state_dir=str(tmp_path),
    )
    client_dev = AuthenticatedClient(cfg_dev)
    assert client_dev.server_url == "http://127.0.0.1:5001"

    # 3. Secure HTTPS -> Always allowed
    cfg_https = AgentConfig(
        server_url="https://control.venue.internal",
        allow_insecure_dev=False,
        state_dir=str(tmp_path),
    )
    client_https = AuthenticatedClient(cfg_https)
    assert client_https.server_url == "https://control.venue.internal"
