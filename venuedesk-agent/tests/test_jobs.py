"""Unit and integration tests for agent remote job handlers, execution, and security."""
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from agent.config import AgentConfig
from agent.jobs.executor import JobExecutor
from agent.jobs.handlers import (
    ALLOWLISTED_JOB_TYPES,
    execute_collect_diagnostics,
    execute_collect_logs,
    execute_refresh_configuration,
    execute_refresh_inventory,
    execute_restart_approved_service,
    execute_run_network_diagnostic,
    redact_sensitive_text,
)
from agent.jobs.scheduler import JobPoller


def test_agent_source_tree_contains_zero_shell_equals_true():
    """Security Invariant: The agent source code MUST NEVER contain shell=True anywhere."""
    agent_src_dir = Path(__file__).resolve().parent.parent / "agent"
    assert agent_src_dir.is_dir()

    violating_files = []
    for py_file in agent_src_dir.rglob("*.py"):
        content = py_file.read_text(encoding="utf-8", errors="replace")
        if "shell=True" in content or "shell = True" in content:
            violating_files.append(str(py_file.relative_to(agent_src_dir)))

    assert not violating_files, f"Security violation: Found shell=True in agent source files: {violating_files}"


def test_token_and_secret_redaction():
    """Test pairing tokens and secret credentials are automatically redacted."""
    raw = (
        "Agent enrolled with token PAIR-abcd1234efgh5678ijkl90 and "
        "Authorization: Bearer secret_api_token_12345678"
    )
    sanitized = redact_sensitive_text(raw)
    assert "PAIR-abcd1234efgh5678ijkl90" not in sanitized
    assert "PAIR-[REDACTED]" in sanitized
    assert "secret_api_token_12345678" not in sanitized
    assert "[REDACTED]" in sanitized


def test_allowlisted_job_types_set():
    """Verify standard allowlisted job types match specification."""
    expected = {
        "REFRESH_INVENTORY",
        "COLLECT_DIAGNOSTICS",
        "COLLECT_LOGS",
        "RESTART_APPROVED_SERVICE",
        "REFRESH_CONFIGURATION",
        "RUN_NETWORK_DIAGNOSTIC",
    }
    assert ALLOWLISTED_JOB_TYPES == expected


def test_refresh_inventory_and_config(tmp_path):
    """Test inventory gathering and configuration refresh handlers."""
    cfg = AgentConfig(state_dir=str(tmp_path))
    inv = execute_refresh_inventory({}, cfg)
    assert "hostname" in inv
    assert "cpu_model" in inv

    reloaded = execute_refresh_configuration({}, cfg)
    assert reloaded["heartbeat_seconds"] == cfg.heartbeat_seconds


def test_collect_diagnostics_allowlist_validation(tmp_path):
    """Test COLLECT_DIAGNOSTICS accepts allowlisted targets and rejects unallowlisted."""
    cfg = AgentConfig(state_dir=str(tmp_path))

    # Allowed targets
    for target in ["system", "network", "storage", "agent", "all"]:
        res = execute_collect_diagnostics({"target": target}, cfg)
        assert res["target"] == target
        assert "platform" in res

    # Unallowlisted target
    with pytest.raises(ValueError, match="is not allowlisted"):
        execute_collect_diagnostics({"target": "arbitrary_kernel_dump"}, cfg)


def test_collect_logs_redaction_and_size_cap(tmp_path):
    """Test COLLECT_LOGS redacts tokens and observes max size cap."""
    log_file = tmp_path / "agent.log"
    log_file.write_text(
        "Line 1\nToken PAIR-xyz9876543210used here\nLine 3\n",
        encoding="utf-8",
    )
    cfg = AgentConfig(state_dir=str(tmp_path))

    res = execute_collect_logs({}, cfg)
    assert "PAIR-[REDACTED]" in res["log_content"]
    assert "PAIR-xyz9876543210" not in res["log_content"]
    assert res["size_bytes"] > 0
    assert res["truncated"] is False


def test_restart_service_local_allowlist_enforcement(tmp_path):
    """Test RESTART_APPROVED_SERVICE strictly rejects services not in local configuration."""
    cfg = AgentConfig(
        state_dir=str(tmp_path),
        approved_services=["venuedesk-worker", "ssh"],
    )

    # 1. Unapproved service must be rejected without executing any command
    with pytest.raises(ValueError, match="is not in the local approved services allowlist"):
        execute_restart_approved_service({"service_name": "malicious_daemon"}, cfg)

    # 2. Approved service invokes subprocess with shell=False
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout="OK", stderr="")
        res = execute_restart_approved_service({"service_name": "ssh"}, cfg)
        assert res["service"] == "ssh"
        assert res["success"] is True

        # Assert shell=False was explicitly passed
        mock_run.assert_called_once()
        _, kwargs = mock_run.call_args
        assert kwargs.get("shell") is False


def test_run_network_diagnostic_security_enforcement(tmp_path):
    """Test RUN_NETWORK_DIAGNOSTIC requires target to be in allowlist and validates target syntax."""
    cfg = AgentConfig(
        state_dir=str(tmp_path),
        diagnostic_allowlist=["127.0.0.1", "localhost", "api.internal.venue"],
    )

    # 1. Non-allowlisted host rejected
    with pytest.raises(ValueError, match="is not in the local diagnostic allowlist"):
        execute_run_network_diagnostic({"target": "evil.external.attacker.com"}, cfg)

    # 2. Malformed target with injection syntax rejected
    cfg_bad = AgentConfig(diagnostic_allowlist=["127.0.0.1; rm -rf /"])
    with pytest.raises(ValueError, match="Malformed target host"):
        execute_run_network_diagnostic({"target": "127.0.0.1; rm -rf /"}, cfg_bad)

    # 3. Allowlisted ping executes with shell=False
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout="64 bytes from 127.0.0.1")
        res = execute_run_network_diagnostic({"target": "127.0.0.1", "tool": "ping"}, cfg)
        assert res["success"] is True
        mock_run.assert_called_once()
        _, kwargs = mock_run.call_args
        assert kwargs.get("shell") is False

    # 4. Allowlisted tcp_connect
    with patch("socket.socket") as mock_sock_cls:
        mock_sock = MagicMock()
        mock_sock_cls.return_value = mock_sock
        res = execute_run_network_diagnostic(
            {"target": "127.0.0.1", "tool": "tcp_connect", "port": 8080},
            cfg,
        )
        assert res["reachable"] is True
        mock_sock.connect.assert_called_once_with(("127.0.0.1", 8080))


def test_job_executor_unallowlisted_job_rejected(tmp_path):
    """Test executor immediately rejects unknown or arbitrary jobs."""
    cfg = AgentConfig(state_dir=str(tmp_path))
    executor = JobExecutor(cfg)

    status, result, error = executor.execute("RUN_ARBITRARY_PYTHON", {"code": "import os; os.system('whoami')"})
    assert status == "FAILED"
    assert result is None
    assert "job_type_not_allowed" in error


def test_job_poller_cycle(tmp_path):
    """Test JobPoller fetches jobs, runs executor, and sends results."""
    cfg = AgentConfig(
        state_dir=str(tmp_path),
        diagnostic_allowlist=["localhost"],
    )
    mock_client = MagicMock()

    # Mock response from GET /api/v1/agents/jobs
    poll_resp = MagicMock(status_code=200)
    poll_resp.json.return_value = {
        "jobs": [
            {
                "id": 42,
                "job_type": "REFRESH_CONFIGURATION",
                "payload": {},
            }
        ]
    }
    mock_client.request.side_effect = [
        poll_resp,  # GET /jobs
        MagicMock(status_code=200),  # POST /jobs/42/result
    ]

    poller = JobPoller(cfg, client=mock_client)
    executed = poller.poll_and_execute_once()

    assert len(executed) == 1
    assert executed[0]["id"] == 42
    assert executed[0]["status"] == "SUCCEEDED"
    assert executed[0]["reported"] is True

    # Check that result was posted to server
    assert mock_client.request.call_count == 2
    post_call = mock_client.request.call_args_list[1]
    assert post_call[0][0] == "POST"
    assert post_call[0][1] == "/api/v1/agents/jobs/42/result"
    assert post_call[1]["json_data"]["status"] == "SUCCEEDED"
