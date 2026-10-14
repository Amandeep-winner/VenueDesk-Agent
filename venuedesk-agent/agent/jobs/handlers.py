"""Allowlisted remote maintenance and diagnostic job handlers (spec §4.10)."""

import platform
import re
import socket
import subprocess
from pathlib import Path
from typing import Any

from agent.config import AgentConfig

ALLOWLISTED_JOB_TYPES = {
    "REFRESH_INVENTORY",
    "COLLECT_DIAGNOSTICS",
    "COLLECT_LOGS",
    "RESTART_APPROVED_SERVICE",
    "REFRESH_CONFIGURATION",
    "RUN_NETWORK_DIAGNOSTIC",
}

ALLOWLISTED_DIAGNOSTIC_TARGETS = {
    "system",
    "network",
    "storage",
    "hardware",
    "agent",
    "all",
}

TOKEN_REDACTION_PATTERN = re.compile(r"PAIR-[A-Za-z0-9_\-]+")
BEARER_REDACTION_PATTERN = re.compile(
    r"(?i)\b(bearer|token|secret|password|private_key)(?:\s*[:=]|\s+)\s*['\"]?([A-Za-z0-9_\-\.\/+=]{8,})['\"]?"
)


def redact_sensitive_text(text: str) -> str:
    """Redact pairing tokens and sensitive secrets from log content."""
    redacted = TOKEN_REDACTION_PATTERN.sub("PAIR-[REDACTED]", text)
    redacted = BEARER_REDACTION_PATTERN.sub(r"\1 [REDACTED]", redacted)
    return redacted


def execute_refresh_inventory(payload: dict[str, Any], config: AgentConfig) -> dict[str, Any]:
    """Execute REFRESH_INVENTORY job: gather current technical inventory snapshot."""
    from agent.collectors import collect_full_inventory

    return collect_full_inventory()


def execute_collect_diagnostics(payload: dict[str, Any], config: AgentConfig) -> dict[str, Any]:
    """Execute COLLECT_DIAGNOSTICS job: collect diagnostic health indicators.

    Rejects diagnostic targets that are not in the strict allowlist.
    """
    target = payload.get("target", "system")
    if target not in ALLOWLISTED_DIAGNOSTIC_TARGETS:
        raise ValueError(
            f"Diagnostic target '{target}' is not allowlisted (allowed: {sorted(ALLOWLISTED_DIAGNOSTIC_TARGETS)})"
        )

    import psutil

    diag: dict[str, Any] = {"target": target, "platform": platform.platform()}
    if target in ("system", "all"):
        diag["cpu_percent"] = psutil.cpu_percent(interval=0.1)
        diag["memory"] = psutil.virtual_memory()._asdict()
        diag["boot_time"] = psutil.boot_time()
    if target in ("storage", "all"):
        diag["disk_usage"] = {
            p.mountpoint: psutil.disk_usage(p.mountpoint)._asdict()
            for p in psutil.disk_partitions(all=False)[:3]
        }
    if target in ("network", "all"):
        diag["net_io"] = psutil.net_io_counters()._asdict()
    if target in ("agent", "all"):
        diag["state_dir_exists"] = Path(config.state_dir).exists()
        diag["key_store"] = config.key_store
    return diag


def execute_collect_logs(payload: dict[str, Any], config: AgentConfig) -> dict[str, Any]:
    """Execute COLLECT_LOGS job: return agent logs capped at 1MB with token redaction."""
    log_candidates = [
        Path(config.state_dir) / "agent.log",
        Path("logs") / "agent.log",
        Path("/var/log/venuedesk-agent/agent.log"),
    ]

    log_path = None
    for p in log_candidates:
        if p.is_file():
            log_path = p
            break

    max_bytes = 1024 * 1024  # 1 MB cap per spec §4.10
    if not log_path or not log_path.exists():
        return {
            "log_content": "[No local log file found on disk]",
            "size_bytes": 0,
            "truncated": False,
        }

    file_size = log_path.stat().st_size
    truncated = file_size > max_bytes

    with open(log_path, "r", encoding="utf-8", errors="replace") as f:
        if truncated:
            f.seek(file_size - max_bytes)
        raw_text = f.read()

    sanitized = redact_sensitive_text(raw_text)
    return {
        "log_content": sanitized,
        "size_bytes": len(sanitized.encode("utf-8")),
        "truncated": truncated,
    }


def execute_restart_approved_service(
    payload: dict[str, Any], config: AgentConfig
) -> dict[str, Any]:
    """Execute RESTART_APPROVED_SERVICE job.

    Security check: rejects any service name not in the local config's approved_services allowlist.
    """
    service_name = payload.get("service_name")
    if not service_name:
        raise ValueError("Missing 'service_name' in payload")

    # Local configuration allowlist check - server cannot extend this list
    if service_name not in config.approved_services:
        raise ValueError(
            f"Service '{service_name}' is not in the local approved services allowlist "
            f"(approved: {config.approved_services})"
        )

    # Cross-platform restart using safe argument list (shell=False)
    system = platform.system().lower()
    if system == "windows":
        cmd = [
            "powershell.exe",
            "-NoProfile",
            "-Command",
            f"Restart-Service -Name '{service_name}'",
        ]
    else:
        cmd = ["systemctl", "restart", service_name]

    try:
        proc = subprocess.run(
            cmd,
            shell=False,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        return {
            "service": service_name,
            "returncode": proc.returncode,
            "stdout": proc.stdout.strip(),
            "stderr": proc.stderr.strip(),
            "success": proc.returncode == 0,
        }
    except FileNotFoundError:
        return {
            "service": service_name,
            "returncode": -1,
            "error": "Service control binary not found",
            "success": False,
        }


def execute_refresh_configuration(payload: dict[str, Any], config: AgentConfig) -> dict[str, Any]:
    """Execute REFRESH_CONFIGURATION job: reload runtime settings."""
    reloaded = AgentConfig.load()
    return {
        "server_url": reloaded.server_url,
        "heartbeat_seconds": reloaded.heartbeat_seconds,
        "telemetry_seconds": reloaded.telemetry_seconds,
        "inventory_seconds": reloaded.inventory_seconds,
        "jobs_poll_seconds": reloaded.jobs_poll_seconds,
        "approved_services": reloaded.approved_services,
        "diagnostic_allowlist": reloaded.diagnostic_allowlist,
    }


def execute_run_network_diagnostic(payload: dict[str, Any], config: AgentConfig) -> dict[str, Any]:
    """Execute RUN_NETWORK_DIAGNOSTIC job.

    Security checks: strict target allowlisting, port range validation, shell=False invocation.
    """
    target = payload.get("target")
    if not target or not isinstance(target, str):
        raise ValueError("Missing or invalid 'target' host in payload")

    target = target.strip()

    # Target allowlist enforcement
    if target not in config.diagnostic_allowlist:
        raise ValueError(
            f"Target host '{target}' is not in the local diagnostic allowlist "
            f"(allowlist: {config.diagnostic_allowlist})"
        )

    # Sanitize target to ensure it is purely a valid hostname or IP (no injections or special chars)
    if not re.match(r"^[a-zA-Z0-9\.\-]+$", target):
        raise ValueError(f"Malformed target host '{target}'")

    tool = payload.get("tool", "ping").lower()

    if tool == "ping":
        system = platform.system().lower()
        if system == "windows":
            cmd = ["ping", "-n", "2", "-w", "2000", target]
        else:
            cmd = ["ping", "-c", "2", "-W", "2", target]

        proc = subprocess.run(
            cmd,
            shell=False,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        return {
            "tool": "ping",
            "target": target,
            "returncode": proc.returncode,
            "output": proc.stdout.strip(),
            "success": proc.returncode == 0,
        }

    elif tool == "dns":
        try:
            resolved_ip = socket.gethostbyname(target)
            return {
                "tool": "dns",
                "target": target,
                "resolved_ip": resolved_ip,
                "success": True,
            }
        except socket.gaierror as exc:
            return {
                "tool": "dns",
                "target": target,
                "error": str(exc),
                "success": False,
            }

    elif tool == "tcp_connect":
        port = payload.get("port", 80)
        try:
            port = int(port)
            if not (1 <= port <= 65535):
                raise ValueError("Port out of range (1-65535)")
        except (ValueError, TypeError):
            raise ValueError(f"Invalid port: {port}")

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3.0)
        try:
            s.connect((target, port))
            s.close()
            return {
                "tool": "tcp_connect",
                "target": target,
                "port": port,
                "reachable": True,
                "success": True,
            }
        except OSError as exc:
            return {
                "tool": "tcp_connect",
                "target": target,
                "port": port,
                "reachable": False,
                "error": str(exc),
                "success": False,
            }

    else:
        raise ValueError(
            f"Unsupported network diagnostic tool '{tool}' (allowed: ping, dns, tcp_connect)"
        )
