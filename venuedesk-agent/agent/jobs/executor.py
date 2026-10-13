"""Job executor enforcing allowlist validation and reporting status."""

import logging
from typing import Any

from agent.config import AgentConfig
from agent.jobs.handlers import (
    ALLOWLISTED_JOB_TYPES,
    execute_collect_diagnostics,
    execute_collect_logs,
    execute_refresh_configuration,
    execute_refresh_inventory,
    execute_restart_approved_service,
    execute_run_network_diagnostic,
)

logger = logging.getLogger(__name__)


class JobExecutor:
    """Dispatches allowlisted jobs and traps execution exceptions."""

    def __init__(self, config: AgentConfig) -> None:
        self.config = config

    def execute(
        self, job_type: str, payload: dict[str, Any] | None = None
    ) -> tuple[str, dict[str, Any] | None, str | None]:
        """Execute a job and return (status, result, error).

        status is 'SUCCEEDED' or 'FAILED'.
        """
        payload = payload or {}

        if job_type not in ALLOWLISTED_JOB_TYPES:
            logger.warning("Rejected unallowlisted job type: %s", job_type)
            return "FAILED", None, f"job_type_not_allowed: '{job_type}'"

        try:
            if job_type == "REFRESH_INVENTORY":
                result = execute_refresh_inventory(payload, self.config)
            elif job_type == "COLLECT_DIAGNOSTICS":
                result = execute_collect_diagnostics(payload, self.config)
            elif job_type == "COLLECT_LOGS":
                result = execute_collect_logs(payload, self.config)
            elif job_type == "RESTART_APPROVED_SERVICE":
                result = execute_restart_approved_service(payload, self.config)
            elif job_type == "REFRESH_CONFIGURATION":
                result = execute_refresh_configuration(payload, self.config)
            elif job_type == "RUN_NETWORK_DIAGNOSTIC":
                result = execute_run_network_diagnostic(payload, self.config)
            else:
                return "FAILED", None, f"Unhandled job type: {job_type}"

            return "SUCCEEDED", result, None

        except Exception as exc:
            logger.exception("Job %s execution failed", job_type)
            return "FAILED", None, str(exc)
