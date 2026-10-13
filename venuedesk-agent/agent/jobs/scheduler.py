"""Remote job poller and dispatcher for VenueDesk agent."""

import logging
from typing import Any

from agent.communication.client import AuthenticatedClient
from agent.config import AgentConfig
from agent.jobs.executor import JobExecutor

logger = logging.getLogger(__name__)


class JobPoller:
    """Polls control plane for pending jobs, dispatches to executor, and posts results."""

    def __init__(
        self,
        config: AgentConfig,
        client: AuthenticatedClient | None = None,
        executor: JobExecutor | None = None,
    ) -> None:
        self.config = config
        self.client = client or AuthenticatedClient(config)
        self.executor = executor or JobExecutor(config)

    def poll_and_execute_once(self) -> list[dict[str, Any]]:
        """Fetch pending jobs, execute each, and report results back to the control plane."""
        executed: list[dict[str, Any]] = []

        try:
            resp = self.client.request("GET", "/api/v1/agents/jobs")
            if resp.status_code != 200:
                logger.warning("Failed to poll jobs: HTTP %s (%s)", resp.status_code, resp.text)
                return executed

            data = resp.json()
            jobs = data.get("jobs", [])
            if not jobs:
                return executed

            logger.info("Received %d pending jobs from control plane", len(jobs))

            for job in jobs:
                job_id = job.get("id")
                job_type = job.get("job_type")
                payload = job.get("payload", {})

                logger.info("Executing job #%s (%s)", job_id, job_type)
                status, result, error = self.executor.execute(job_type, payload)

                # Report result back to control plane
                result_payload = {
                    "status": status,
                    "result": result or {},
                    "error": error,
                }
                report_resp = self.client.request(
                    "POST",
                    f"/api/v1/agents/jobs/{job_id}/result",
                    json_data=result_payload,
                )

                executed.append(
                    {
                        "id": job_id,
                        "job_type": job_type,
                        "status": status,
                        "reported": report_resp.status_code == 200,
                    }
                )

        except Exception as exc:
            logger.exception("Error in job poll and execution cycle")
            _ = exc

        return executed
