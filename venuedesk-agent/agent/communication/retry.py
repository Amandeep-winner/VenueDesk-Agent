"""Exponential backoff retry utility with jitter and Retry-After support."""
import logging
import random
import time
from collections.abc import Callable

import httpx

logger = logging.getLogger(__name__)


class RetryPolicy:
    """Configurable retry policy with exponential backoff and jitter."""

    def __init__(
        self,
        max_attempts: int = 3,
        initial_interval: float = 2.0,
        backoff_multiplier: float = 2.0,
        max_interval: float = 300.0,
        jitter_factor: float = 0.2,
        full_jitter: bool = False,
    ) -> None:
        self.max_attempts = max_attempts
        self.initial_interval = initial_interval
        self.backoff_multiplier = backoff_multiplier
        self.max_interval = max_interval
        self.jitter_factor = jitter_factor
        self.full_jitter = full_jitter

    def compute_delay(
        self,
        attempt: int,
        response: httpx.Response | None = None,
        full_jitter: bool | None = None,
    ) -> float:
        """Compute delay in seconds for given attempt, honoring Retry-After header if present."""
        if response is not None:
            retry_after = response.headers.get("Retry-After")
            if retry_after:
                try:
                    return min(float(retry_after), self.max_interval)
                except ValueError:
                    pass

        delay = self.initial_interval * (self.backoff_multiplier ** (attempt - 1))
        delay = min(delay, self.max_interval)

        use_full_jitter = self.full_jitter if full_jitter is None else full_jitter
        if use_full_jitter and self.jitter_factor > 0.0:
            return random.uniform(0.0, delay)

        if self.jitter_factor > 0.0:
            jitter_range = delay * self.jitter_factor
            jittered = delay + random.uniform(-jitter_range, jitter_range)
            return max(0.1, min(jittered, self.max_interval))

        return delay

    def execute(self, func: Callable[[], httpx.Response]) -> httpx.Response:
        """Execute HTTP call with retry logic on network errors and transient HTTP status codes."""
        last_exception: Exception | None = None
        last_response: httpx.Response | None = None

        for attempt in range(1, self.max_attempts + 1):
            try:
                response = func()
                # If success or client error (except 429), return immediately
                if response.status_code < 500 and response.status_code != 429:
                    return response

                last_response = response
                if attempt == self.max_attempts:
                    return response

                delay = self.compute_delay(attempt, response)
                logger.warning(
                    "HTTP %d received (attempt %d/%d). Retrying in %.2fs...",
                    response.status_code,
                    attempt,
                    self.max_attempts,
                    delay,
                )
                time.sleep(delay)

            except (httpx.NetworkError, httpx.TimeoutException) as exc:
                last_exception = exc
                if attempt == self.max_attempts:
                    raise

                delay = self.compute_delay(attempt, None)
                logger.warning(
                    "Network error: %s (attempt %d/%d). Retrying in %.2fs...",
                    exc,
                    attempt,
                    self.max_attempts,
                    delay,
                )
                time.sleep(delay)

        if last_response is not None:
            return last_response
        if last_exception is not None:
            raise last_exception
        raise RuntimeError("Retry policy reached unexpected termination")


def classify_http_status(status_code: int) -> str:
    """Classify HTTP response status code into retry and error disposition."""
    if status_code in (400, 422):
        return "FAILED_PERMANENT"
    if status_code == 401:
        return "AUTH_FAILED"
    if status_code == 403:
        return "DEVICE_BLOCKED"
    if status_code in (404, 410):
        return "DROP"
    if status_code in (408, 429) or 500 <= status_code < 600:
        return "TRANSIENT"
    return "UNKNOWN"
