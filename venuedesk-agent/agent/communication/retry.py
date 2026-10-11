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
        initial_interval: float = 1.0,
        backoff_multiplier: float = 2.0,
        max_interval: float = 60.0,
        jitter_factor: float = 0.2,
    ) -> None:
        self.max_attempts = max_attempts
        self.initial_interval = initial_interval
        self.backoff_multiplier = backoff_multiplier
        self.max_interval = max_interval
        self.jitter_factor = jitter_factor

    def compute_delay(self, attempt: int, response: httpx.Response | None = None) -> float:
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

        # Apply symmetric jitter
        jitter_range = delay * self.jitter_factor
        jittered = delay + random.uniform(-jitter_range, jitter_range)
        return max(0.1, jittered)

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
