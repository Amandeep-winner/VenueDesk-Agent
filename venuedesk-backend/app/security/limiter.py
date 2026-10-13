"""Rate limiting utilities for sensitive control plane endpoints."""

import threading
import time
from collections import defaultdict
from functools import wraps

from flask import flash, jsonify, make_response, render_template, request


class InMemoryRateLimiter:
    """Thread-safe in-memory sliding window rate limiter.

    Documented for single-process instances or test suites. For multi-process
    production deployments across multiple workers/nodes, configure Redis
    storage via RATELIMIT_STORAGE_URL.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._events: dict[str, list[float]] = defaultdict(list)

    def is_allowed(self, key: str, max_requests: int, window_seconds: int) -> tuple[bool, int]:
        """Check if request under key is allowed.

        Returns (allowed: bool, retry_after: int seconds).
        """
        now = time.time()
        with self._lock:
            # Clean expired events
            valid_events = [t for t in self._events[key] if now - t < window_seconds]
            if len(valid_events) >= max_requests:
                oldest = valid_events[0]
                retry_after = max(1, int(window_seconds - (now - oldest)))
                self._events[key] = valid_events
                return False, retry_after

            valid_events.append(now)
            self._events[key] = valid_events
            return True, 0

    def reset(self) -> None:
        """Clear all recorded rate limit windows."""
        with self._lock:
            self._events.clear()


limiter = InMemoryRateLimiter()


def rate_limit(max_requests: int = 10, window_seconds: int = 60, key_prefix: str = "ip"):
    """Decorator to enforce rate limiting per remote IP."""

    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            ip = request.remote_addr or "127.0.0.1"
            key = f"{key_prefix}:{ip}:{request.endpoint}"
            allowed, retry_after = limiter.is_allowed(key, max_requests, window_seconds)
            if not allowed:
                # Differentiate JSON vs HTML requests
                if request.is_json or request.path.startswith("/api/"):
                    resp = jsonify(
                        {
                            "error": "rate_limited",
                            "message": "Too many requests. Please try again later.",
                            "retry_after": retry_after,
                        }
                    )
                    resp.headers["Retry-After"] = str(retry_after)
                    return resp, 429

                flash(f"Too many attempts. Please wait {retry_after} seconds.", "danger")
                resp = make_response(render_template("infrastructure/login.html"), 429)
                resp.headers["Retry-After"] = str(retry_after)
                return resp
            return fn(*args, **kwargs)

        return wrapper

    return decorator
