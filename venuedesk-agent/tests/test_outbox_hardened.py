"""Comprehensive unit tests for hardened agent outbox and retry behavior."""
import subprocess
import sys
import time
from unittest.mock import MagicMock

from agent.communication.retry import RetryPolicy, classify_http_status
from agent.storage.outbox import (
    PRIORITY_IDENTITY_EVENT,
    PRIORITY_INVENTORY,
    PRIORITY_TELEMETRY,
    STATUS_FAILED_PERMANENT,
    STATUS_IN_FLIGHT,
    STATUS_PENDING,
    Outbox,
    _redact_message,
)


def test_network_down_events_queued(tmp_path):
    """When network is unavailable, enqueued events are safely queued and none are dropped."""
    db_file = tmp_path / "test_outbox.db"
    box = Outbox(db_file)

    box.enqueue(PRIORITY_IDENTITY_EVENT, "identity", {"event": "id_01"})
    box.enqueue(PRIORITY_INVENTORY, "inventory", {"hostname": "box-01"})
    box.enqueue(PRIORITY_TELEMETRY, "telemetry", {"cpu_percent": 45.0})

    assert box.count() == 3

    # Attempt flush with failing client
    client = MagicMock()
    client.post.side_effect = ConnectionError("Network unreachable")

    flushed = box.flush(client)
    assert flushed == 0
    assert box.count() == 3


def test_in_flight_reverted_after_crash(tmp_path):
    """Crash recovery: IN_FLIGHT rows older than threshold revert to PENDING on startup."""
    db_file = tmp_path / "test_outbox.db"
    box = Outbox(db_file)

    box.enqueue(PRIORITY_IDENTITY_EVENT, "identity", {"event": "id_crash"})
    box.mark_in_flight([1])

    with box._get_connection() as conn:
        cur = conn.execute("SELECT status FROM outbox WHERE id = 1")
        assert cur.fetchone()["status"] == STATUS_IN_FLIGHT

        # Artificially age the in-flight row beyond 60s
        conn.execute("UPDATE outbox SET created_at = ?, next_attempt_at = ? WHERE id = 1", (time.time() - 100, time.time() - 100))
        conn.commit()

    # Reinitialize outbox simulating process crash restart
    box2 = Outbox(db_file)
    with box2._get_connection() as conn:
        cur = conn.execute("SELECT status FROM outbox WHERE id = 1")
        assert cur.fetchone()["status"] == STATUS_PENDING


def test_long_outage_then_drain_in_priority_order(tmp_path):
    """Simulate long outage queuing multiple priority items, then draining in order 0, 1, 2."""
    db_file = tmp_path / "test_outbox.db"
    box = Outbox(db_file)

    box.enqueue(PRIORITY_TELEMETRY, "telemetry", {"sample": 1})
    box.enqueue(PRIORITY_INVENTORY, "inventory", {"host": "pc-01"})
    box.enqueue(PRIORITY_IDENTITY_EVENT, "identity", {"event": "reconcile"})
    box.enqueue(PRIORITY_TELEMETRY, "telemetry", {"sample": 2})

    called_topics = []
    client = MagicMock()

    def mock_post(url, json_data=None):
        topic = url.split("/")[-1]
        called_topics.append(topic)
        resp = MagicMock()
        resp.status_code = 200
        return resp

    client.post.side_effect = mock_post

    flushed = box.flush(client)
    assert flushed == 4
    assert box.count() == 0
    # Strict priority: identity (0) -> inventory (1) -> telemetry (2)
    assert called_topics == ["identity", "inventory", "telemetry"]


def test_permanent_error_not_retried_forever(tmp_path):
    """Unrecoverable HTTP 400/422 marks item as FAILED_PERMANENT and halts repeat loops."""
    db_file = tmp_path / "test_outbox.db"
    box = Outbox(db_file)

    box.enqueue(PRIORITY_INVENTORY, "inventory", {"bad_data": True})

    client = MagicMock()
    resp = MagicMock()
    resp.status_code = 400
    client.post.return_value = resp

    flushed = box.flush(client)
    assert flushed == 0

    with box._get_connection() as conn:
        cur = conn.execute("SELECT status, last_error FROM outbox WHERE id = 1")
        row = cur.fetchone()
        assert row["status"] == STATUS_FAILED_PERMANENT
        assert "400" in row["last_error"]

    # Subsequent peek does not include FAILED_PERMANENT
    pending = box.peek()
    assert len(pending) == 0


def test_queue_capacity_drops_lowest_priority_first(tmp_path):
    """Queue capacity pressure sheds oldest telemetry (priority 2) before inventory."""
    db_file = tmp_path / "test_outbox.db"
    box = Outbox(db_file, max_items=2)

    box.enqueue(PRIORITY_INVENTORY, "inventory", {"host": "pc1"})
    box.enqueue(PRIORITY_TELEMETRY, "telemetry", {"cpu": 10})
    assert box.count() == 2

    # Enqueue another telemetry: sheds older telemetry
    box.enqueue(PRIORITY_TELEMETRY, "telemetry", {"cpu": 20})
    assert box.count() == 2

    items = box.peek()
    assert items[0].topic == "inventory"
    assert items[1].payload["cpu"] == 20
    assert box.get_and_reset_dropped_events_count() == 1


def test_priority0_never_dropped_before_ttl(tmp_path):
    """Priority 0 events are never dropped under capacity pressure before TTL."""
    db_file = tmp_path / "test_outbox.db"
    box = Outbox(db_file, max_items=2)

    box.enqueue(PRIORITY_IDENTITY_EVENT, "identity", {"id": "ev1"})
    box.enqueue(PRIORITY_IDENTITY_EVENT, "identity", {"id": "ev2"})
    assert box.count() == 2

    # Attempting to enqueue lower priority when full with P0
    res = box.enqueue(PRIORITY_TELEMETRY, "telemetry", {"cpu": 99})
    assert res is None
    assert box.count() == 2

    items = box.peek()
    assert all(it.priority == PRIORITY_IDENTITY_EVENT for it in items)


def test_corrupt_db_recovers(tmp_path):
    """Corrupted database file is moved aside and outbox resets automatically."""
    db_file = tmp_path / "test_outbox.db"
    box = Outbox(db_file)
    box.enqueue(PRIORITY_INVENTORY, "inventory", {"host": "pc-orig"})
    assert box.count() == 1

    # Overwrite DB file with garbage bytes to simulate corruption and unlink wal/shm
    with open(db_file, "wb") as f:
        f.write(b"GARBAGE_NOT_A_SQLITE_DATABASE_HEADER_DATA_1234567890")
    for suffix in ["-wal", "-shm"]:
        extra = tmp_path / f"test_outbox.db{suffix}"
        if extra.exists():
            extra.unlink(missing_ok=True)

    # Accessing corrupt outbox should trigger corruption recovery
    box_recovered = Outbox(db_file)
    assert box_recovered.outbox_resets_count >= 1
    assert box_recovered.count() == 0

    # New writes succeed
    box_recovered.enqueue(PRIORITY_IDENTITY_EVENT, "identity", {"recovered": True})
    assert box_recovered.count() == 1


def test_backoff_has_jitter_and_cap():
    """Exponential backoff enforces cap, honors jitter, and classifies status codes."""
    policy = RetryPolicy(
        max_attempts=5,
        initial_interval=2.0,
        backoff_multiplier=2.0,
        max_interval=300.0,
        jitter_factor=0.2,
        full_jitter=True,
    )

    # Delay should always be within [0, min(cap, base * 2^(attempt-1))]
    for attempt in range(1, 6):
        ceiling = min(300.0, 2.0 * (2.0 ** (attempt - 1)))
        delays = [policy.compute_delay(attempt, full_jitter=True) for _ in range(20)]
        assert all(0.0 <= d <= ceiling for d in delays)
        # Verify jitter exists (not all values identical)
        assert len(set(delays)) > 1

    # Verify status code classifications
    assert classify_http_status(400) == "FAILED_PERMANENT"
    assert classify_http_status(422) == "FAILED_PERMANENT"
    assert classify_http_status(401) == "AUTH_FAILED"
    assert classify_http_status(403) == "DEVICE_BLOCKED"
    assert classify_http_status(404) == "DROP"
    assert classify_http_status(410) == "DROP"
    assert classify_http_status(429) == "TRANSIENT"
    assert classify_http_status(500) == "TRANSIENT"
    assert classify_http_status(503) == "TRANSIENT"


def test_no_secrets_in_agent_logs():
    """Secrets, tokens, and credentials are redacted from stored errors and logs."""
    msg = "Error connecting with token PAIR-abcd-1234-wxyz and password=supersecret"
    sanitized = _redact_message(msg)
    assert "PAIR-abcd-1234-wxyz" not in sanitized
    assert "supersecret" not in sanitized
    assert "[REDACTED]" in sanitized


def test_kill_process_then_restart_preserves_queue(tmp_path):
    """Subprocess termination preserves queued items in sqlite outbox."""
    db_file = tmp_path / "subprocess_outbox.db"

    # Run helper script in separate process to enqueue items
    script = f"""
import sys
from pathlib import Path
from agent.storage.outbox import Outbox, PRIORITY_IDENTITY_EVENT, PRIORITY_INVENTORY

box = Outbox(r"{db_file}")
box.enqueue(PRIORITY_IDENTITY_EVENT, "identity", {{"event": "sub_p0"}})
box.enqueue(PRIORITY_INVENTORY, "inventory", {{"host": "sub_p1"}})
"""
    res = subprocess.run([sys.executable, "-c", script], check=False, capture_output=True, text=True)
    assert res.returncode == 0

    # Re-open in parent process
    box = Outbox(db_file)
    assert box.count() == 2
    items = box.peek()
    assert items[0].topic == "identity"
    assert items[1].topic == "inventory"
