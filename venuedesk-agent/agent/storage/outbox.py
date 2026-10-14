"""Agent offline outbox implementing priority queue, TTL, pressure shedding, and ordered flush."""

import json
import logging
import os
import re
import sqlite3
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Priority constants
PRIORITY_IDENTITY_EVENT = 0  # Highest priority: never dropped under pressure unless TTL expired
PRIORITY_INVENTORY = 1  # Medium priority
PRIORITY_TELEMETRY = 2  # Lowest priority: dropped first under buffer pressure

# Status constants
STATUS_PENDING = "PENDING"
STATUS_IN_FLIGHT = "IN_FLIGHT"
STATUS_DELIVERED = "DELIVERED"
STATUS_FAILED_PERMANENT = "FAILED_PERMANENT"

_SECRET_PATTERN = re.compile(
    r"(pair-[a-zA-Z0-9_\-]+|bearer\s+[a-zA-Z0-9_\.\-]+|password['\":\s=]+[^\s,;]+|"
    r"private_key['\":\s=]+[^\s,;]+|secret['\":\s=]+[^\s,;]+)",
    re.IGNORECASE,
)


def _redact_message(msg: str) -> str:
    """Sanitize secrets and credentials from error logs and message strings."""
    if not msg:
        return ""
    return _SECRET_PATTERN.sub("[REDACTED]", str(msg))


@dataclass
class OutboxItem:
    """Outbox queued item representation."""

    id: int
    priority: int
    topic: str
    payload: dict[str, Any]
    created_at: float
    attempts: int = 0
    event_id: str = ""
    kind: str = ""
    status: str = STATUS_PENDING
    next_attempt_at: float = 0.0
    last_error: str | None = None


class _DbConnectionWrapper:
    """Wrapper ensuring SQLite connection is closed on context exit while managing transactions."""

    def __init__(self, conn: sqlite3.Connection):
        self._conn = conn

    def __getattr__(self, name: str) -> Any:
        return getattr(self._conn, name)

    def __enter__(self) -> sqlite3.Connection:
        self._conn.__enter__()
        return self._conn

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: object,
    ) -> Any:
        try:
            return self._conn.__exit__(exc_type, exc_val, exc_tb)
        finally:
            self._conn.close()


class Outbox:
    """SQLite-backed persistent priority queue with TTL, WAL mode, and pressure shedding."""

    def __init__(
        self,
        db_path: str | Path,
        max_items: int = 10000,
        ttl_hours: int = 24,
        max_bytes: int = 50 * 1024 * 1024,
    ) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.max_items = max_items
        self.ttl_hours = ttl_hours
        self.max_bytes = max_bytes
        self.dropped_events_count = 0
        self.outbox_resets_count = 0
        self._in_memory_queue: list[OutboxItem] = []
        self._init_db()
        self.revert_in_flight(stale_threshold_seconds=60.0)

    def _get_connection(self) -> Any:
        """Create a sqlite3 connection with WAL mode and NORMAL synchronous."""
        conn = None
        try:
            conn = sqlite3.connect(self.db_path, timeout=10.0)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("PRAGMA synchronous=NORMAL;")
            return _DbConnectionWrapper(conn)
        except sqlite3.DatabaseError as exc:
            if conn is not None:
                try:
                    conn.close()
                except (sqlite3.Error, OSError):
                    pass
            if "malformed" in str(exc).lower() or "not a database" in str(exc).lower():
                self._handle_corrupt_db()
                fresh = sqlite3.connect(self.db_path, timeout=10.0)
                fresh.row_factory = sqlite3.Row
                fresh.execute("PRAGMA journal_mode=WAL;")
                fresh.execute("PRAGMA synchronous=NORMAL;")
                return _DbConnectionWrapper(fresh)
            raise

    def _handle_corrupt_db(self) -> None:
        """Move corrupted database aside and reinitialize a clean store."""
        ts = int(time.time() * 1000)
        corrupt_path = self.db_path.parent / f"{self.db_path.name}.corrupt.{ts}"
        logger.error(
            "Outbox SQLite database corrupt! Moving to %s and resetting outbox", corrupt_path
        )
        try:
            if self.db_path.exists():
                os.replace(self.db_path, corrupt_path)
            for suffix in ["-wal", "-shm"]:
                extra = Path(str(self.db_path) + suffix)
                if extra.exists():
                    os.replace(extra, Path(str(corrupt_path) + suffix))
        except OSError as exc:
            logger.warning("Failed moving corrupt database: %s", exc)
            try:
                self.db_path.unlink(missing_ok=True)
            except OSError:
                pass

        self.outbox_resets_count += 1
        logger.warning("Event OUTBOX_RESET emitted: Outbox database reinitialized after corruption")

    def _init_db(self) -> None:
        """Initialize schema and ensure all required columns and indexes exist."""
        try:
            with self._get_connection() as conn:
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS outbox (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        event_id TEXT UNIQUE,
                        kind TEXT NOT NULL,
                        priority INTEGER NOT NULL,
                        topic TEXT NOT NULL,
                        payload TEXT NOT NULL,
                        created_at REAL NOT NULL,
                        status TEXT NOT NULL DEFAULT 'PENDING',
                        attempts INTEGER DEFAULT 0,
                        next_attempt_at REAL DEFAULT 0.0,
                        last_error TEXT
                    )
                    """
                )
                conn.execute(
                    """
                    CREATE INDEX IF NOT EXISTS idx_outbox_prio
                    ON outbox(priority, created_at, id)
                    """
                )
                conn.execute(
                    """
                    CREATE INDEX IF NOT EXISTS idx_outbox_status
                    ON outbox(status, next_attempt_at)
                    """
                )
                # Check for legacy schema migration
                cur = conn.execute("PRAGMA table_info(outbox)")
                cols = {row["name"] for row in cur.fetchall()}
                if "event_id" not in cols:
                    conn.execute("ALTER TABLE outbox ADD COLUMN event_id TEXT")
                if "kind" not in cols:
                    conn.execute(
                        "ALTER TABLE outbox ADD COLUMN kind TEXT NOT NULL DEFAULT 'telemetry'"
                    )
                if "status" not in cols:
                    conn.execute(
                        "ALTER TABLE outbox ADD COLUMN status TEXT NOT NULL DEFAULT 'PENDING'"
                    )
                if "next_attempt_at" not in cols:
                    conn.execute("ALTER TABLE outbox ADD COLUMN next_attempt_at REAL DEFAULT 0.0")
                if "last_error" not in cols:
                    conn.execute("ALTER TABLE outbox ADD COLUMN last_error TEXT")
                conn.commit()
        except sqlite3.DatabaseError as exc:
            if "malformed" in str(exc).lower() or "not a database" in str(exc).lower():
                self._handle_corrupt_db()
            else:
                raise

    def get_and_reset_dropped_events_count(self) -> int:
        """Return the count of events dropped due to buffer pressure, resetting the counter."""
        dropped = self.dropped_events_count
        self.dropped_events_count = 0
        return dropped

    def revert_in_flight(self, stale_threshold_seconds: float = 60.0) -> int:
        """Crash recovery: revert stale IN_FLIGHT rows back to PENDING status."""
        cutoff = time.time() - stale_threshold_seconds
        try:
            with self._get_connection() as conn:
                cur = conn.execute(
                    """
                    UPDATE outbox
                    SET status = ?
                    WHERE status = ? AND (created_at < ? OR next_attempt_at < ?)
                    """,
                    (STATUS_PENDING, STATUS_IN_FLIGHT, cutoff, cutoff),
                )
                conn.commit()
                reverted = cur.rowcount
                if reverted > 0:
                    logger.info(
                        "Crash recovery: reverted %d stale in-flight events to PENDING", reverted
                    )
                return reverted
        except sqlite3.DatabaseError as exc:
            if "malformed" in str(exc).lower() or "not a database" in str(exc).lower():
                self._handle_corrupt_db()
            return 0

    def purge_expired(self) -> int:
        """Purge items older than TTL hours. Priority 0 items also respect TTL."""
        cutoff = time.time() - (self.ttl_hours * 3600)
        try:
            with self._get_connection() as conn:
                cur = conn.execute("DELETE FROM outbox WHERE created_at < ?", (cutoff,))
                conn.commit()
                return cur.rowcount
        except sqlite3.DatabaseError as exc:
            if "malformed" in str(exc).lower() or "not a database" in str(exc).lower():
                self._handle_corrupt_db()
            return 0

    def purge_delivered(self, retention_seconds: float = 3600.0) -> int:
        """Purge DELIVERED items older than retention threshold."""
        cutoff = time.time() - retention_seconds
        try:
            with self._get_connection() as conn:
                cur = conn.execute(
                    "DELETE FROM outbox WHERE status = ? AND next_attempt_at < ?",
                    (STATUS_DELIVERED, cutoff),
                )
                conn.commit()
                return cur.rowcount
        except sqlite3.DatabaseError:
            return 0

    def count(self) -> int:
        """Return total number of non-delivered items currently in outbox."""
        try:
            with self._get_connection() as conn:
                cur = conn.execute(
                    "SELECT count(*) FROM outbox WHERE status != ?", (STATUS_DELIVERED,)
                )
                return int(cur.fetchone()[0]) + len(self._in_memory_queue)
        except sqlite3.DatabaseError as exc:
            if "malformed" in str(exc).lower() or "not a database" in str(exc).lower():
                self._handle_corrupt_db()
            return len(self._in_memory_queue)

    def count_by_priority(self) -> dict[int, int]:
        """Return item count broken down by priority level for pending/in-flight items."""
        counts = {0: 0, 1: 0, 2: 0}
        for item in self._in_memory_queue:
            counts[item.priority] = counts.get(item.priority, 0) + 1
        try:
            with self._get_connection() as conn:
                cur = conn.execute(
                    "SELECT priority, count(*) FROM outbox WHERE status != ? GROUP BY priority",
                    (STATUS_DELIVERED,),
                )
                for row in cur.fetchall():
                    counts[row[0]] = counts.get(row[0], 0) + row[1]
        except sqlite3.DatabaseError:
            pass
        return counts

    def _get_queue_bytes(self) -> int:
        """Estimate current byte size of the outbox database."""
        try:
            if self.db_path.exists():
                return self.db_path.stat().st_size
        except OSError:
            pass
        return 0

    def enqueue(
        self,
        priority: int,
        topic: str,
        payload: dict[str, Any],
        event_id: str | None = None,
        kind: str | None = None,
    ) -> int | None:
        """Enqueue payload with priority. Sheds lowest-priority items under pressure."""
        self.purge_expired()
        now = time.time()

        if event_id is None:
            event_id = payload.get("event_id") or str(uuid.uuid4())
        if kind is None:
            kind = topic

        # Ensure event_id is preserved inside payload dict
        if isinstance(payload, dict):
            payload.setdefault("event_id", event_id)
            if (
                topic == "telemetry"
                and "samples" in payload
                and isinstance(payload["samples"], list)
            ):
                for s in payload["samples"]:
                    if isinstance(s, dict) and "event_id" not in s:
                        s["event_id"] = str(uuid.uuid4())

        payload_str = json.dumps(payload, separators=(",", ":"))

        try:
            with self._get_connection() as conn:
                cur = conn.execute(
                    "SELECT count(*) FROM outbox WHERE status != ?", (STATUS_DELIVERED,)
                )
                total = cur.fetchone()[0]
                queue_bytes = self._get_queue_bytes()

                if total >= self.max_items or queue_bytes >= self.max_bytes:
                    # Pressure shed: find the lowest priority item (highest priority number > 0)
                    # Telemetry (2) dropped first, then Inventory (1).
                    # Priority 0 is NEVER dropped under pressure.
                    drop_cur = conn.execute(
                        """
                        SELECT id, event_id FROM outbox
                        WHERE priority > 0 AND status != ?
                        ORDER BY priority DESC, created_at ASC
                        LIMIT 1
                        """,
                        (STATUS_DELIVERED,),
                    )
                    drop_row = drop_cur.fetchone()
                    if drop_row:
                        conn.execute("DELETE FROM outbox WHERE id = ?", (drop_row["id"],))
                        self.dropped_events_count += 1
                        logger.debug("Dropped outbox item %s under buffer pressure", drop_row["id"])
                    else:
                        # Queue consists entirely of priority 0 items
                        if priority > 0:
                            logger.warning(
                                "Outbox full with priority 0 items; dropping lower priority enqueue"
                            )
                            self.dropped_events_count += 1
                            return None

                ins_cur = conn.execute(
                    """
                    INSERT INTO outbox (
                        event_id, kind, priority, topic, payload, created_at, status, attempts, next_attempt_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, 0, 0.0)
                    """,
                    (event_id, kind, priority, topic, payload_str, now, STATUS_PENDING),
                )
                conn.commit()
                return ins_cur.lastrowid

        except sqlite3.OperationalError as exc:
            err_msg = str(exc).lower()
            if (
                "disk is full" in err_msg
                or "disk full" in err_msg
                or "database or disk is full" in err_msg
            ):
                logger.warning(
                    "Disk full detected! Degrading to in-memory queue for priority-0 items only"
                )
                if priority == PRIORITY_IDENTITY_EVENT:
                    mem_item = OutboxItem(
                        id=-(len(self._in_memory_queue) + 1),
                        priority=priority,
                        topic=topic,
                        payload=payload,
                        created_at=now,
                        event_id=event_id,
                        kind=kind,
                        status=STATUS_PENDING,
                    )
                    self._in_memory_queue.append(mem_item)
                    return mem_item.id
                self.dropped_events_count += 1
                return None
            raise
        except sqlite3.DatabaseError as exc:
            if "malformed" in str(exc).lower() or "not a database" in str(exc).lower():
                self._handle_corrupt_db()
                return self.enqueue(priority, topic, payload, event_id, kind)
            raise

    def peek(self, limit: int = 100, include_in_flight: bool = False) -> list[OutboxItem]:
        """Retrieve pending items ordered by priority (0 first) then chronological arrival."""
        items: list[OutboxItem] = []

        # Include priority-0 items from in-memory fallback
        for item in self._in_memory_queue:
            if item.status == STATUS_PENDING or include_in_flight:
                items.append(item)

        status_clause = (
            "status IN ('PENDING', 'IN_FLIGHT')" if include_in_flight else "status = 'PENDING'"
        )
        try:
            with self._get_connection() as conn:
                cur = conn.execute(
                    f"""
                    SELECT id, event_id, kind, priority, topic, payload, created_at, status, attempts, next_attempt_at, last_error
                    FROM outbox
                    WHERE {status_clause}
                    ORDER BY priority ASC, created_at ASC, id ASC
                    LIMIT ?
                    """,
                    (limit,),
                )
                for row in cur.fetchall():
                    items.append(
                        OutboxItem(
                            id=row["id"],
                            priority=row["priority"],
                            topic=row["topic"],
                            payload=json.loads(row["payload"]),
                            created_at=row["created_at"],
                            attempts=row["attempts"],
                            event_id=row["event_id"] or "",
                            kind=row["kind"] or row["topic"],
                            status=row["status"],
                            next_attempt_at=row["next_attempt_at"] or 0.0,
                            last_error=row["last_error"],
                        )
                    )
        except sqlite3.DatabaseError as exc:
            if "malformed" in str(exc).lower() or "not a database" in str(exc).lower():
                self._handle_corrupt_db()
            return items

        # Sort combined in-memory and database items
        items.sort(key=lambda it: (it.priority, it.created_at, it.id))
        return items[:limit]

    def mark_in_flight(self, item_ids: list[int | str]) -> int:
        """Set status to IN_FLIGHT for given item IDs or event IDs."""
        if not item_ids:
            return 0
        int_ids = [x for x in item_ids if isinstance(x, int)]
        str_ids = [x for x in item_ids if isinstance(x, str)]

        with self._get_connection() as conn:
            updated = 0
            if int_ids:
                ph = ",".join("?" for _ in int_ids)
                cur = conn.execute(
                    f"UPDATE outbox SET status = ? WHERE id IN ({ph})", [STATUS_IN_FLIGHT, *int_ids]
                )
                updated += cur.rowcount
            if str_ids:
                ph = ",".join("?" for _ in str_ids)
                cur = conn.execute(
                    f"UPDATE outbox SET status = ? WHERE event_id IN ({ph})",
                    [STATUS_IN_FLIGHT, *str_ids],
                )
                updated += cur.rowcount
            conn.commit()
            return updated

    def mark_delivered(self, item_ids: list[int | str]) -> int:
        """Set status to DELIVERED for given item IDs or event IDs."""
        if not item_ids:
            return 0
        int_ids = [x for x in item_ids if isinstance(x, int)]
        str_ids = [x for x in item_ids if isinstance(x, str)]

        # Remove from in-memory fallback if present
        self._in_memory_queue = [
            it
            for it in self._in_memory_queue
            if it.id not in int_ids and it.event_id not in str_ids
        ]

        with self._get_connection() as conn:
            updated = 0
            now = time.time()
            if int_ids:
                ph = ",".join("?" for _ in int_ids)
                cur = conn.execute(
                    f"UPDATE outbox SET status = ?, next_attempt_at = ? WHERE id IN ({ph})",
                    [STATUS_DELIVERED, now, *int_ids],
                )
                updated += cur.rowcount
            if str_ids:
                ph = ",".join("?" for _ in str_ids)
                cur = conn.execute(
                    f"UPDATE outbox SET status = ?, next_attempt_at = ? WHERE event_id IN ({ph})",
                    [STATUS_DELIVERED, now, *str_ids],
                )
                updated += cur.rowcount
            conn.commit()
            return updated

    def mark_failed_permanent(self, item_ids: list[int | str], error: str = "") -> int:
        """Mark items as FAILED_PERMANENT when unrecoverable client errors (400/422) occur."""
        if not item_ids:
            return 0
        sanitized_error = _redact_message(error)
        int_ids = [x for x in item_ids if isinstance(x, int)]
        str_ids = [x for x in item_ids if isinstance(x, str)]

        with self._get_connection() as conn:
            updated = 0
            if int_ids:
                ph = ",".join("?" for _ in int_ids)
                cur = conn.execute(
                    f"UPDATE outbox SET status = ?, last_error = ? WHERE id IN ({ph})",
                    [STATUS_FAILED_PERMANENT, sanitized_error, *int_ids],
                )
                updated += cur.rowcount
            if str_ids:
                ph = ",".join("?" for _ in str_ids)
                cur = conn.execute(
                    f"UPDATE outbox SET status = ?, last_error = ? WHERE event_id IN ({ph})",
                    [STATUS_FAILED_PERMANENT, sanitized_error, *str_ids],
                )
                updated += cur.rowcount
            conn.commit()
            return updated

    def record_attempt(
        self,
        item_ids: list[int | str],
        error: str = "",
        next_attempt_at: float = 0.0,
    ) -> None:
        """Increment attempt counter, save sanitized last_error, and revert status to PENDING."""
        if not item_ids:
            return
        sanitized_error = _redact_message(error)
        int_ids = [x for x in item_ids if isinstance(x, int)]
        str_ids = [x for x in item_ids if isinstance(x, str)]

        with self._get_connection() as conn:
            if int_ids:
                ph = ",".join("?" for _ in int_ids)
                conn.execute(
                    f"""
                    UPDATE outbox
                    SET attempts = attempts + 1,
                        status = ?,
                        last_error = ?,
                        next_attempt_at = ?
                    WHERE id IN ({ph})
                    """,
                    [STATUS_PENDING, sanitized_error, next_attempt_at, *int_ids],
                )
            if str_ids:
                ph = ",".join("?" for _ in str_ids)
                conn.execute(
                    f"""
                    UPDATE outbox
                    SET attempts = attempts + 1,
                        status = ?,
                        last_error = ?,
                        next_attempt_at = ?
                    WHERE event_id IN ({ph})
                    """,
                    [STATUS_PENDING, sanitized_error, next_attempt_at, *str_ids],
                )
            conn.commit()

    def delete(self, item_ids: list[int | str]) -> int:
        """Remove successfully delivered items from queue."""
        if not item_ids:
            return 0
        int_ids = [x for x in item_ids if isinstance(x, int)]
        str_ids = [x for x in item_ids if isinstance(x, str)]

        self._in_memory_queue = [
            it
            for it in self._in_memory_queue
            if it.id not in int_ids and it.event_id not in str_ids
        ]

        with self._get_connection() as conn:
            deleted = 0
            if int_ids:
                ph = ",".join("?" for _ in int_ids)
                cur = conn.execute(f"DELETE FROM outbox WHERE id IN ({ph})", int_ids)
                deleted += cur.rowcount
            if str_ids:
                ph = ",".join("?" for _ in str_ids)
                cur = conn.execute(f"DELETE FROM outbox WHERE event_id IN ({ph})", str_ids)
                deleted += cur.rowcount
            conn.commit()
            return deleted

    def increment_attempts(self, item_ids: list[int | str]) -> None:
        """Increment delivery attempt counter for items that encountered transient errors."""
        self.record_attempt(item_ids, error="Transient failure")

    def flush(self, client: Any, batch_size: int = 100) -> int:
        """Flush queued items to the server in strict priority order. Halts on connection failure."""
        flushed_count = 0

        while True:
            items = self.peek(limit=batch_size)
            if not items:
                break

            # Group consecutive telemetry items for batching up to 500 samples
            idx = 0
            while idx < len(items):
                item = items[idx]

                if item.topic == "telemetry":
                    # Batch contiguous telemetry samples up to 500
                    telemetry_batch: list[OutboxItem] = []
                    while (
                        idx < len(items)
                        and items[idx].topic == "telemetry"
                        and len(telemetry_batch) < 500
                    ):
                        telemetry_batch.append(items[idx])
                        idx += 1

                    samples = []
                    for t_item in telemetry_batch:
                        if "samples" in t_item.payload and isinstance(
                            t_item.payload["samples"], list
                        ):
                            samples.extend(t_item.payload["samples"])
                        else:
                            samples.append(t_item.payload)

                    try:
                        resp = client.post(
                            "/api/v1/agents/telemetry", json_data={"samples": samples}
                        )
                        if resp.status_code == 200:
                            ids = [t.id for t in telemetry_batch]
                            self.delete(ids)
                            flushed_count += len(ids)
                        elif resp.status_code in (400, 422):
                            ids = [t.id for t in telemetry_batch]
                            self.mark_failed_permanent(ids, error=f"HTTP {resp.status_code}")
                            logger.error(
                                "Telemetry payload rejected with HTTP %s: permanent failure",
                                resp.status_code,
                            )
                            return flushed_count
                        else:
                            self.increment_attempts([t.id for t in telemetry_batch])
                            logger.warning(
                                "Telemetry batch flush failed with status %s", resp.status_code
                            )
                            return flushed_count
                    except (OSError, RuntimeError, ValueError) as exc:
                        logger.warning("Telemetry flush aborted due to connection failure: %s", exc)
                        return flushed_count

                elif item.topic == "inventory":
                    try:
                        resp = client.post("/api/v1/agents/inventory", json_data=item.payload)
                        if resp.status_code == 200:
                            self.delete([item.id])
                            flushed_count += 1
                        elif resp.status_code in (400, 422):
                            self.mark_failed_permanent([item.id], error=f"HTTP {resp.status_code}")
                            logger.error(
                                "Inventory rejected with HTTP %s: permanent failure",
                                resp.status_code,
                            )
                            return flushed_count
                        else:
                            self.increment_attempts([item.id])
                            logger.warning(
                                "Inventory flush failed with status %s", resp.status_code
                            )
                            return flushed_count
                    except (OSError, RuntimeError, ValueError) as exc:
                        logger.warning("Inventory flush aborted due to connection failure: %s", exc)
                        return flushed_count
                    idx += 1

                elif item.topic == "identity":
                    try:
                        resp = client.post("/api/v1/agents/identity", json_data=item.payload)
                        if resp.status_code == 200:
                            self.delete([item.id])
                            flushed_count += 1
                        elif resp.status_code in (400, 422):
                            self.mark_failed_permanent([item.id], error=f"HTTP {resp.status_code}")
                            logger.error(
                                "Identity rejected with HTTP %s: permanent failure",
                                resp.status_code,
                            )
                            return flushed_count
                        else:
                            self.increment_attempts([item.id])
                            logger.warning("Identity flush failed with status %s", resp.status_code)
                            return flushed_count
                    except (OSError, RuntimeError, ValueError) as exc:
                        logger.warning("Identity flush aborted due to connection failure: %s", exc)
                        return flushed_count
                    idx += 1

                else:
                    # Generic or event dispatch
                    try:
                        resp = client.post(f"/api/v1/agents/{item.topic}", json_data=item.payload)
                        if resp.status_code == 200:
                            self.delete([item.id])
                            flushed_count += 1
                        elif resp.status_code in (400, 422):
                            self.mark_failed_permanent([item.id], error=f"HTTP {resp.status_code}")
                            return flushed_count
                        elif resp.status_code in (404, 410) and item.topic == "jobs":
                            self.delete([item.id])
                            logger.info(
                                "Dropping stale job item %s with HTTP %s", item.id, resp.status_code
                            )
                        else:
                            self.increment_attempts([item.id])
                            return flushed_count
                    except (OSError, RuntimeError, ValueError) as exc:
                        logger.warning("Flush item %s failed: %s", item.id, exc)
                        return flushed_count
                    idx += 1

        return flushed_count
