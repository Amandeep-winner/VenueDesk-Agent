"""Agent offline outbox implementing priority queue, TTL, pressure shedding, and ordered flush."""
import json
import logging
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Priority constants
PRIORITY_IDENTITY_EVENT = 0  # Highest priority: never dropped under pressure unless TTL expired
PRIORITY_INVENTORY = 1       # Medium priority
PRIORITY_TELEMETRY = 2       # Lowest priority: dropped first under buffer pressure


@dataclass
class OutboxItem:
    """Outbox queued item representation."""
    id: int
    priority: int
    topic: str
    payload: dict[str, Any]
    created_at: float
    attempts: int = 0


class Outbox:
    """SQLite-backed persistent priority queue with TTL and pressure shedding."""

    def __init__(
        self,
        db_path: str | Path,
        max_items: int = 10000,
        ttl_hours: int = 24,
    ) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.max_items = max_items
        self.ttl_hours = ttl_hours
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._get_connection() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS outbox (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    priority INTEGER NOT NULL,
                    topic TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    attempts INTEGER DEFAULT 0
                )
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_outbox_prio
                ON outbox(priority, created_at, id)
                """
            )
            conn.commit()

    def purge_expired(self) -> int:
        """Purge items older than TTL hours. Priority 0 items also respect TTL."""
        cutoff = time.time() - (self.ttl_hours * 3600)
        with self._get_connection() as conn:
            cur = conn.execute("DELETE FROM outbox WHERE created_at < ?", (cutoff,))
            conn.commit()
            return cur.rowcount

    def count(self) -> int:
        """Return total number of items currently in outbox."""
        with self._get_connection() as conn:
            cur = conn.execute("SELECT count(*) FROM outbox")
            return int(cur.fetchone()[0])

    def count_by_priority(self) -> dict[int, int]:
        """Return item count broken down by priority level."""
        counts = {0: 0, 1: 0, 2: 0}
        with self._get_connection() as conn:
            cur = conn.execute("SELECT priority, count(*) FROM outbox GROUP BY priority")
            for row in cur.fetchall():
                counts[row[0]] = row[1]
        return counts

    def enqueue(self, priority: int, topic: str, payload: dict[str, Any]) -> int | None:
        """Enqueue payload with priority. Sheds lowest-priority items under pressure."""
        self.purge_expired()
        now = time.time()
        payload_str = json.dumps(payload, separators=(",", ":"))

        with self._get_connection() as conn:
            cur = conn.execute("SELECT count(*) FROM outbox")
            total = cur.fetchone()[0]

            if total >= self.max_items:
                # Pressure shed: find the lowest priority item (highest priority number > 0)
                # Telemetry (2) dropped first, then Inventory (1).
                # Priority 0 is NEVER dropped under pressure.
                drop_cur = conn.execute(
                    """
                    SELECT id FROM outbox
                    WHERE priority > 0
                    ORDER BY priority DESC, created_at ASC
                    LIMIT 1
                    """
                )
                drop_row = drop_cur.fetchone()
                if drop_row:
                    conn.execute("DELETE FROM outbox WHERE id = ?", (drop_row["id"],))
                    logger.debug("Dropped outbox item %s under buffer pressure", drop_row["id"])
                else:
                    # Queue consists entirely of priority 0 items
                    if priority > 0:
                        logger.warning("Outbox full with priority 0 items; dropping lower priority enqueue")
                        return None

            ins_cur = conn.execute(
                """
                INSERT INTO outbox (priority, topic, payload, created_at, attempts)
                VALUES (?, ?, ?, ?, 0)
                """,
                (priority, topic, payload_str, now),
            )
            conn.commit()
            return ins_cur.lastrowid

    def peek(self, limit: int = 100) -> list[OutboxItem]:
        """Retrieve pending items ordered by priority (0 first) then chronological arrival."""
        with self._get_connection() as conn:
            cur = conn.execute(
                """
                SELECT id, priority, topic, payload, created_at, attempts
                FROM outbox
                ORDER BY priority ASC, created_at ASC, id ASC
                LIMIT ?
                """,
                (limit,),
            )
            items = []
            for row in cur.fetchall():
                items.append(
                    OutboxItem(
                        id=row["id"],
                        priority=row["priority"],
                        topic=row["topic"],
                        payload=json.loads(row["payload"]),
                        created_at=row["created_at"],
                        attempts=row["attempts"],
                    )
                )
            return items

    def delete(self, item_ids: list[int]) -> int:
        """Remove successfully delivered items from queue."""
        if not item_ids:
            return 0
        placeholders = ",".join("?" for _ in item_ids)
        with self._get_connection() as conn:
            cur = conn.execute(f"DELETE FROM outbox WHERE id IN ({placeholders})", item_ids)
            conn.commit()
            return cur.rowcount

    def increment_attempts(self, item_ids: list[int]) -> None:
        """Increment delivery attempt counter for items that encountered transient errors."""
        if not item_ids:
            return
        placeholders = ",".join("?" for _ in item_ids)
        with self._get_connection() as conn:
            conn.execute(f"UPDATE outbox SET attempts = attempts + 1 WHERE id IN ({placeholders})", item_ids)
            conn.commit()

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
                    while idx < len(items) and items[idx].topic == "telemetry" and len(telemetry_batch) < 500:
                        telemetry_batch.append(items[idx])
                        idx += 1

                    samples = []
                    for t_item in telemetry_batch:
                        if "samples" in t_item.payload and isinstance(t_item.payload["samples"], list):
                            samples.extend(t_item.payload["samples"])
                        else:
                            samples.append(t_item.payload)

                    try:
                        resp = client.post("/api/v1/agents/telemetry", json_data={"samples": samples})
                        if resp.status_code == 200:
                            ids = [t.id for t in telemetry_batch]
                            self.delete(ids)
                            flushed_count += len(ids)
                        else:
                            self.increment_attempts([t.id for t in telemetry_batch])
                            logger.warning("Telemetry batch flush failed with status %s", resp.status_code)
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
                        else:
                            self.increment_attempts([item.id])
                            logger.warning("Inventory flush failed with status %s", resp.status_code)
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
                        else:
                            self.increment_attempts([item.id])
                            return flushed_count
                    except (OSError, RuntimeError, ValueError) as exc:
                        logger.warning("Flush item %s failed: %s", item.id, exc)
                        return flushed_count
                    idx += 1

        return flushed_count
