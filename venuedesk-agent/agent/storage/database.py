"""Agent local SQLite database for state management and continuity."""
import sqlite3
import uuid
from pathlib import Path


class AgentDatabase:
    """Manages local SQLite database (agent_state.db)."""

    def __init__(self, db_path: str | Path) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._get_connection() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS agent_state (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                )
                """
            )
            conn.commit()

    def get_state(self, key: str, default: str | None = None) -> str | None:
        with self._get_connection() as conn:
            cur = conn.execute("SELECT value FROM agent_state WHERE key = ?", (key,))
            row = cur.fetchone()
            if row:
                return str(row["value"])
            return default

    def set_state(self, key: str, value: str) -> None:
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO agent_state (key, value)
                VALUES (?, ?)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value
                """,
                (key, str(value)),
            )
            conn.commit()

    def delete_state(self, key: str) -> None:
        with self._get_connection() as conn:
            conn.execute("DELETE FROM agent_state WHERE key = ?", (key,))
            conn.commit()

    def get_agent_instance_id(self) -> str:
        """Retrieve persistent local agent_instance_id or generate a fresh UUID4."""
        instance_id = self.get_state("agent_instance_id")
        if not instance_id:
            instance_id = str(uuid.uuid4())
            self.set_state("agent_instance_id", instance_id)
        return instance_id

    def get_os_installation_id(self) -> str:
        """Retrieve persistent local os_installation_id or generate a fresh UUID4."""
        os_inst_id = self.get_state("os_installation_id")
        if not os_inst_id:
            os_inst_id = str(uuid.uuid4())
            self.set_state("os_installation_id", os_inst_id)
        return os_inst_id

    def get_device_id(self) -> str | None:
        """Get enrolled device_id (e.g. VD-DEVICE-XXXXXXXX) if registered."""
        return self.get_state("device_id")

    def set_device_id(self, device_id: str) -> None:
        """Store enrolled device_id."""
        self.set_state("device_id", device_id)

    def get_credential_version(self) -> int:
        """Get active credential version (default 1)."""
        val = self.get_state("credential_version", "1")
        try:
            return int(val or "1")
        except ValueError:
            return 1

    def set_credential_version(self, version: int) -> None:
        """Update active credential version."""
        self.set_state("credential_version", str(version))
