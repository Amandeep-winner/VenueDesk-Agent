"""Local device identity and agent instance identifier helpers."""
from agent.storage.database import AgentDatabase


class IdentityStore:
    """Manages identity attributes in local agent storage."""

    def __init__(self, db: AgentDatabase) -> None:
        self.db = db

    @property
    def agent_instance_id(self) -> str:
        """Persistent local UUID identifying this specific OS/agent installation instance."""
        return self.db.get_agent_instance_id()

    @property
    def os_installation_id(self) -> str:
        """Persistent local UUID identifying this specific OS installation."""
        return self.db.get_os_installation_id()

    @property
    def device_id(self) -> str | None:
        """Assigned control-plane device identifier (e.g. VD-DEVICE-XXXXXXXX)."""
        return self.db.get_device_id()

    def set_device_id(self, device_id: str) -> None:
        """Persist device identifier assigned during enrollment."""
        self.db.set_device_id(device_id)

    @property
    def credential_version(self) -> int:
        """Active credential version (default 1)."""
        return self.db.get_credential_version()

    def set_credential_version(self, version: int) -> None:
        """Update active credential version."""
        self.db.set_credential_version(version)

    def is_enrolled(self) -> bool:
        """Return True if device_id is assigned and present."""
        return bool(self.device_id)
