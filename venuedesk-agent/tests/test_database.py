"""Unit tests for agent SQLite local database and identity store."""
from agent.identity.device_id import IdentityStore
from agent.storage.database import AgentDatabase


def test_agent_database_crud(tmp_path):
    db_file = tmp_path / "state" / "agent_state.db"
    db = AgentDatabase(db_file)

    assert db.get_state("non_existent") is None
    assert db.get_state("non_existent", "default_val") == "default_val"

    db.set_state("test_key", "value_1")
    assert db.get_state("test_key") == "value_1"

    db.set_state("test_key", "value_2")
    assert db.get_state("test_key") == "value_2"

    db.delete_state("test_key")
    assert db.get_state("test_key") is None


def test_agent_instance_id_persistent(tmp_path):
    db_file = tmp_path / "state" / "agent_state.db"
    db = AgentDatabase(db_file)

    id1 = db.get_agent_instance_id()
    assert id1 is not None
    assert len(id1) == 36  # UUID4 string format

    # Call again on same DB
    id2 = db.get_agent_instance_id()
    assert id1 == id2

    # Open fresh instance with same DB file
    db2 = AgentDatabase(db_file)
    assert db2.get_agent_instance_id() == id1


def test_identity_store_device_lifecycle(tmp_path):
    db_file = tmp_path / "state" / "agent_state.db"
    db = AgentDatabase(db_file)
    store = IdentityStore(db)

    assert not store.is_enrolled()
    assert store.device_id is None
    assert store.credential_version == 1

    store.set_device_id("VD-DEVICE-A8123F00")
    assert store.is_enrolled()
    assert store.device_id == "VD-DEVICE-A8123F00"

    store.set_credential_version(2)
    assert store.credential_version == 2
