#!/usr/bin/env python3
"""Database migration verification script.

Copies a development/staging database, applies pending Alembic migrations
to head on the copy, and executes schema integrity and constraint checks.
"""

import shutil
import sqlite3
import sys
import tempfile
from pathlib import Path

# Add backend to pythonpath
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "venuedesk-backend"))

from alembic import command
from alembic.config import Config


def verify_database_integrity(db_path: Path) -> None:
    """Verify foreign key integrity, uniqueness constraints, and index presence."""
    conn = sqlite3.connect(str(db_path))
    cursor = conn.cursor()

    try:
        # 1. Foreign key integrity check
        cursor.execute("PRAGMA foreign_key_check")
        fk_violations = cursor.fetchall()
        if fk_violations:
            raise RuntimeError(f"Foreign key violations found: {fk_violations}")
        print("  [PASS] Foreign key integrity check passed (0 violations).")

        # 2. General database integrity check
        cursor.execute("PRAGMA integrity_check")
        integrity_row = cursor.fetchone()
        if not integrity_row or integrity_row[0] != "ok":
            raise RuntimeError(f"SQLite PRAGMA integrity_check failed: {integrity_row}")
        print("  [PASS] PRAGMA integrity_check passed (ok).")

        # 3. Check for duplicate ACTIVE links per device
        cursor.execute("""
            SELECT device_id, COUNT(*)
            FROM asset_device_links
            WHERE relationship_status = 'ACTIVE'
            GROUP BY device_id
            HAVING COUNT(*) > 1
        """)
        dup_device_links = cursor.fetchall()
        if dup_device_links:
            raise RuntimeError(
                f"Duplicate ACTIVE links per device found: {dup_device_links}"
            )
        print("  [PASS] No duplicate ACTIVE links per device.")

        # 4. Check for duplicate ACTIVE links per asset
        cursor.execute("""
            SELECT asset_id, COUNT(*)
            FROM asset_device_links
            WHERE relationship_status = 'ACTIVE'
            GROUP BY asset_id
            HAVING COUNT(*) > 1
        """)
        dup_asset_links = cursor.fetchall()
        if dup_asset_links:
            raise RuntimeError(
                f"Duplicate ACTIVE links per asset found: {dup_asset_links}"
            )
        print("  [PASS] No duplicate ACTIVE links per asset.")

        # 5. Verify essential production indexes
        cursor.execute("SELECT name FROM sqlite_master WHERE type = 'index'")
        existing_indexes = {row[0] for row in cursor.fetchall()}
        required_indexes = [
            "idx_telemetry_device_timestamp",
            "idx_device_events_device_occurred",
            "idx_physical_devices_status_last_seen",
            "idx_asset_device_links_asset_status",
            "uq_active_link_per_asset",
            "uq_active_link_per_device",
        ]
        missing = [idx for idx in required_indexes if idx not in existing_indexes]
        if missing:
            raise RuntimeError(f"Missing required production indexes: {missing}")
        print(
            f"  [PASS] All {len(required_indexes)} required production indexes present."
        )

    finally:
        conn.close()


def main() -> int:
    """Run migration on a database copy and verify integrity."""
    print("=== VenueDesk Database Migration-on-Copy Verification ===")

    # Determine source database
    dev_db_candidates = [
        REPO_ROOT / "venuedesk_dev.db",
        REPO_ROOT / "venuedesk-backend" / "venuedesk_dev.db",
        REPO_ROOT / "instance" / "venuedesk.db",
    ]
    source_db = next((p for p in dev_db_candidates if p.exists()), None)

    temp_dir = tempfile.mkdtemp(prefix="venuedesk_migration_test_")
    copy_path = Path(temp_dir) / "test_migrated.db"

    try:
        if source_db:
            print(f"Copying existing database from {source_db} to {copy_path}...")
            shutil.copy2(source_db, copy_path)
        else:
            print(
                f"No existing dev DB found; creating blank SQLite database at {copy_path}..."
            )
            # Touch file
            copy_path.touch()

        # Run Alembic migrations to head on the copy
        alembic_ini_path = (
            REPO_ROOT / "venuedesk-backend" / "migrations" / "alembic.ini"
        )
        alembic_cfg = Config(str(alembic_ini_path))
        alembic_cfg.set_main_option(
            "script_location",
            str(REPO_ROOT / "venuedesk-backend" / "migrations"),
        )
        alembic_cfg.set_main_option(
            "sqlalchemy.url",
            f"sqlite:///{copy_path.as_posix()}",
        )

        from app import create_app

        app = create_app(
            "development",
            test_config={
                "SQLALCHEMY_DATABASE_URI": f"sqlite:///{copy_path.as_posix()}"
            },
        )

        print("Applying Alembic migrations to 'head'...")
        with app.app_context():
            command.upgrade(alembic_cfg, "head")
        print("Alembic upgrade completed.")

        print("Executing post-migration integrity assertions...")
        verify_database_integrity(copy_path)
        print("=== Migration on copy verification SUCCESSFUL ===")
        return 0

    except (RuntimeError, sqlite3.Error, OSError) as exc:
        print(f"ERROR: Migration on copy failed: {exc}", file=sys.stderr)
        return 1

    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
