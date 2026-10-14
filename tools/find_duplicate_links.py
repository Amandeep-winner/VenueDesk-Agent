"""Tool to find duplicate ACTIVE asset-device links before running migrations."""

import os
import sys

backend_path = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "venuedesk-backend"
)
if backend_path not in sys.path:
    sys.path.insert(0, backend_path)

from app import create_app
from app.extensions import db
from sqlalchemy import text


def find_duplicate_links():
    app = create_app()
    with app.app_context():
        # Check duplicate ACTIVE links per asset
        asset_dups = db.session.execute(
            text(
                "SELECT asset_id, COUNT(*) as cnt "
                "FROM asset_device_links "
                "WHERE relationship_status = 'ACTIVE' "
                "GROUP BY asset_id HAVING COUNT(*) > 1"
            )
        ).fetchall()

        # Check duplicate ACTIVE links per device
        device_dups = db.session.execute(
            text(
                "SELECT device_id, COUNT(*) as cnt "
                "FROM asset_device_links "
                "WHERE relationship_status = 'ACTIVE' "
                "GROUP BY device_id HAVING COUNT(*) > 1"
            )
        ).fetchall()

        has_duplicates = False
        if asset_dups:
            has_duplicates = True
            print("ERROR: Duplicate ACTIVE links found for assets:")
            for row in asset_dups:
                print(f"  Asset ID: {row[0]}, Active Link Count: {row[1]}")

        if device_dups:
            has_duplicates = True
            print("ERROR: Duplicate ACTIVE links found for devices:")
            for row in device_dups:
                print(f"  Device ID: {row[0]}, Active Link Count: {row[1]}")

        if not has_duplicates:
            print("OK: No duplicate ACTIVE links found in asset_device_links.")
            return 0
        else:
            print(
                "\nPlease resolve duplicate links per docs/RUNBOOK.md before applying migration."
            )
            return 1


if __name__ == "__main__":
    sys.exit(find_duplicate_links())
