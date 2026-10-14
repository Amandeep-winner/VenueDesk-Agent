"""Add partial unique indexes on asset_device_links for single active link per asset and per device.

Revision ID: 7a8c9e0d1f2a
Revises: 5e2bb272925c
Create Date: 2026-10-14 01:52:00.000000
"""

from alembic import op
from sqlalchemy import text

# revision identifiers, used by Alembic.
revision = "7a8c9e0d1f2a"
down_revision = "5e2bb272925c"
branch_labels = None
depends_on = None


def upgrade():
    # 1. Check for existing duplicate ACTIVE links before applying index
    conn = op.get_bind()
    asset_dups = conn.execute(
        text(
            "SELECT asset_id, COUNT(*) as cnt "
            "FROM asset_device_links "
            "WHERE relationship_status = 'ACTIVE' "
            "GROUP BY asset_id HAVING COUNT(*) > 1"
        )
    ).fetchall()
    device_dups = conn.execute(
        text(
            "SELECT device_id, COUNT(*) as cnt "
            "FROM asset_device_links "
            "WHERE relationship_status = 'ACTIVE' "
            "GROUP BY device_id HAVING COUNT(*) > 1"
        )
    ).fetchall()

    if asset_dups or device_dups:
        msg = ["Cannot apply migration: duplicate ACTIVE links exist in asset_device_links:"]
        for row in asset_dups:
            msg.append(f"  Asset ID {row[0]} has {row[1]} active links")
        for row in device_dups:
            msg.append(f"  Device ID {row[0]} has {row[1]} active links")
        msg.append(
            "Please run tools/find_duplicate_links.py and follow docs/RUNBOOK.md to clean them up."
        )
        raise RuntimeError("\n".join(msg))

    # 2. Create partial unique indexes
    op.create_index(
        "uq_active_link_per_asset",
        "asset_device_links",
        ["asset_id"],
        unique=True,
        sqlite_where=text("relationship_status = 'ACTIVE'"),
        postgresql_where=text("relationship_status = 'ACTIVE'"),
    )
    op.create_index(
        "uq_active_link_per_device",
        "asset_device_links",
        ["device_id"],
        unique=True,
        sqlite_where=text("relationship_status = 'ACTIVE'"),
        postgresql_where=text("relationship_status = 'ACTIVE'"),
    )


def downgrade():
    op.drop_index("uq_active_link_per_device", table_name="asset_device_links")
    op.drop_index("uq_active_link_per_asset", table_name="asset_device_links")
