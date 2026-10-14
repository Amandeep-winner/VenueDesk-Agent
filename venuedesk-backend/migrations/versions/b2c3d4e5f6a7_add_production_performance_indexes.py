"""Add production performance indexes on device_events, physical_devices, and asset_device_links.

Revision ID: b2c3d4e5f6a7
Revises: a1b2c3d4e5f6
Create Date: 2026-10-14 04:00:00.000000

"""

from alembic import op

# revision identifiers, used by Alembic.
revision = "b2c3d4e5f6a7"
down_revision = "a1b2c3d4e5f6"
branch_labels = None
depends_on = None


def upgrade():
    op.create_index(
        "idx_device_events_device_occurred",
        "device_events",
        ["device_id", "occurred_at"],
        unique=False,
    )
    op.create_index(
        "idx_physical_devices_status_last_seen",
        "physical_devices",
        ["status", "last_seen"],
        unique=False,
    )
    op.create_index(
        "idx_asset_device_links_asset_status",
        "asset_device_links",
        ["asset_id", "relationship_status"],
        unique=False,
    )


def downgrade():
    op.drop_index("idx_asset_device_links_asset_status", table_name="asset_device_links")
    op.drop_index("idx_physical_devices_status_last_seen", table_name="physical_devices")
    op.drop_index("idx_device_events_device_occurred", table_name="device_events")
