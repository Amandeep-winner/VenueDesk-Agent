"""Add processed_events table for server-side idempotency.

Revision ID: a1b2c3d4e5f6
Revises: 9c0d1e2f3a4b
Create Date: 2026-10-14 03:20:00.000000
"""
import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "a1b2c3d4e5f6"
down_revision = "9c0d1e2f3a4b"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "processed_events",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("device_id", sa.Integer(), nullable=False),
        sa.Column("event_id", sa.String(length=64), nullable=False),
        sa.Column("processed_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["device_id"], ["physical_devices.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("device_id", "event_id", name="uq_processed_events_device_event"),
    )
    op.create_index("ix_processed_events_device_id", "processed_events", ["device_id"], unique=False)
    op.create_index("ix_processed_events_event_id", "processed_events", ["event_id"], unique=False)
    op.create_index("idx_processed_events_device_time", "processed_events", ["device_id", "processed_at"], unique=False)


def downgrade():
    op.drop_index("idx_processed_events_device_time", table_name="processed_events")
    op.drop_index("ix_processed_events_event_id", table_name="processed_events")
    op.drop_index("ix_processed_events_device_id", table_name="processed_events")
    op.drop_table("processed_events")
