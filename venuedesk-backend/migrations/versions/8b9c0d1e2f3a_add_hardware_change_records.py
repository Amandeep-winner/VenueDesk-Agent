"""Add hardware_change_records table for historical evidence preservation.

Revision ID: 8b9c0d1e2f3a
Revises: 7a8c9e0d1f2a
Create Date: 2026-10-14 02:40:00.000000
"""
import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "8b9c0d1e2f3a"
down_revision = "7a8c9e0d1f2a"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "hardware_change_records",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("device_id", sa.Integer(), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("field", sa.String(length=64), nullable=False),
        sa.Column("previous_value", sa.Text(), nullable=True),
        sa.Column("new_value", sa.Text(), nullable=True),
        sa.Column("evidence_source", sa.String(length=32), nullable=False),
        sa.Column("reconciliation_decision", sa.String(length=64), nullable=False),
        sa.Column("requires_approval", sa.Boolean(), nullable=False, server_default=sa.text("0")),
        sa.Column("approved_by", sa.String(length=128), nullable=True),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("audit_log_id", sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(["device_id"], ["physical_devices.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["audit_log_id"], ["audit_logs.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_hardware_change_records_device_id", "hardware_change_records", ["device_id"], unique=False)


def downgrade():
    op.drop_index("ix_hardware_change_records_device_id", table_name="hardware_change_records")
    op.drop_table("hardware_change_records")
