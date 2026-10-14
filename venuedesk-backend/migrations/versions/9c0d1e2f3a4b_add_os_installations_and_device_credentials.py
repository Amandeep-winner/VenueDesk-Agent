"""Add os_installation_id, device_credentials table, and device-scoped enrollment tokens.

Revision ID: 9c0d1e2f3a4b
Revises: 8b9c0d1e2f3a
Create Date: 2026-10-14 03:00:00.000000
"""

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "9c0d1e2f3a4b"
down_revision = "8b9c0d1e2f3a"
branch_labels = None
depends_on = None


def upgrade():
    # 1. Add os_installation_id to os_installations and backfill from agent_instance_id
    with op.batch_alter_table("os_installations") as batch_op:
        batch_op.add_column(sa.Column("os_installation_id", sa.String(length=64), nullable=True))
        batch_op.create_index(
            "ix_os_installations_os_installation_id", ["os_installation_id"], unique=False
        )
        batch_op.create_index(
            "ix_os_inst_device_os_inst_id", ["device_id", "os_installation_id"], unique=False
        )

    op.execute(
        "UPDATE os_installations SET os_installation_id = agent_instance_id WHERE os_installation_id IS NULL"
    )

    # 2. Add scope and device_id to enrollment_tokens, and allow nullable asset_id
    with op.batch_alter_table("enrollment_tokens") as batch_op:
        batch_op.add_column(
            sa.Column("scope", sa.String(length=32), nullable=False, server_default="ASSET")
        )
        batch_op.add_column(sa.Column("device_id", sa.Integer(), nullable=True))
        batch_op.alter_column("asset_id", existing_type=sa.Integer(), nullable=True)
        batch_op.create_foreign_key(
            "fk_enrollment_tokens_device_id",
            "physical_devices",
            ["device_id"],
            ["id"],
            ondelete="CASCADE",
        )
        batch_op.create_index("ix_enrollment_tokens_device_id", ["device_id"], unique=False)

    # 3. Create device_credentials table
    op.create_table(
        "device_credentials",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("device_id", sa.Integer(), nullable=False),
        sa.Column("os_installation_id", sa.String(length=64), nullable=True),
        sa.Column("public_key", sa.Text(), nullable=False),
        sa.Column("credential_version", sa.Integer(), nullable=False, server_default=sa.text("1")),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="ACTIVE"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["device_id"], ["physical_devices.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_device_credentials_device_id", "device_credentials", ["device_id"], unique=False
    )
    op.create_index(
        "ix_device_credentials_os_inst_id",
        "device_credentials",
        ["os_installation_id"],
        unique=False,
    )

    # Backfill device_credentials from existing physical_devices
    op.execute(
        """
        INSERT INTO device_credentials (device_id, public_key, credential_version, status, created_at)
        SELECT id, device_public_key, credential_version, 'ACTIVE', created_at
        FROM physical_devices
        WHERE device_public_key IS NOT NULL
        """
    )

    # 4. Add recovery request columns
    with op.batch_alter_table("device_recovery_requests") as batch_op:
        batch_op.add_column(sa.Column("candidate_device_id", sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column("evidence_snapshot_id", sa.Integer(), nullable=True))
        batch_op.add_column(
            sa.Column("new_os_installation_id", sa.String(length=64), nullable=True)
        )
        batch_op.add_column(sa.Column("reason", sa.String(length=256), nullable=True))
        batch_op.alter_column("device_id", existing_type=sa.Integer(), nullable=True)
        batch_op.create_foreign_key(
            "fk_recovery_candidate_device_id",
            "physical_devices",
            ["candidate_device_id"],
            ["id"],
            ondelete="CASCADE",
        )
        batch_op.create_foreign_key(
            "fk_recovery_evidence_snapshot_id",
            "device_identity_evidence",
            ["evidence_snapshot_id"],
            ["id"],
            ondelete="SET NULL",
        )
        batch_op.create_index(
            "ix_device_recovery_requests_candidate_id", ["candidate_device_id"], unique=False
        )


def downgrade():
    with op.batch_alter_table("device_recovery_requests") as batch_op:
        batch_op.drop_index("ix_device_recovery_requests_candidate_id")
        batch_op.drop_constraint("fk_recovery_evidence_snapshot_id", type_="foreignkey")
        batch_op.drop_constraint("fk_recovery_candidate_device_id", type_="foreignkey")
        batch_op.drop_column("reason")
        batch_op.drop_column("new_os_installation_id")
        batch_op.drop_column("evidence_snapshot_id")
        batch_op.drop_column("candidate_device_id")

    op.drop_index("ix_device_credentials_os_inst_id", table_name="device_credentials")
    op.drop_index("ix_device_credentials_device_id", table_name="device_credentials")
    op.drop_table("device_credentials")

    with op.batch_alter_table("enrollment_tokens") as batch_op:
        batch_op.drop_index("ix_enrollment_tokens_device_id")
        batch_op.drop_constraint("fk_enrollment_tokens_device_id", type_="foreignkey")
        batch_op.drop_column("device_id")
        batch_op.drop_column("scope")

    with op.batch_alter_table("os_installations") as batch_op:
        batch_op.drop_index("ix_os_inst_device_os_inst_id")
        batch_op.drop_index("ix_os_installations_os_installation_id")
        batch_op.drop_column("os_installation_id")
