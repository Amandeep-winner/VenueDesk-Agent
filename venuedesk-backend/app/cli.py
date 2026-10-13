"""Flask CLI management commands."""
import click
from flask.cli import with_appcontext

from app.extensions import db
from app.models import (
    Asset,
    AssetLifecycleStatus,
    AssetType,
    User,
    UserRole,
    generate_next_asset_id,
)


@click.command("seed-demo")
@with_appcontext
def seed_demo_command():
    """Seed initial demonstration assets and default administrative user."""
    # Ensure default admin exists
    admin = User.query.filter_by(username="admin").first()
    if not admin:
        admin = User(username="admin", role=UserRole.INFRA_ADMIN)
        admin.set_password("admin123")
        db.session.add(admin)
        click.echo("Created default admin user (admin / admin123).")

    # Seed AI-LAB-PC-07
    asset1 = Asset.query.filter_by(asset_tag="AI-LAB-PC-07").first()
    if not asset1:
        asset1 = Asset(
            asset_id=generate_next_asset_id(db.session),
            asset_tag="AI-LAB-PC-07",
            asset_type=AssetType.DESKTOP,
            department_id="AI_DEPT",
            building_id="ACADEMIC_BLOCK_A",
            room_id="AI_LAB_101",
            location_label="Academic Block A, Room 101",
            position_label="Desk 07",
            lifecycle_status=AssetLifecycleStatus.DRAFT
        )
        db.session.add(asset1)
        click.echo(f"Created demo asset AI-LAB-PC-07 with ID {asset1.asset_id}.")

    # Seed CSE-LAB-PC-12
    asset2 = Asset.query.filter_by(asset_tag="CSE-LAB-PC-12").first()
    if not asset2:
        asset2 = Asset(
            asset_id=generate_next_asset_id(db.session),
            asset_tag="CSE-LAB-PC-12",
            asset_type=AssetType.DESKTOP,
            department_id="CSE_DEPT",
            building_id="ACADEMIC_BLOCK_B",
            room_id="CSE_LAB_204",
            location_label="Academic Block B, Room 204",
            position_label="Desk 12",
            lifecycle_status=AssetLifecycleStatus.DRAFT
        )
        db.session.add(asset2)
        click.echo(f"Created demo asset CSE-LAB-PC-12 with ID {asset2.asset_id}.")

    db.session.commit()
    click.echo("Seed demo completed successfully.")


@click.command("create-admin")
@click.option("--username", prompt=True, help="Admin username")
@click.option("--password", prompt=True, hide_input=True, confirmation_prompt=True, help="Admin password")
@with_appcontext
def create_admin_command(username, password):
    """Create a new administrative user."""
    existing = User.query.filter_by(username=username).first()
    if existing:
        click.echo(f"User {username} already exists.", err=True)
        return

    user = User(username=username, role=UserRole.INFRA_ADMIN)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()
    click.echo(f"Successfully created admin user {username}.")


@click.command("mark-offline")
@click.option("--interval", default=60, help="Heartbeat interval in seconds (default 60)")
@with_appcontext
def mark_offline_command(interval):
    """Mark devices that have missed heartbeats as OFFLINE."""
    from app.services.device_service import mark_offline_devices
    marked = mark_offline_devices(heartbeat_interval_seconds=interval)
    click.echo(f"Marked {len(marked)} devices as OFFLINE: {marked}")


@click.command("purge-telemetry")
@click.option("--older-than-days", default=30, type=int, help="Retention window threshold in days (default 30)")
@with_appcontext
def purge_telemetry_command(older_than_days):
    """Purge high-frequency telemetry records older than retention threshold."""
    from app.services.telemetry_service import purge_telemetry
    deleted = purge_telemetry(older_than_days=older_than_days)
    click.echo(f"Purged {deleted} telemetry records older than {older_than_days} days.")


@click.command("purge-nonces")
@with_appcontext
def purge_nonces_command():
    """Purge expired request nonces."""
    from app.security.replay import purge_expired_nonces
    deleted = purge_expired_nonces()
    click.echo(f"Purged {deleted} expired request nonces.")


def register_cli_commands(app):
    """Register CLI commands with the Flask application."""
    app.cli.add_command(seed_demo_command)
    app.cli.add_command(create_admin_command)
    app.cli.add_command(mark_offline_command)
    app.cli.add_command(purge_telemetry_command)
    app.cli.add_command(purge_nonces_command)
