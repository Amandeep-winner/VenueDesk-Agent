import json
import logging
from pathlib import Path

import click

logger = logging.getLogger(__name__)

from agent.collectors import collect_identity_evidence
from agent.config import AgentConfig
from agent.identity.device_id import IdentityStore
from agent.identity.keys import export_public_key_b64, get_keystore, load_or_create_key
from agent.logging_setup import setup_logging
from agent.storage.database import AgentDatabase


def output_identity(config: AgentConfig) -> None:
    """Collect and output local identity evidence JSON (hashes only, no private key)."""
    db_path = Path(config.state_dir) / "agent_state.db"
    db = AgentDatabase(db_path)
    id_store = IdentityStore(db)
    keystore = get_keystore(config)
    key = load_or_create_key(keystore)
    pub_key_b64 = export_public_key_b64(key)

    evidence = collect_identity_evidence()
    payload = evidence.to_evidence_payload(config.deployment_salt)
    payload["agent_instance_id"] = id_store.agent_instance_id
    payload["os_installation_id"] = id_store.os_installation_id
    payload["device_id"] = id_store.device_id
    payload["device_public_key"] = pub_key_b64
    payload["strong_anchors"] = sorted(evidence.strong_anchors())

    click.echo(json.dumps(payload, indent=2))


@click.group(invoke_without_command=True)
@click.option("--config", "-c", "config_file", type=click.Path(exists=True), help="Path to config.toml")
@click.option("--print-identity", "flag_print_identity", is_flag=True, help="Print identity evidence JSON and exit")
@click.pass_context
def cli(ctx: click.Context, config_file: str | None, flag_print_identity: bool) -> None:
    """VenueDesk Endpoint Agent CLI."""
    ctx.ensure_object(dict)
    config = AgentConfig.load(config_file)
    setup_logging(log_level=config.log_level)
    ctx.obj["config"] = config

    if flag_print_identity:
        output_identity(config)
        ctx.exit(0)

    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


@cli.command()
@click.pass_context
def run(ctx: click.Context) -> None:
    """Start the agent daemon service."""
    config: AgentConfig = ctx.obj["config"]
    click.echo("Starting VenueDesk Agent daemon...")

    from pathlib import Path

    from agent.identity.device_id import IdentityStore
    from agent.identity.keys import get_keystore
    from agent.storage.database import AgentDatabase

    db_path = Path(config.state_dir) / "agent_state.db"
    db = AgentDatabase(db_path)
    id_store = IdentityStore(db)
    keystore = get_keystore(config)

    if (not id_store.is_enrolled() or not keystore.has_key()) and config.server_url and not config.pairing_token:
        logger.info("Agent state or key missing. Entering awaiting recovery mode...")
        click.echo("Awaiting administrator recovery approval...")
        try:
            from agent.communication.recovery import recover_agent
            result = recover_agent(config, wait_for_approval=True, poll_timeout_seconds=300)
            click.echo(f"Recovery approved! Enrolled device: {result.get('device_id')}")
        except (RuntimeError, ValueError, TimeoutError, OSError) as exc:
            logger.warning("Recovery polling ended: %s", exc)
            return


@cli.command()
@click.option("--server", "-s", default=None, help="Control plane server URL")
@click.option("--token", "-t", default=None, help="One-time pairing token (PAIR-...)")
@click.option("--force-reenroll", is_flag=True, default=False, help="Force new enrollment even if already enrolled")
@click.pass_context
def enroll(ctx: click.Context, server: str | None, token: str | None, force_reenroll: bool) -> None:
    """Enroll this endpoint with the VenueDesk control plane."""
    config: AgentConfig = ctx.obj["config"]
    try:
        from agent.communication.enrollment import enroll_agent
        result = enroll_agent(config, token=token, force_reenroll=force_reenroll, server_url=server)
        click.echo(f"Successfully enrolled device: {result['device_id']} (Status: {result['status']})")
    except (RuntimeError, ValueError, OSError) as exc:
        click.echo(f"Enrollment error: {exc}", err=True)
        ctx.exit(1)


@cli.command()
@click.pass_context
def status(ctx: click.Context) -> None:
    """Display current local agent status and enrollment."""
    click.echo("Agent Status: initialized (pending enrollment).")


@cli.command("print-identity")
@click.pass_context
def print_identity_cmd(ctx: click.Context) -> None:
    """Print local identity evidence and fingerprint without exposing private keys."""
    config: AgentConfig = ctx.obj["config"]
    output_identity(config)


@cli.command()
@click.option("--server", "-s", default=None, help="Control plane server URL")
@click.option("--wait", is_flag=True, default=False, help="Wait and poll for administrator approval")
@click.option("--timeout", default=60, help="Polling timeout in seconds")
@click.pass_context
def recover(ctx: click.Context, server: str | None, wait: bool, timeout: int) -> None:
    """Attempt recovery workflow following OS reinstall or state loss."""
    config: AgentConfig = ctx.obj["config"]
    try:
        from agent.communication.recovery import recover_agent
        result = recover_agent(
            config,
            server_url=server,
            wait_for_approval=wait,
            poll_timeout_seconds=timeout,
        )
        click.echo(f"Recovery request status: {result['status']} (Device ID: {result.get('device_id')})")
    except (RuntimeError, ValueError, TimeoutError, OSError) as exc:
        click.echo(f"Recovery error: {exc}", err=True)
        ctx.exit(1)


@cli.command("rotate-credential")
@click.pass_context
def rotate_credential_cmd(ctx: click.Context) -> None:
    """Generate new key pair and request credential rotation from control plane."""
    config: AgentConfig = ctx.obj["config"]
    try:
        from agent.communication.client import AuthenticatedClient
        client = AuthenticatedClient(config)
        res = client.rotate_credential()
        click.echo(f"Successfully rotated credential to version {res.get('credential_version')}.")
    except (RuntimeError, ValueError, OSError) as exc:
        click.echo(f"Credential rotation error: {exc}", err=True)
        ctx.exit(1)


@cli.command("collect-once")
@click.pass_context
def collect_once(ctx: click.Context) -> None:
    """Run one collection cycle of inventory and telemetry to stdout."""
    click.echo("Running single collection cycle...")


if __name__ == "__main__":
    cli()
