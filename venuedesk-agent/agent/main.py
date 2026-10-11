"""VenueDesk Agent Command-Line Interface."""
import json
from pathlib import Path

import click

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
    click.echo("Starting VenueDesk Agent daemon...")


@cli.command()
@click.option("--server", "-s", default=None, help="Control plane server URL")
@click.option("--token", "-t", default=None, help="One-time pairing token (PAIR-...)")
@click.option("--force-reenroll", is_flag=True, default=False, help="Force new enrollment even if already enrolled")
@click.pass_context
def enroll(ctx: click.Context, server: str | None, token: str | None, force_reenroll: bool) -> None:
    """Enroll this endpoint with the VenueDesk control plane."""
    click.echo("Enrollment command initialized.")


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
@click.pass_context
def recover(ctx: click.Context) -> None:
    """Attempt recovery workflow following OS reinstall or state loss."""
    click.echo("Initiating endpoint recovery workflow...")


@cli.command("rotate-credential")
@click.pass_context
def rotate_credential_cmd(ctx: click.Context) -> None:
    """Generate new key pair and request credential rotation from control plane."""
    click.echo("Initiating credential rotation...")


@cli.command("collect-once")
@click.pass_context
def collect_once(ctx: click.Context) -> None:
    """Run one collection cycle of inventory and telemetry to stdout."""
    click.echo("Running single collection cycle...")


if __name__ == "__main__":
    cli()
