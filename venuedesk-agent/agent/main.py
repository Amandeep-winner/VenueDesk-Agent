"""VenueDesk Agent Command-Line Interface."""
import click

from agent.config import AgentConfig
from agent.logging_setup import setup_logging


@click.group()
@click.option("--config", "-c", "config_file", type=click.Path(exists=True), help="Path to config.toml")
@click.pass_context
def cli(ctx: click.Context, config_file: str | None) -> None:
    """VenueDesk Endpoint Agent CLI."""
    ctx.ensure_object(dict)
    config = AgentConfig.load(config_file)
    setup_logging(log_level=config.log_level)
    ctx.obj["config"] = config


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
def print_identity(ctx: click.Context) -> None:
    """Print local identity evidence and fingerprint without exposing private keys."""
    click.echo("Identity evidence viewer.")


@cli.command()
@click.pass_context
def recover(ctx: click.Context) -> None:
    """Attempt recovery workflow following OS reinstall or state loss."""
    click.echo("Initiating endpoint recovery workflow...")


@cli.command("rotate-credential")
@click.pass_context
def rotate_credential(ctx: click.Context) -> None:
    """Generate new key pair and request credential rotation from control plane."""
    click.echo("Initiating credential rotation...")


@cli.command("collect-once")
@click.pass_context
def collect_once(ctx: click.Context) -> None:
    """Run one collection cycle of inventory and telemetry to stdout."""
    click.echo("Running single collection cycle...")


if __name__ == "__main__":
    cli()
