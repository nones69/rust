"""Command-line interface for IP-Discrambler."""

import json
import sys
from pathlib import Path
from typing import List, Optional

import click
import yaml
from rich.console import Console
from rich.table import Table
from tabulate import tabulate

from .client import Discrambler
from .config import Config
from .models import IPResult


console = Console()


@click.group()
@click.option("--timeout", default=10.0, help="HTTP request timeout in seconds.")
@click.option("--concurrency", default=50, help="Maximum concurrent async workers.")
@click.option("--env-file", default=".env", help="Path to .env configuration file.")
@click.pass_context
def cli(ctx: click.Context, timeout: float, concurrency: int, env_file: str) -> None:
    """IP-Discrambler — IP enrichment and analysis CLI."""
    ctx.ensure_object(dict)
    ctx.obj["config"] = Config.from_env(env_file)
    ctx.obj["timeout"] = timeout
    ctx.obj["concurrency"] = concurrency


@cli.command()
@click.argument("ip", required=False)
@click.option("--file", "ip_file", type=click.Path(exists=True), help="File with one IP per line.")
@click.option("--output", default="table", type=click.Choice(["json", "csv", "yaml", "table"]))
@click.option("--no-rdns", is_flag=True, help="Skip reverse DNS lookups.")
@click.pass_context
def lookup(
    ctx: click.Context,
    ip: Optional[str],
    ip_file: Optional[str],
    output: str,
    no_rdns: bool,
) -> None:
    """Look up geolocation, WHOIS, and threat data for one or more IPs."""
    ips = _read_ips(ip, ip_file)
    if not ips:
        click.echo("Error: provide an IP argument or --file.", err=True)
        sys.exit(1)

    client = _make_client(ctx)
    results = client.lookup_batch_sync(ips, include_rdns=not no_rdns)
    _render(results, output)


@cli.command()
@click.argument("cidr")
@click.option("--expand", is_flag=True, help="List all usable host addresses.")
@click.option("--limit", default=256, help="Max hosts to expand.")
@click.pass_context
def subnet(ctx: click.Context, cidr: str, expand: bool, limit: int) -> None:
    """Analyze a CIDR subnet."""
    client = _make_client(ctx)
    summary = client.analyze_subnet(cidr, expand=expand, limit=limit)
    click.echo(json.dumps(summary.to_dict(), indent=2))


@cli.command()
@click.argument("ip")
@click.option(
    "--providers",
    default="abuseipdb,virustotal",
    help="Comma-separated threat provider names.",
)
@click.pass_context
def threat(ctx: click.Context, ip: str, providers: str) -> None:
    """Run a threat intelligence check for an IP."""
    config: Config = ctx.obj["config"]
    requested = {p.strip().lower() for p in providers.split(",")}
    available = {
        "abuseipdb": bool(config.abuseipdb_api_key),
        "virustotal": bool(config.virustotal_api_key),
        "shodan": bool(config.shodan_api_key),
    }
    enabled = {k for k, v in available.items() if v}
    to_query = requested & enabled
    missing = requested - enabled

    if missing:
        click.echo(f"Warning: providers without API keys configured: {', '.join(missing)}", err=True)

    client = _make_client(ctx)
    # Restrict providers to those requested.
    client.threat_providers = [p for p in client.threat_providers if p.__class__.__name__.lower().replace("provider", "") in to_query]
    results = client.lookup_batch_sync([ip])
    _render(results, "json")


def _make_client(ctx: click.Context) -> Discrambler:
    return Discrambler(
        timeout=ctx.obj["timeout"],
        max_concurrency=ctx.obj["concurrency"],
        config=ctx.obj["config"],
    )


def _read_ips(ip: Optional[str], ip_file: Optional[str]) -> List[str]:
    ips: List[str] = []
    if ip:
        ips.append(ip)
    if ip_file:
        text = Path(ip_file).read_text()
        for line in text.splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                ips.append(line)
    return ips


def _render(results: List[IPResult], output: str) -> None:
    if output == "json":
        click.echo(json.dumps([r.to_dict() for r in results], indent=2))
    elif output == "yaml":
        click.echo(yaml.safe_dump([r.to_dict() for r in results], sort_keys=False))
    elif output == "csv":
        _render_csv(results)
    else:
        _render_table(results)


def _render_csv(results: List[IPResult]) -> None:
    headers = ["ip", "country", "country_code", "city", "asn", "org", "reverse_dns", "threat_score"]
    rows = []
    for r in results:
        rows.append([r.ip, r.country, r.country_code, r.city, r.asn, r.org, r.reverse_dns, r.threat_score])
    click.echo(tabulate(rows, headers=headers, tablefmt="csv"))


def _render_table(results: List[IPResult]) -> None:
    table = Table(title="IP-Discrambler Results")
    table.add_column("IP")
    table.add_column("Country")
    table.add_column("City")
    table.add_column("ASN")
    table.add_column("Org")
    table.add_column("Reverse DNS")
    table.add_column("Threat")
    for r in results:
        table.add_row(
            r.ip,
            r.country or "-",
            r.city or "-",
            r.asn or "-",
            r.org or "-",
            r.reverse_dns or "-",
            str(r.threat_score),
        )
    console.print(table)


def main() -> None:
    cli()


if __name__ == "__main__":
    main()
