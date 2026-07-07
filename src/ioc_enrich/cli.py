"""ioc-enrich command line interface."""

from __future__ import annotations

import asyncio
import sys

import typer
from rich.console import Console

from . import __version__
from .aggregate import enrich
from .detect import detect_ioc
from .models import ProviderStatus
from .output import render_json, render_stix, render_table

app = typer.Typer(
    add_completion=False,
    help="Enrich an indicator of compromise with a unified threat-intel verdict.",
)
console = Console()
err_console = Console(stderr=True)


def _version_callback(value: bool) -> None:
    if value:
        console.print(f"ioc-enrich {__version__}")
        raise typer.Exit()


@app.command()
def main(
    indicator: str = typer.Argument(
        ..., help="IP, domain, URL, or file hash (type is auto-detected)."
    ),
    json_output: bool = typer.Option(
        False, "--json", help="Output the verdict as JSON."
    ),
    stix_output: bool = typer.Option(
        False, "--stix", help="Output the verdict as a STIX 2.1 bundle."
    ),
    version: bool = typer.Option(
        False, "--version", callback=_version_callback, is_eager=True
    ),
) -> None:
    """Query VirusTotal, AbuseIPDB, Shodan and AlienVault OTX concurrently."""
    if json_output and stix_output:
        err_console.print("[red]--json and --stix are mutually exclusive[/red]")
        raise typer.Exit(code=2)

    try:
        ioc = detect_ioc(indicator)
    except ValueError as exc:
        err_console.print(f"[red]error:[/red] {exc}")
        raise typer.Exit(code=2)

    verdict = asyncio.run(enrich(ioc))

    if json_output:
        print(render_json(verdict))
    elif stix_output:
        print(render_stix(verdict))
    else:
        render_table(verdict, console)
        skipped = [
            s for s in verdict.sources if s.status is ProviderStatus.NO_KEY
        ]
        if skipped:
            err_console.print(
                "[dim]hint: "
                + "; ".join(f"{s.provider}: {s.detail}" for s in skipped)
                + "[/dim]"
            )

    if not any(s.status is ProviderStatus.OK for s in verdict.sources):
        err_console.print(
            "[yellow]warning: no provider returned data "
            "(check API keys and connectivity)[/yellow]"
        )
        sys.exit(1)


if __name__ == "__main__":
    app()
