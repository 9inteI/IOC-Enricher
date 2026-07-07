"""Verdict renderers: rich table (default), JSON, and STIX 2.1 bundle."""

from __future__ import annotations

import json

from rich.console import Console
from rich.table import Table

from .models import IOCType, ProviderStatus, Verdict

_LABEL_STYLE = {
    "malicious": "bold red",
    "suspicious": "bold yellow",
    "clean": "bold green",
    "unknown": "dim",
}

_STATUS_TEXT = {
    ProviderStatus.OK: "[green]ok[/green]",
    ProviderStatus.NO_KEY: "[dim]skipped (no key)[/dim]",
    ProviderStatus.NOT_FOUND: "[cyan]not found[/cyan]",
    ProviderStatus.UNSUPPORTED: "[dim]n/a[/dim]",
    ProviderStatus.ERROR: "[red]error[/red]",
}


def render_table(verdict: Verdict, console: Console) -> None:
    style = _LABEL_STYLE[verdict.label]
    score = f"{verdict.score:g}/100" if verdict.score is not None else "-"
    console.print(
        f"\n[bold]{verdict.ioc.value}[/bold] "
        f"([italic]{verdict.ioc.type.value}[/italic]) — "
        f"[{style}]{verdict.label.upper()}[/{style}] {score}\n"
    )

    table = Table(show_lines=False)
    table.add_column("Source", style="bold")
    table.add_column("Status")
    table.add_column("Score", justify="right")
    table.add_column("Categories", max_width=40)
    table.add_column("Detail", max_width=50)

    for src in verdict.sources:
        table.add_row(
            src.provider,
            _STATUS_TEXT[src.status],
            f"{src.score:g}" if src.score is not None else "-",
            ", ".join(src.categories) or "-",
            src.detail or "-",
        )
    console.print(table)

    meta = []
    if verdict.first_seen:
        meta.append(f"first seen {verdict.first_seen:%Y-%m-%d}")
    if verdict.last_seen:
        meta.append(f"last seen {verdict.last_seen:%Y-%m-%d}")
    if verdict.related_iocs:
        meta.append(
            "related: " + ", ".join(r.value for r in verdict.related_iocs[:10])
        )
    if meta:
        console.print("[dim]" + " | ".join(meta) + "[/dim]")


def render_json(verdict: Verdict) -> str:
    return verdict.model_dump_json(indent=2)


_STIX_PATTERN = {
    IOCType.IP: "[ipv4-addr:value = '{v}']",
    IOCType.DOMAIN: "[domain-name:value = '{v}']",
    IOCType.URL: "[url:value = '{v}']",
}

_HASH_ALGO = {32: "MD5", 40: "SHA-1", 64: "SHA-256"}


def render_stix(verdict: Verdict) -> str:
    """Export the verdict as a STIX 2.1 bundle (JSON string)."""
    import stix2

    ioc = verdict.ioc
    if ioc.type is IOCType.HASH:
        algo = _HASH_ALGO[len(ioc.value)]
        pattern = f"[file:hashes.'{algo}' = '{ioc.value}']"
    else:
        pattern = _STIX_PATTERN[ioc.type].format(v=ioc.value)

    labels = [verdict.label] if verdict.label != "unknown" else []
    kwargs = {}
    if verdict.first_seen:
        kwargs["valid_from"] = verdict.first_seen

    indicator = stix2.Indicator(
        name=f"ioc-enrich verdict for {ioc.value}",
        description=(
            f"Unified verdict {verdict.label}"
            + (f" (score {verdict.score}/100)" if verdict.score is not None else "")
            + ". Sources: "
            + ", ".join(
                s.provider for s in verdict.sources if s.status is ProviderStatus.OK
            )
        ),
        pattern=pattern,
        pattern_type="stix",
        labels=labels or None,
        confidence=int(verdict.score) if verdict.score is not None else None,
        **kwargs,
    )

    objects: list = [indicator]
    for rel in verdict.related_iocs:
        if rel.type in _STIX_PATTERN:
            objects.append(
                stix2.Indicator(
                    name=f"related IOC of {ioc.value}",
                    pattern=_STIX_PATTERN[rel.type].format(v=rel.value),
                    pattern_type="stix",
                )
            )

    bundle = stix2.Bundle(objects=objects)
    return json.dumps(json.loads(bundle.serialize()), indent=2)
