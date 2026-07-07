"""Run all providers concurrently and merge their results into one Verdict."""

from __future__ import annotations

import asyncio

import httpx

from .models import IOC, ProviderResult, ProviderStatus, Verdict
from .providers import ALL_PROVIDERS, Provider

_TIMEOUT = httpx.Timeout(15.0)

# Weight per provider when averaging scores; Shodan is context-only unless it
# tags the host as malicious, so it weighs less.
_WEIGHTS = {"VirusTotal": 1.0, "AbuseIPDB": 1.0, "AlienVault OTX": 0.6, "Shodan": 0.5}


def label_for(score: float | None) -> str:
    if score is None:
        return "unknown"
    if score >= 60:
        return "malicious"
    if score >= 25:
        return "suspicious"
    return "clean"


async def enrich(ioc: IOC, providers: list[Provider] | None = None) -> Verdict:
    """Query every provider concurrently and aggregate into a Verdict."""
    providers = providers if providers is not None else [p() for p in ALL_PROVIDERS]

    async with httpx.AsyncClient(timeout=_TIMEOUT, follow_redirects=True) as client:
        results = await asyncio.gather(*(p.run(client, ioc) for p in providers))

    return merge(ioc, list(results))


def merge(ioc: IOC, results: list[ProviderResult]) -> Verdict:
    scored = [
        r for r in results if r.status is ProviderStatus.OK and r.score is not None
    ]

    score: float | None = None
    if scored:
        total_weight = sum(_WEIGHTS.get(r.provider, 1.0) for r in scored)
        score = round(
            sum(r.score * _WEIGHTS.get(r.provider, 1.0) for r in scored)
            / total_weight,
            1,
        )

    ok = [r for r in results if r.status is ProviderStatus.OK]
    categories = sorted({c for r in ok for c in r.categories})

    first_seen = min((r.first_seen for r in ok if r.first_seen), default=None)
    last_seen = max((r.last_seen for r in ok if r.last_seen), default=None)

    seen_related: set[tuple[str, str]] = set()
    related = []
    for r in ok:
        for rel in r.related_iocs:
            key = (rel.type.value, rel.value)
            if key not in seen_related:
                seen_related.add(key)
                related.append(rel)

    return Verdict(
        ioc=ioc,
        score=score,
        label=label_for(score),
        categories=categories,
        first_seen=first_seen,
        last_seen=last_seen,
        related_iocs=related,
        sources=results,
    )
