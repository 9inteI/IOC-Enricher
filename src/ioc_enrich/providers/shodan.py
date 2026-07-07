"""Shodan provider. IP addresses only — contributes context, not a score."""

from __future__ import annotations

import httpx

from ..models import IOC, IOCType, ProviderResult, ProviderStatus
from .base import NotFound, Provider, from_iso

_BASE = "https://api.shodan.io"


class ShodanProvider(Provider):
    name = "Shodan"
    env_key = "SHODAN_API_KEY"
    supported_types = frozenset({IOCType.IP})

    async def fetch(self, client: httpx.AsyncClient, ioc: IOC) -> ProviderResult:
        resp = await client.get(
            f"{_BASE}/shodan/host/{ioc.value}",
            params={"key": self.api_key, "minify": "true"},
        )
        if resp.status_code == 404:
            raise NotFound
        resp.raise_for_status()
        data = resp.json()

        ports = sorted(data.get("ports", []))
        tags = sorted(data.get("tags", []))
        vulns = sorted(data.get("vulns", []))

        parts = []
        if ports:
            parts.append(f"open ports: {', '.join(map(str, ports[:10]))}")
        if data.get("org"):
            parts.append(f"org: {data['org']}")
        if vulns:
            parts.append(f"vulns: {', '.join(vulns[:5])}")

        # Shodan is an exposure index, not a reputation feed: only known
        # malicious tags translate into an opinionated score.
        score = None
        if {"malware", "botnet", "c2", "compromised"} & set(tags):
            score = 80.0

        return ProviderResult(
            provider=self.name,
            status=ProviderStatus.OK,
            score=score,
            categories=tags,
            last_seen=from_iso(data.get("last_update")),
            detail="; ".join(parts) or None,
            link=f"https://www.shodan.io/host/{ioc.value}",
        )
