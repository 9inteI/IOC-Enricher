"""VirusTotal v3 API provider. Supports all IOC types."""

from __future__ import annotations

import base64

import httpx

from ..models import IOC, IOCType, ProviderResult, ProviderStatus
from .base import NotFound, Provider, from_timestamp

_BASE = "https://www.virustotal.com/api/v3"

_ENDPOINTS = {
    IOCType.IP: "ip_addresses",
    IOCType.DOMAIN: "domains",
    IOCType.URL: "urls",
    IOCType.HASH: "files",
}


class VirusTotalProvider(Provider):
    name = "VirusTotal"
    env_key = "VT_API_KEY"
    supported_types = frozenset(IOCType)

    async def fetch(self, client: httpx.AsyncClient, ioc: IOC) -> ProviderResult:
        identifier = ioc.value
        if ioc.type is IOCType.URL:
            # VT identifies URLs by unpadded url-safe base64 of the URL itself.
            identifier = base64.urlsafe_b64encode(ioc.value.encode()).decode().rstrip("=")

        resp = await client.get(
            f"{_BASE}/{_ENDPOINTS[ioc.type]}/{identifier}",
            headers={"x-apikey": self.api_key},
        )
        if resp.status_code == 404:
            raise NotFound
        resp.raise_for_status()
        attrs = resp.json()["data"]["attributes"]

        stats = attrs.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total = sum(stats.values()) or 1
        score = round(100 * (malicious + 0.5 * suspicious) / total, 1)

        categories: list[str] = []
        if ioc.type is IOCType.HASH:
            label = attrs.get("popular_threat_classification", {}).get(
                "suggested_threat_label"
            )
            if label:
                categories.append(label)
        else:
            categories.extend(set(attrs.get("categories", {}).values()))

        return ProviderResult(
            provider=self.name,
            status=ProviderStatus.OK,
            score=score,
            categories=sorted(categories),
            first_seen=from_timestamp(
                attrs.get("first_submission_date") or attrs.get("creation_date")
            ),
            last_seen=from_timestamp(attrs.get("last_analysis_date")),
            detail=f"{malicious}/{total} engines flagged malicious",
            link=f"https://www.virustotal.com/gui/search/{ioc.value}",
        )
