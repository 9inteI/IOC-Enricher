"""AlienVault OTX provider. Supports all IOC types."""

from __future__ import annotations

import hashlib

import httpx

from ..models import IOC, IOCType, ProviderResult, ProviderStatus
from .base import NotFound, Provider, from_iso

_BASE = "https://otx.alienvault.com/api/v1"

_SECTIONS = {
    IOCType.IP: "IPv4",
    IOCType.DOMAIN: "domain",
    IOCType.URL: "url",
    IOCType.HASH: "file",
}


class OTXProvider(Provider):
    name = "AlienVault OTX"
    env_key = "OTX_API_KEY"
    supported_types = frozenset(IOCType)

    async def fetch(self, client: httpx.AsyncClient, ioc: IOC) -> ProviderResult:
        section = _SECTIONS[ioc.type]
        value = ioc.value
        if ioc.type is IOCType.IP and ":" in ioc.value:
            section = "IPv6"

        resp = await client.get(
            f"{_BASE}/indicators/{section}/{value}/general",
            headers={"X-OTX-API-KEY": self.api_key},
        )
        if resp.status_code == 404:
            raise NotFound
        resp.raise_for_status()
        data = resp.json()

        pulse_info = data.get("pulse_info", {})
        pulses = pulse_info.get("pulses", [])
        count = pulse_info.get("count", len(pulses))

        categories = sorted(
            {
                tag.lower()
                for pulse in pulses[:20]
                for tag in pulse.get("tags", [])
            }
        )[:15]

        created = sorted(filter(None, (from_iso(p.get("created")) for p in pulses)))
        modified = sorted(filter(None, (from_iso(p.get("modified")) for p in pulses)))

        malware_families = sorted(
            {
                family.get("display_name", "")
                for pulse in pulses
                for family in pulse.get("malware_families", [])
            }
            - {""}
        )
        categories = sorted(set(categories) | set(malware_families))[:15]

        # OTX has no numeric verdict; scale pulse count into a soft score.
        score = min(100.0, count * 10.0) if count else 0.0

        return ProviderResult(
            provider=self.name,
            status=ProviderStatus.OK,
            score=score,
            categories=categories,
            first_seen=created[0] if created else None,
            last_seen=modified[-1] if modified else None,
            detail=f"appears in {count} pulses",
            link=self._link(ioc),
        )

    @staticmethod
    def _link(ioc: IOC) -> str:
        if ioc.type is IOCType.URL:
            digest = hashlib.md5(ioc.value.encode()).hexdigest()
            return f"https://otx.alienvault.com/indicator/url/{digest}"
        kind = {"ip": "ip", "domain": "domain", "hash": "file"}[ioc.type.value]
        return f"https://otx.alienvault.com/indicator/{kind}/{ioc.value}"
