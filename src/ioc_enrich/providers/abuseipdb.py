"""AbuseIPDB provider. IP addresses only."""

from __future__ import annotations

import httpx

from ..models import IOC, IOCType, ProviderResult, ProviderStatus
from .base import NotFound, Provider, from_iso

_BASE = "https://api.abuseipdb.com/api/v2"

# https://www.abuseipdb.com/categories
_CATEGORIES = {
    1: "dns-compromise", 2: "dns-poisoning", 3: "fraud-orders", 4: "ddos-attack",
    5: "ftp-brute-force", 6: "ping-of-death", 7: "phishing", 8: "fraud-voip",
    9: "open-proxy", 10: "web-spam", 11: "email-spam", 12: "blog-spam",
    13: "vpn-ip", 14: "port-scan", 15: "hacking", 16: "sql-injection",
    17: "spoofing", 18: "brute-force", 19: "bad-web-bot", 20: "exploited-host",
    21: "web-app-attack", 22: "ssh", 23: "iot-targeted",
}


class AbuseIPDBProvider(Provider):
    name = "AbuseIPDB"
    env_key = "ABUSEIPDB_API_KEY"
    supported_types = frozenset({IOCType.IP})

    async def fetch(self, client: httpx.AsyncClient, ioc: IOC) -> ProviderResult:
        resp = await client.get(
            f"{_BASE}/check",
            params={"ipAddress": ioc.value, "maxAgeInDays": 365, "verbose": ""},
            headers={"Key": self.api_key, "Accept": "application/json"},
        )
        if resp.status_code == 404:
            raise NotFound
        resp.raise_for_status()
        data = resp.json()["data"]

        category_ids = {
            cat
            for report in data.get("reports", [])
            for cat in report.get("categories", [])
        }
        categories = sorted(
            _CATEGORIES.get(cat, f"category-{cat}") for cat in category_ids
        )

        reports = data.get("totalReports", 0)
        return ProviderResult(
            provider=self.name,
            status=ProviderStatus.OK,
            score=float(data.get("abuseConfidenceScore", 0)),
            categories=categories,
            last_seen=from_iso(data.get("lastReportedAt")),
            detail=f"{reports} reports from {data.get('numDistinctUsers', 0)} users",
            link=f"https://www.abuseipdb.com/check/{ioc.value}",
        )
