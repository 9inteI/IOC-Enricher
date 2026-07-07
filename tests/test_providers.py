"""Provider tests with mocked HTTP responses (respx) — no live calls."""

import httpx
import pytest
import respx

from ioc_enrich.detect import detect_ioc
from ioc_enrich.models import ProviderStatus
from ioc_enrich.providers import (
    AbuseIPDBProvider,
    OTXProvider,
    ShodanProvider,
    VirusTotalProvider,
)

IP = detect_ioc("1.2.3.4")
DOMAIN = detect_ioc("evil.example")
HASH = detect_ioc("44d88612fea8a8f36de82e1278abb02f")


async def run(provider, ioc):
    async with httpx.AsyncClient() as client:
        return await provider.run(client, ioc)


VT_IP_BODY = {
    "data": {
        "attributes": {
            "last_analysis_stats": {"malicious": 6, "suspicious": 2, "harmless": 72},
            "last_analysis_date": 1717000000,
            "categories": {"vendor1": "malware"},
        }
    }
}


@respx.mock
async def test_virustotal_ok():
    respx.get("https://www.virustotal.com/api/v3/ip_addresses/1.2.3.4").respond(
        json=VT_IP_BODY
    )
    result = await run(VirusTotalProvider(), IP)
    assert result.status is ProviderStatus.OK
    assert result.score == pytest.approx(8.8, abs=0.1)  # (6 + 0.5*2)/80 * 100
    assert result.categories == ["malware"]


@respx.mock
async def test_virustotal_not_found():
    respx.get("https://www.virustotal.com/api/v3/domains/evil.example").respond(404)
    result = await run(VirusTotalProvider(), DOMAIN)
    assert result.status is ProviderStatus.NOT_FOUND


@respx.mock
async def test_virustotal_server_error_is_graceful():
    respx.get("https://www.virustotal.com/api/v3/files/" + HASH.value).respond(500)
    result = await run(VirusTotalProvider(), HASH)
    assert result.status is ProviderStatus.ERROR
    assert "500" in result.detail


@respx.mock
async def test_abuseipdb_ok():
    respx.get("https://api.abuseipdb.com/api/v2/check").respond(
        json={
            "data": {
                "abuseConfidenceScore": 97,
                "totalReports": 42,
                "numDistinctUsers": 10,
                "lastReportedAt": "2026-06-30T12:00:00+00:00",
                "reports": [{"categories": [18, 22]}],
            }
        }
    )
    result = await run(AbuseIPDBProvider(), IP)
    assert result.status is ProviderStatus.OK
    assert result.score == 97.0
    assert result.categories == ["brute-force", "ssh"]


async def test_abuseipdb_skips_domains():
    result = await run(AbuseIPDBProvider(), DOMAIN)
    assert result.status is ProviderStatus.UNSUPPORTED


@respx.mock
async def test_shodan_ok_without_malicious_tags():
    respx.get("https://api.shodan.io/shodan/host/1.2.3.4").respond(
        json={"ports": [22, 443], "tags": ["tor"], "org": "ExampleOrg"}
    )
    result = await run(ShodanProvider(), IP)
    assert result.status is ProviderStatus.OK
    assert result.score is None  # context-only
    assert "22" in result.detail


@respx.mock
async def test_shodan_scores_malicious_tags():
    respx.get("https://api.shodan.io/shodan/host/1.2.3.4").respond(
        json={"ports": [80], "tags": ["c2"]}
    )
    result = await run(ShodanProvider(), IP)
    assert result.score == 80.0


@respx.mock
async def test_otx_ok():
    respx.get(
        "https://otx.alienvault.com/api/v1/indicators/IPv4/1.2.3.4/general"
    ).respond(
        json={
            "pulse_info": {
                "count": 3,
                "pulses": [
                    {
                        "tags": ["botnet"],
                        "created": "2024-01-01T00:00:00",
                        "modified": "2026-01-01T00:00:00",
                        "malware_families": [{"display_name": "Mirai"}],
                    }
                ],
            }
        }
    )
    result = await run(OTXProvider(), IP)
    assert result.status is ProviderStatus.OK
    assert result.score == 30.0
    assert "Mirai" in result.categories
    assert result.first_seen.year == 2024


async def test_missing_key_is_skipped(monkeypatch):
    monkeypatch.delenv("VT_API_KEY")
    result = await run(VirusTotalProvider(), IP)
    assert result.status is ProviderStatus.NO_KEY


@respx.mock
async def test_network_error_is_graceful():
    respx.get("https://api.shodan.io/shodan/host/1.2.3.4").mock(
        side_effect=httpx.ConnectError("boom")
    )
    result = await run(ShodanProvider(), IP)
    assert result.status is ProviderStatus.ERROR
