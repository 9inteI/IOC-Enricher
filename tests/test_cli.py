"""End-to-end CLI tests with all HTTP traffic mocked."""

import json

import respx
from typer.testing import CliRunner

from ioc_enrich.cli import app

runner = CliRunner()


def mock_all_ip_providers():
    respx.get("https://www.virustotal.com/api/v3/ip_addresses/1.2.3.4").respond(
        json={
            "data": {
                "attributes": {
                    "last_analysis_stats": {"malicious": 60, "harmless": 20},
                }
            }
        }
    )
    respx.get("https://api.abuseipdb.com/api/v2/check").respond(
        json={"data": {"abuseConfidenceScore": 100, "totalReports": 5,
                       "numDistinctUsers": 3, "reports": []}}
    )
    respx.get("https://api.shodan.io/shodan/host/1.2.3.4").respond(404)
    respx.get(
        "https://otx.alienvault.com/api/v1/indicators/IPv4/1.2.3.4/general"
    ).respond(json={"pulse_info": {"count": 0, "pulses": []}})


@respx.mock
def test_table_output():
    mock_all_ip_providers()
    result = runner.invoke(app, ["1.2.3.4"])
    assert result.exit_code == 0
    assert "MALICIOUS" in result.output
    assert "VirusTotal" in result.output
    assert "not found" in result.output  # Shodan 404 noted, not fatal


@respx.mock
def test_json_output():
    mock_all_ip_providers()
    result = runner.invoke(app, ["1.2.3.4", "--json"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["ioc"] == {"value": "1.2.3.4", "type": "ip"}
    assert data["label"] == "malicious"
    assert len(data["sources"]) == 4


@respx.mock
def test_stix_output():
    mock_all_ip_providers()
    result = runner.invoke(app, ["1.2.3.4", "--stix"])
    assert result.exit_code == 0
    bundle = json.loads(result.output)
    assert bundle["type"] == "bundle"
    indicator = bundle["objects"][0]
    assert indicator["type"] == "indicator"
    assert indicator["pattern"] == "[ipv4-addr:value = '1.2.3.4']"
    assert "malicious" in indicator["labels"]


def test_invalid_indicator_exits_2():
    result = runner.invoke(app, ["not an ioc!!"])
    assert result.exit_code == 2


def test_json_and_stix_are_exclusive():
    result = runner.invoke(app, ["1.2.3.4", "--json", "--stix"])
    assert result.exit_code == 2
