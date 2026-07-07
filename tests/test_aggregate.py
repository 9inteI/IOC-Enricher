from datetime import datetime, timezone

from ioc_enrich.aggregate import label_for, merge
from ioc_enrich.detect import detect_ioc
from ioc_enrich.models import IOC, IOCType, ProviderResult, ProviderStatus

IP = detect_ioc("1.2.3.4")


def ok(provider, **kwargs):
    return ProviderResult(provider=provider, status=ProviderStatus.OK, **kwargs)


def test_weighted_average():
    verdict = merge(
        IP,
        [
            ok("VirusTotal", score=80.0),  # weight 1.0
            ok("AlienVault OTX", score=20.0),  # weight 0.6
        ],
    )
    assert verdict.score == 57.5  # (80*1 + 20*0.6) / 1.6
    assert verdict.label == "suspicious"


def test_ignores_unscored_and_failed_sources():
    verdict = merge(
        IP,
        [
            ok("AbuseIPDB", score=100.0),
            ok("Shodan", score=None, categories=["tor"]),
            ProviderResult(provider="VirusTotal", status=ProviderStatus.ERROR),
            ProviderResult(provider="AlienVault OTX", status=ProviderStatus.NO_KEY),
        ],
    )
    assert verdict.score == 100.0
    assert verdict.label == "malicious"
    assert verdict.categories == ["tor"]  # categories from OK sources only
    assert len(verdict.sources) == 4  # but every source is reported


def test_no_data_gives_unknown():
    verdict = merge(IP, [ProviderResult(provider="X", status=ProviderStatus.ERROR)])
    assert verdict.score is None
    assert verdict.label == "unknown"


def test_seen_window_and_related_dedup():
    early = datetime(2020, 1, 1, tzinfo=timezone.utc)
    late = datetime(2026, 6, 1, tzinfo=timezone.utc)
    rel = IOC(value="bad.example", type=IOCType.DOMAIN)
    verdict = merge(
        IP,
        [
            ok("VirusTotal", score=10.0, first_seen=late, last_seen=late,
               related_iocs=[rel]),
            ok("AbuseIPDB", score=10.0, first_seen=early, related_iocs=[rel]),
        ],
    )
    assert verdict.first_seen == early
    assert verdict.last_seen == late
    assert verdict.related_iocs == [rel]


def test_labels():
    assert label_for(None) == "unknown"
    assert label_for(10) == "clean"
    assert label_for(30) == "suspicious"
    assert label_for(90) == "malicious"
