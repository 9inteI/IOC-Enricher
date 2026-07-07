import pytest


@pytest.fixture(autouse=True)
def api_keys(monkeypatch):
    """Fake keys for every provider; individual tests may delete them."""
    monkeypatch.setenv("VT_API_KEY", "test-vt")
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "test-abuse")
    monkeypatch.setenv("SHODAN_API_KEY", "test-shodan")
    monkeypatch.setenv("OTX_API_KEY", "test-otx")
