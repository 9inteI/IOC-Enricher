"""Threat-intel provider registry."""

from .base import Provider
from .virustotal import VirusTotalProvider
from .abuseipdb import AbuseIPDBProvider
from .shodan import ShodanProvider
from .otx import OTXProvider

ALL_PROVIDERS: list[type[Provider]] = [
    VirusTotalProvider,
    AbuseIPDBProvider,
    ShodanProvider,
    OTXProvider,
]

__all__ = [
    "Provider",
    "VirusTotalProvider",
    "AbuseIPDBProvider",
    "ShodanProvider",
    "OTXProvider",
    "ALL_PROVIDERS",
]
