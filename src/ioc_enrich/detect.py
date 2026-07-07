"""Auto-detection of IOC type from its raw string value."""

from __future__ import annotations

import ipaddress
import re

from .models import IOC, IOCType

_HASH_RE = re.compile(r"^[A-Fa-f0-9]{32}$|^[A-Fa-f0-9]{40}$|^[A-Fa-f0-9]{64}$")
_DOMAIN_RE = re.compile(
    r"^(?=.{4,253}$)([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$"
)
_URL_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://\S+$")


def detect_ioc(value: str) -> IOC:
    """Classify *value* as an IP, domain, URL or file hash.

    Raises ValueError if the value doesn't look like any supported IOC type.
    """
    value = value.strip()
    if not value:
        raise ValueError("empty indicator")

    if _URL_RE.match(value):
        return IOC(value=value, type=IOCType.URL)

    try:
        ipaddress.ip_address(value)
        return IOC(value=value, type=IOCType.IP)
    except ValueError:
        pass

    if _HASH_RE.match(value):
        return IOC(value=value.lower(), type=IOCType.HASH)

    if _DOMAIN_RE.match(value):
        return IOC(value=value.lower(), type=IOCType.DOMAIN)

    raise ValueError(
        f"could not detect IOC type for {value!r} "
        "(expected IP, domain, URL, or MD5/SHA1/SHA256 hash)"
    )
