"""Pydantic models shared across providers and output renderers."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, Field


class IOCType(StrEnum):
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    HASH = "hash"


class IOC(BaseModel):
    value: str
    type: IOCType


class ProviderStatus(StrEnum):
    OK = "ok"
    NO_KEY = "no_key"
    NOT_FOUND = "not_found"
    UNSUPPORTED = "unsupported"
    ERROR = "error"


class ProviderResult(BaseModel):
    """Normalised result from a single threat-intel provider."""

    provider: str
    status: ProviderStatus
    # 0 = clean, 100 = malicious. None when the provider has no opinion.
    score: float | None = None
    categories: list[str] = Field(default_factory=list)
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    related_iocs: list[IOC] = Field(default_factory=list)
    detail: str | None = None
    link: str | None = None


class Verdict(BaseModel):
    """Unified verdict aggregated from all provider results."""

    ioc: IOC
    score: float | None = None
    label: str = "unknown"  # clean | suspicious | malicious | unknown
    categories: list[str] = Field(default_factory=list)
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    related_iocs: list[IOC] = Field(default_factory=list)
    sources: list[ProviderResult] = Field(default_factory=list)
