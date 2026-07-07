"""Common Provider interface.

A provider only implements ``fetch()``; key handling, unsupported IOC types
and error trapping are dealt with here so individual providers stay small and
a failing provider can never crash the CLI.
"""

from __future__ import annotations

import os
from abc import ABC, abstractmethod
from datetime import datetime, timezone

import httpx

from ..models import IOC, IOCType, ProviderResult, ProviderStatus


class NotFound(Exception):
    """Raised by a provider when the IOC is unknown to that source."""


class Provider(ABC):
    """Base class for all threat-intel providers."""

    name: str
    env_key: str
    supported_types: frozenset[IOCType]

    def __init__(self) -> None:
        self.api_key = os.environ.get(self.env_key, "").strip()

    @abstractmethod
    async def fetch(self, client: httpx.AsyncClient, ioc: IOC) -> ProviderResult:
        """Query the provider and return a normalised result.

        May raise ``NotFound`` or any httpx error; ``run()`` handles both.
        """

    async def run(self, client: httpx.AsyncClient, ioc: IOC) -> ProviderResult:
        if ioc.type not in self.supported_types:
            return ProviderResult(
                provider=self.name,
                status=ProviderStatus.UNSUPPORTED,
                detail=f"{ioc.type.value} not supported by {self.name}",
            )
        if not self.api_key:
            return ProviderResult(
                provider=self.name,
                status=ProviderStatus.NO_KEY,
                detail=f"set {self.env_key} to enable this provider",
            )
        try:
            return await self.fetch(client, ioc)
        except NotFound:
            return ProviderResult(provider=self.name, status=ProviderStatus.NOT_FOUND)
        except httpx.HTTPStatusError as exc:
            return ProviderResult(
                provider=self.name,
                status=ProviderStatus.ERROR,
                detail=f"HTTP {exc.response.status_code}",
            )
        except httpx.HTTPError as exc:
            return ProviderResult(
                provider=self.name,
                status=ProviderStatus.ERROR,
                detail=type(exc).__name__,
            )
        except (KeyError, TypeError, ValueError) as exc:
            return ProviderResult(
                provider=self.name,
                status=ProviderStatus.ERROR,
                detail=f"unexpected response shape: {exc}",
            )


def from_timestamp(value: int | float | None) -> datetime | None:
    """Epoch seconds -> aware datetime, tolerating None/0."""
    if not value:
        return None
    return datetime.fromtimestamp(value, tz=timezone.utc)


def from_iso(value: str | None) -> datetime | None:
    """ISO-8601 string -> aware datetime, tolerating None/empty/garbage."""
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed
