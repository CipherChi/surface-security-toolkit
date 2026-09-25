"""Domain registration lookup through the public WHOIS protocol."""

from __future__ import annotations

import logging
import socket
import time
from dataclasses import dataclass, field
from datetime import date, datetime
from typing import Any, Callable, Protocol

import whois

logger = logging.getLogger(__name__)
WHOIS_FIELDS = (
    "domain_name",
    "registrar",
    "whois_server",
    "creation_date",
    "expiration_date",
    "updated_date",
    "name_servers",
    "emails",
    "status",
    "country",
    "state",
    "city",
    "org",
)


class WhoisLookup(Protocol):
    """Callable interface for the WHOIS library, injectable in unit tests."""

    def __call__(self, domain: str, **kwargs: object) -> dict[str, Any]:
        """Return parsed WHOIS data for a domain."""


@dataclass(slots=True)
class WhoisLookupResult:
    """Selected registration fields and lookup status."""

    data: dict[str, str | list[str] | None] = field(default_factory=dict)
    status: str = "success"
    error: str | None = None


class WhoisService:
    """Fetch a small, stable set of domain registration fields."""

    def __init__(
        self,
        lookup: WhoisLookup | None = None,
        *,
        attempts: int = 2,
        backoff_seconds: float = 0.25,
        timeout_seconds: int = 6,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        """Create a service with injectable WHOIS lookup and retry policy."""
        self._lookup = lookup or whois.whois
        self._attempts = max(1, attempts)
        self._backoff_seconds = max(0.0, backoff_seconds)
        self._timeout_seconds = timeout_seconds
        self._sleep = sleep

    def lookup_domain(self, domain: str) -> WhoisLookupResult:
        """Return selected WHOIS fields without exposing raw registry output."""
        raw: dict[str, Any] | None = None
        for attempt in range(self._attempts):
            try:
                raw = self._lookup(
                    domain,
                    timeout=self._timeout_seconds,
                    ignore_socket_errors=False,
                )
                break
            except (socket.timeout, TimeoutError, OSError, Exception) as exc:
                if attempt + 1 >= self._attempts:
                    logger.warning(
                        "WHOIS lookup failed",
                        extra={"domain": domain, "error": type(exc).__name__},
                    )
                    return WhoisLookupResult(status="error", error=str(exc) or type(exc).__name__)
                delay = self._backoff_seconds * (2**attempt)
                logger.info(
                    "Retrying WHOIS lookup",
                    extra={"domain": domain, "attempt": attempt + 1, "retry_delay_seconds": delay},
                )
                self._sleep(delay)

        if not raw or not any(raw.get(field_name) for field_name in WHOIS_FIELDS):
            return WhoisLookupResult(status="not_found")

        data = {
            field_name: self._normalize(raw.get(field_name))
            for field_name in WHOIS_FIELDS
            if raw.get(field_name) is not None
        }
        return WhoisLookupResult(data=data, status="success")

    @classmethod
    def _normalize(cls, value: Any) -> str | list[str] | None:
        """Convert WHOIS date and collection values to JSON-safe values."""
        if value is None:
            return None
        if isinstance(value, (datetime, date)):
            return value.isoformat()
        if isinstance(value, (list, tuple, set)):
            values = [cls._normalize(item) for item in value]
            return [str(item) for item in values if item is not None]
        if isinstance(value, dict):
            return str(value)
        return str(value).strip()
