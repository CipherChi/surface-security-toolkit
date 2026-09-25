"""DNS record lookups using the system's configured recursive resolver."""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Callable, Protocol

import dns.exception
import dns.resolver

logger = logging.getLogger(__name__)

RECORD_TYPES = ("A", "MX", "TXT", "NS")


class Resolver(Protocol):
    """Subset of the dnspython resolver interface used by this service."""

    def resolve(self, qname: str, rdtype: str, **kwargs: object) -> object:
        """Resolve a record name and type."""


@dataclass(slots=True)
class DNSLookupResult:
    """Per-record DNS results, including independent lookup failures."""

    records: dict[str, list[str]] = field(default_factory=dict)
    statuses: dict[str, str] = field(default_factory=dict)
    errors: dict[str, str] = field(default_factory=dict)


class DNSService:
    """Look up common DNS records with bounded retries and partial failures."""

    def __init__(
        self,
        resolver: Resolver | None = None,
        *,
        attempts: int = 3,
        backoff_seconds: float = 0.25,
        timeout_seconds: float = 2.0,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        """Create a service using an injectable resolver and retry policy."""
        self._resolver = resolver or dns.resolver.Resolver()
        self._attempts = max(1, attempts)
        self._backoff_seconds = max(0.0, backoff_seconds)
        self._timeout_seconds = timeout_seconds
        self._sleep = sleep

    def lookup(self, domain: str) -> DNSLookupResult:
        """Query A, MX, TXT, and NS records, preserving results per record type.

        A record type with no published answer is returned as ``not_found``
        with an empty list. Transient resolver failures are retried with
        exponential backoff; exhausting retries for one type does not stop
        the remaining lookups.
        """
        result = DNSLookupResult()
        for record_type in RECORD_TYPES:
            try:
                answer = self._resolve_with_retry(domain, record_type)
                result.records[record_type] = [
                    self._format_record(record_type, record) for record in answer
                ]
                result.statuses[record_type] = (
                    "success" if result.records[record_type] else "not_found"
                )
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                result.records[record_type] = []
                result.statuses[record_type] = "not_found"
            except (dns.exception.DNSException, OSError, TimeoutError) as exc:
                result.records[record_type] = []
                result.statuses[record_type] = "error"
                result.errors[record_type] = str(exc) or type(exc).__name__
                logger.warning(
                    "DNS record lookup failed",
                    extra={
                        "domain": domain,
                        "record_type": record_type,
                        "error": type(exc).__name__,
                    },
                )
        return result

    def _resolve_with_retry(self, domain: str, record_type: str) -> object:
        """Resolve one record type, retrying transient DNS and OS failures."""
        for attempt in range(self._attempts):
            try:
                return self._resolver.resolve(
                    domain,
                    record_type,
                    lifetime=self._timeout_seconds,
                )
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                raise
            except (dns.exception.DNSException, OSError, TimeoutError):
                if attempt + 1 >= self._attempts:
                    raise
                delay = self._backoff_seconds * (2**attempt)
                logger.info(
                    "Retrying DNS record lookup",
                    extra={
                        "domain": domain,
                        "record_type": record_type,
                        "attempt": attempt + 1,
                        "retry_delay_seconds": delay,
                    },
                )
                self._sleep(delay)
        raise RuntimeError("DNS retry loop exited unexpectedly")

    @staticmethod
    def _format_record(record_type: str, record: object) -> str:
        """Convert a dnspython record object to a readable string."""
        if record_type == "TXT" and hasattr(record, "strings"):
            chunks = getattr(record, "strings")
            return b"".join(chunks).decode("utf-8", errors="replace")
        return str(record).rstrip(".") if record_type == "NS" else str(record)
