"""Certificate transparency lookups through the public crt.sh JSON endpoint."""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Callable, Protocol

import httpx

logger = logging.getLogger(__name__)


class HTTPClient(Protocol):
    """Subset of an HTTP client required by the crt.sh service."""

    def get(self, url: str, **kwargs: object) -> object:
        """Send an HTTP GET request."""


@dataclass(slots=True)
class CTLookupResult:
    """Certificate transparency names and the outcome of the lookup."""

    subdomains: list[str]
    status: str
    error: str | None = None


class CRTShService:
    """Read certificate transparency entries published by crt.sh."""

    endpoint = "https://crt.sh/"
    fallback_endpoint = "https://api.certspotter.com/v1/issuances"

    def __init__(
        self,
        client: HTTPClient | None = None,
        *,
        attempts: int = 3,
        backoff_seconds: float = 0.25,
        timeout_seconds: float = 8.0,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        """Create a service with an injectable client and retry policy."""
        self._client = client or httpx.Client()
        self._attempts = max(1, attempts)
        self._backoff_seconds = max(0.0, backoff_seconds)
        self._timeout_seconds = timeout_seconds
        self._sleep = sleep

    def lookup(self, domain: str) -> CTLookupResult:
        """Return unique certificate names matching the requested domain."""
        try:
            response = self._get_with_retry(domain)
            rows = response.json()
            if not isinstance(rows, list):
                raise ValueError("crt.sh returned an unexpected response format")
            return CTLookupResult(self._names_from_crtsh(rows, domain), "success")
        except Exception as exc:
            if not isinstance(exc, httpx.HTTPStatusError) or exc.response.status_code < 500:
                logger.warning(
                    "Certificate transparency lookup failed",
                    extra={"domain": domain, "error": type(exc).__name__},
                )
                return CTLookupResult([], "error", str(exc) or type(exc).__name__)
            logger.info(
                "crt.sh unavailable; trying Cert Spotter",
                extra={"domain": domain, "error": type(exc).__name__},
            )
            try:
                rows = self._get_certspotter(domain)
                return CTLookupResult(self._names_from_certspotter(rows, domain), "success")
            except Exception as fallback_exc:
                logger.warning(
                    "Certificate transparency providers failed",
                    extra={"domain": domain, "error": type(fallback_exc).__name__},
                )
                return CTLookupResult([], "error", str(exc) or type(exc).__name__)

    @staticmethod
    def _names_from_crtsh(rows: list[object], domain: str) -> list[str]:
        names: set[str] = set()
        suffix = f".{domain.lower().rstrip('.')}"
        for row in rows:
            if not isinstance(row, dict):
                continue
            value = row.get("name_value")
            if not isinstance(value, str):
                continue
            for candidate in value.splitlines():
                name = candidate.strip().lower().rstrip(".")
                if name == domain.lower().rstrip(".") or name.endswith(suffix):
                    names.add(name.removeprefix("*."))
        return sorted(names)

    @staticmethod
    def _names_from_certspotter(rows: list[object], domain: str) -> list[str]:
        names: set[str] = set()
        suffix = f".{domain.lower().rstrip('.')}"
        for row in rows:
            if not isinstance(row, dict):
                continue
            dns_names = row.get("dns_names", [])
            if not isinstance(dns_names, list):
                continue
            for candidate in dns_names:
                if not isinstance(candidate, str):
                    continue
                name = candidate.strip().lower().removeprefix("*.").rstrip(".")
                if name == domain.lower().rstrip(".") or name.endswith(suffix):
                    names.add(name)
        return sorted(names)

    def _get_certspotter(self, domain: str) -> list[object]:
        response = self._client.get(
            self.fallback_endpoint,
            params={"domain": domain, "include_subdomains": "true", "expand": "dns_names"},
            timeout=self._timeout_seconds,
        )
        response.raise_for_status()
        rows = response.json()
        if not isinstance(rows, list):
            raise ValueError("Cert Spotter returned an unexpected response format")
        return rows

    def _get_with_retry(self, domain: str) -> httpx.Response:
        """Fetch crt.sh JSON, retrying network and server-side HTTP failures."""
        params = {"q": f"%.{domain}", "output": "json"}
        for attempt in range(self._attempts):
            try:
                response = self._client.get(
                    self.endpoint,
                    params=params,
                    timeout=self._timeout_seconds,
                )
                response.raise_for_status()
                return response
            except httpx.HTTPStatusError as exc:
                if exc.response.status_code < 500 or attempt + 1 >= self._attempts:
                    raise
            except (httpx.TimeoutException, httpx.TransportError, OSError):
                if attempt + 1 >= self._attempts:
                    raise
            delay = self._backoff_seconds * (2**attempt)
            logger.info(
                "Retrying certificate transparency lookup",
                extra={"domain": domain, "attempt": attempt + 1, "retry_delay_seconds": delay},
            )
            self._sleep(delay)
        raise RuntimeError("crt.sh retry loop exited unexpectedly")
