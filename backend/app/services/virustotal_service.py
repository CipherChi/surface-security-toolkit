"""Read-only VirusTotal domain reputation lookup."""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Protocol
from urllib.parse import quote

import httpx

from app.config import Settings

logger = logging.getLogger(__name__)


class HTTPClient(Protocol):
    """Subset of an HTTP client required by this service."""

    def get(self, url: str, **kwargs: object) -> object:
        """Send an HTTP GET request."""


@dataclass(slots=True)
class VirusTotalResult:
    """Selected public domain reputation fields and check status."""

    status: str
    data: dict[str, Any] = field(default_factory=dict)
    error: str | None = None


class VirusTotalService:
    """Fetch an existing VirusTotal domain report without submitting scans."""

    endpoint = "https://www.virustotal.com/api/v3/domains/{}"

    def __init__(
        self,
        api_key: str | None = None,
        client: HTTPClient | None = None,
        *,
        attempts: int = 3,
        backoff_seconds: float = 1.0,
        timeout_seconds: float = 8.0,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        """Create a client using an explicit key or environment configuration."""
        self._api_key = (api_key if api_key is not None else Settings().virustotal_api_key) or None
        self._client = client or httpx.Client()
        self._attempts = max(1, attempts)
        self._backoff_seconds = max(0.0, backoff_seconds)
        self._timeout_seconds = timeout_seconds
        self._sleep = sleep

    def lookup_domain(self, domain: str) -> VirusTotalResult:
        """Return an existing VirusTotal report, or unavailable without a key."""
        if not self._api_key:
            return VirusTotalResult(
                status="unavailable",
                error="VirusTotal is not configured. Set VIRUSTOTAL_API_KEY to enable this check.",
            )
        try:
            response = self._get_with_retry(domain)
            payload = response.json()
            attributes = payload.get("data", {}).get("attributes", {})
            if not isinstance(attributes, dict):
                raise ValueError("VirusTotal returned an unexpected response format")
            return VirusTotalResult(status="success", data=self._select_attributes(attributes))
        except httpx.HTTPStatusError as exc:
            code = exc.response.status_code
            if code == 404:
                return VirusTotalResult(status="not_found", error="No VirusTotal report exists for this domain.")
            if code in (401, 403):
                message = "VirusTotal rejected the API key or this request is not permitted."
            elif code == 429:
                message = "VirusTotal rate limit reached. Try again later."
            else:
                message = f"VirusTotal returned HTTP {code}."
            logger.warning(
                "VirusTotal lookup returned an HTTP error",
                extra={"domain": domain, "status_code": code},
            )
            return VirusTotalResult(status="error", error=message)
        except Exception as exc:
            logger.warning(
                "VirusTotal lookup failed",
                extra={"domain": domain, "error": type(exc).__name__},
            )
            return VirusTotalResult(status="error", error=str(exc) or type(exc).__name__)

    def _get_with_retry(self, domain: str) -> httpx.Response:
        """Fetch the domain report, retrying transport and server failures."""
        url = self.endpoint.format(quote(domain, safe=".-"))
        for attempt in range(self._attempts):
            try:
                response = self._client.get(
                    url,
                    headers={"x-apikey": self._api_key},
                    timeout=self._timeout_seconds,
                )
                response.raise_for_status()
                return response
            except httpx.HTTPStatusError as exc:
                # Authentication, not-found, and quota errors are not transient.
                if exc.response.status_code < 500 or attempt + 1 >= self._attempts:
                    raise
            except (httpx.TimeoutException, httpx.TransportError, OSError):
                if attempt + 1 >= self._attempts:
                    raise
            delay = self._backoff_seconds * (2**attempt)
            logger.info(
                "Retrying VirusTotal lookup",
                extra={"domain": domain, "attempt": attempt + 1, "retry_delay_seconds": delay},
            )
            self._sleep(delay)
        raise RuntimeError("VirusTotal retry loop exited unexpectedly")

    @staticmethod
    def _select_attributes(attributes: dict[str, Any]) -> dict[str, Any]:
        """Extract concise reputation fields from a VirusTotal domain report."""
        keys = (
            "last_analysis_stats",
            "reputation",
            "total_votes",
            "categories",
            "creation_date",
            "last_analysis_date",
            "last_modification_date",
            "registrar",
            "tags",
        )
        return {key: attributes[key] for key in keys if key in attributes}
