"""Read a domain's publicly presented TLS certificate on port 443."""

from __future__ import annotations

import logging
import socket
import ssl
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class TLSLookupResult:
    """Selected TLS certificate metadata and lookup outcome."""

    certificate: dict[str, Any] = field(default_factory=dict)
    status: str = "success"
    error: str | None = None


class TLSService:
    """Inspect a server certificate using a standard TLS handshake."""

    def __init__(
        self,
        *,
        attempts: int = 2,
        backoff_seconds: float = 0.25,
        timeout_seconds: float = 5.0,
        sleep: Callable[[float], None] = time.sleep,
        context: ssl.SSLContext | None = None,
        connection_factory: Callable[..., Any] = socket.create_connection,
    ) -> None:
        """Create a service with configurable timeout and injectable network."""
        self._attempts = max(1, attempts)
        self._backoff_seconds = max(0.0, backoff_seconds)
        self._timeout_seconds = timeout_seconds
        self._sleep = sleep
        if context is None:
            # This is certificate inspection, not peer authentication. Fetch
            # the presented certificate even when it is expired or untrusted.
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        self._context = context
        self._connection_factory = connection_factory

    def inspect(self, domain: str) -> TLSLookupResult:
        """Return issuer, validity dates, SAN names, and expiry state."""
        for attempt in range(self._attempts):
            try:
                certificate = self._read_certificate(domain)
                if not certificate:
                    raise ssl.SSLError("The server did not provide a certificate")
                return TLSLookupResult(self._format_certificate(certificate), "success")
            except (OSError, ssl.SSLError, TimeoutError, ValueError) as exc:
                if attempt + 1 >= self._attempts:
                    logger.warning(
                        "TLS certificate inspection failed",
                        extra={"domain": domain, "error": type(exc).__name__},
                    )
                    message = (
                        str(exc.args[0])
                        if len(exc.args) == 1 and isinstance(exc.args[0], str)
                        else str(exc)
                    )
                    return TLSLookupResult({}, "error", message or type(exc).__name__)
                delay = self._backoff_seconds * (2**attempt)
                logger.info(
                    "Retrying TLS certificate inspection",
                    extra={"domain": domain, "attempt": attempt + 1, "retry_delay_seconds": delay},
                )
                self._sleep(delay)
        return TLSLookupResult({}, "error", "TLS retry loop exited unexpectedly")

    def _read_certificate(self, domain: str) -> dict[str, Any] | None:
        """Open a bounded TLS connection and read its peer certificate."""
        with self._connection_factory((domain, 443), timeout=self._timeout_seconds) as raw_socket:
            with self._context.wrap_socket(raw_socket, server_hostname=domain) as tls_socket:
                return tls_socket.getpeercert()

    @staticmethod
    def _format_certificate(certificate: dict[str, Any]) -> dict[str, Any]:
        """Select JSON-safe issuer, subject, validity, and SAN information."""
        not_before = certificate.get("notBefore")
        not_after = certificate.get("notAfter")
        issuer = TLSService._flatten_name(certificate.get("issuer", ()))
        subject = TLSService._flatten_name(certificate.get("subject", ()))
        sans = [value for kind, value in certificate.get("subjectAltName", ()) if kind == "DNS"]
        expires_at = (
            datetime.fromtimestamp(ssl.cert_time_to_seconds(not_after), tz=timezone.utc)
            if not_after
            else None
        )
        now = datetime.now(timezone.utc)
        return {
            "issuer": issuer,
            "subject": subject,
            "valid_from": not_before,
            "valid_until": not_after,
            "days_until_expiry": (expires_at - now).days if expires_at else None,
            "is_expired": expires_at < now if expires_at else None,
            "subject_alt_names": sans,
            "serial_number": certificate.get("serialNumber"),
            "version": certificate.get("version"),
        }

    @staticmethod
    def _flatten_name(name: tuple[tuple[tuple[str, str], ...], ...]) -> dict[str, str]:
        """Convert the nested distinguished-name tuple to a plain mapping."""
        return {key: value for rdn in name for key, value in rdn}
