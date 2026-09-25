"""Unit tests for TLS certificate inspection."""

import ssl
from unittest.mock import Mock

from app.services.tls_service import TLSService


def test_inspect_formats_certificate_details() -> None:
    """Certificate identity, expiry, and subject alternative names are retained."""
    certificate = {
        "issuer": ((('organizationName', 'Example CA'),), (('commonName', 'Issuer'),)),
        "subject": ((('commonName', 'example.test'),),),
        "notBefore": "Jan  1 00:00:00 2025 GMT",
        "notAfter": "Jan  1 00:00:00 2030 GMT",
        "subjectAltName": (("DNS", "example.test"), ("DNS", "www.example.test")),
        "serialNumber": "01AB",
        "version": 3,
    }
    service = TLSService(sleep=Mock())
    service._read_certificate = Mock(return_value=certificate)  # type: ignore[method-assign]

    result = service.inspect("example.test")

    assert result.status == "success"
    assert result.certificate["issuer"] == {"organizationName": "Example CA", "commonName": "Issuer"}
    assert result.certificate["subject"] == {"commonName": "example.test"}
    assert result.certificate["subject_alt_names"] == ["example.test", "www.example.test"]
    assert result.certificate["is_expired"] is False
    assert result.certificate["serial_number"] == "01AB"


def test_inspect_retries_tls_failure_then_reports_error() -> None:
    """TLS failures retry with backoff and return an error result."""
    service = TLSService(attempts=2, backoff_seconds=0.15, sleep=Mock())
    service._read_certificate = Mock(side_effect=ssl.SSLError("handshake failed"))  # type: ignore[method-assign]

    result = service.inspect("example.test")

    assert result.status == "error"
    assert result.error == "handshake failed"
    service._sleep.assert_called_once_with(0.15)
