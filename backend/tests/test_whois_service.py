"""Unit tests for domain registration lookup."""

from datetime import datetime, timezone
from unittest.mock import Mock

from app.services.whois_service import WhoisService


def test_lookup_normalizes_selected_whois_fields() -> None:
    """Dates and list values are converted to JSON-safe values."""
    lookup = Mock(
        return_value={
            "domain_name": "EXAMPLE.TEST",
            "registrar": "Example Registrar",
            "creation_date": datetime(2020, 1, 2, tzinfo=timezone.utc),
            "name_servers": ["NS1.EXAMPLE.TEST", "NS2.EXAMPLE.TEST"],
            "raw": "unfiltered registry response",
        }
    )

    result = WhoisService(lookup, sleep=Mock()).lookup_domain("example.test")

    assert result.status == "success"
    assert result.data == {
        "domain_name": "EXAMPLE.TEST",
        "registrar": "Example Registrar",
        "creation_date": "2020-01-02T00:00:00+00:00",
        "name_servers": ["NS1.EXAMPLE.TEST", "NS2.EXAMPLE.TEST"],
    }
    assert "raw" not in result.data
    assert lookup.call_args.kwargs["timeout"] > 0


def test_lookup_retries_failure_then_reports_error() -> None:
    """WHOIS failures retry with backoff and return an error result."""
    lookup = Mock(side_effect=TimeoutError("WHOIS timed out"))
    sleep = Mock()

    result = WhoisService(lookup, attempts=2, backoff_seconds=0.2, sleep=sleep).lookup_domain("example.test")

    assert result.status == "error"
    assert result.error == "WHOIS timed out"
    sleep.assert_called_once_with(0.2)
    assert lookup.call_count == 2


def test_empty_whois_response_is_not_found() -> None:
    """An empty registration response is a normal not-found outcome."""
    result = WhoisService(Mock(return_value={}), sleep=Mock()).lookup_domain("example.test")

    assert result.status == "not_found"
    assert result.data == {}
