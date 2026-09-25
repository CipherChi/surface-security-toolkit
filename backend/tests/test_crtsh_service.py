"""Unit tests for certificate transparency lookups."""

from unittest.mock import Mock

import httpx

from app.services.crtsh_service import CRTShService


def test_lookup_returns_unique_names_for_requested_domain() -> None:
    """Names are normalized, deduplicated, and scoped to the domain suffix."""
    response = httpx.Response(
        200,
        json=[
            {"name_value": "www.example.test\n*.api.example.test"},
            {"name_value": "www.example.test"},
            {"name_value": "example.test.attacker.test"},
        ],
        request=httpx.Request("GET", "https://crt.sh/"),
    )
    client = Mock()
    client.get.return_value = response

    result = CRTShService(client, sleep=Mock()).lookup("example.test")

    assert result.status == "success"
    assert result.subdomains == ["api.example.test", "www.example.test"]
    assert client.get.call_args.kwargs["timeout"] > 0


def test_lookup_retries_timeout_then_returns_error() -> None:
    """Exhausted HTTP retries fail gracefully and use exponential backoff."""
    client = Mock()
    client.get.side_effect = httpx.TimeoutException("timed out")
    sleep = Mock()

    result = CRTShService(client, attempts=2, backoff_seconds=0.1, sleep=sleep).lookup("example.test")

    assert result.status == "error"
    assert result.subdomains == []
    assert result.error == "timed out"
    sleep.assert_called_once_with(0.1)
    assert client.get.call_count == 2
