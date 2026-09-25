"""Unit tests for the read-only VirusTotal domain report lookup."""

from unittest.mock import Mock

import httpx

from app.services.virustotal_service import VirusTotalService


def test_missing_key_returns_unavailable_without_http_request() -> None:
    """An unset key keeps the check graceful and makes no outbound request."""
    client = Mock()

    result = VirusTotalService(api_key="", client=client).lookup_domain("example.test")

    assert result.status == "unavailable"
    assert "VIRUSTOTAL_API_KEY" in (result.error or "")
    client.get.assert_not_called()


def test_lookup_extracts_report_attributes_and_uses_auth_header() -> None:
    """A successful domain report returns selected fields, not raw API data."""
    response = httpx.Response(
        200,
        json={
            "data": {
                "attributes": {
                    "last_analysis_stats": {"malicious": 1, "harmless": 5},
                    "reputation": -2,
                    "total_votes": {"harmless": 3, "malicious": 1},
                    "categories": {"Example Vendor": "technology"},
                    "creation_date": 1_700_000_000,
                    "private_field": "not selected",
                }
            }
        },
        request=httpx.Request("GET", "https://www.virustotal.com/api/v3/domains/example.test"),
    )
    client = Mock()
    client.get.return_value = response

    result = VirusTotalService(api_key="test-key", client=client).lookup_domain("example.test")

    assert result.status == "success"
    assert result.data == {
        "last_analysis_stats": {"malicious": 1, "harmless": 5},
        "reputation": -2,
        "total_votes": {"harmless": 3, "malicious": 1},
        "categories": {"Example Vendor": "technology"},
        "creation_date": 1_700_000_000,
    }
    assert "private_field" not in result.data
    assert client.get.call_args.kwargs["headers"] == {"x-apikey": "test-key"}
    assert client.get.call_args.kwargs["timeout"] > 0


def test_server_failure_retries_with_backoff() -> None:
    """Transient server failures retry and eventually return an error result."""
    request = httpx.Request("GET", "https://www.virustotal.com/api/v3/domains/example.test")
    server_error = httpx.Response(503, request=request)
    success = httpx.Response(200, json={"data": {"attributes": {"reputation": 0}}}, request=request)
    client = Mock()
    client.get.side_effect = [server_error, success]
    sleep = Mock()

    result = VirusTotalService(
        api_key="test-key",
        client=client,
        attempts=2,
        backoff_seconds=0.2,
        sleep=sleep,
    ).lookup_domain("example.test")

    assert result.status == "success"
    assert result.data["reputation"] == 0
    sleep.assert_called_once_with(0.2)
    assert client.get.call_count == 2
