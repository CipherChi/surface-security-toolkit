"""Unit tests for passive DNS record lookups."""

from unittest.mock import Mock

import dns.exception
import dns.resolver
import pytest

from app.services.dns_service import DNSService


def test_lookup_returns_common_record_types() -> None:
    """Successful record answers are formatted and marked independently."""
    resolver = Mock()
    resolver.resolve.side_effect = [
        ["192.0.2.10"],
        ["10 mail.example.test."],
        ["v=spf1 -all"],
        ["ns1.example.test."],
    ]
    service = DNSService(resolver, sleep=Mock())

    result = service.lookup("example.test")

    assert result.records == {
        "A": ["192.0.2.10"],
        "MX": ["10 mail.example.test."],
        "TXT": ["v=spf1 -all"],
        "NS": ["ns1.example.test"],
    }
    assert result.statuses == {record_type: "success" for record_type in ("A", "MX", "TXT", "NS")}
    assert result.errors == {}
    assert resolver.resolve.call_count == 4


def test_no_answer_is_not_found_and_other_records_continue() -> None:
    """A missing record is empty, and does not prevent later DNS queries."""
    resolver = Mock()
    resolver.resolve.side_effect = [
        dns.resolver.NoAnswer(),
        ["10 mail.example.test."],
        dns.resolver.NoAnswer(),
        ["ns1.example.test."],
    ]
    service = DNSService(resolver, sleep=Mock())

    result = service.lookup("example.test")

    assert result.records["A"] == []
    assert result.records["MX"] == ["10 mail.example.test."]
    assert result.records["TXT"] == []
    assert result.records["NS"] == ["ns1.example.test"]
    assert result.statuses["A"] == "not_found"
    assert result.statuses["MX"] == "success"
    assert result.statuses["TXT"] == "not_found"
    assert result.statuses["NS"] == "success"


def test_transient_failure_retries_then_keeps_partial_results() -> None:
    """Transient failures are retried and isolated to their record type."""
    resolver = Mock()
    resolver.resolve.side_effect = [
        dns.exception.Timeout(),
        dns.exception.Timeout(),
        dns.exception.Timeout(),
        ["10 mail.example.test."],
        ["v=spf1 -all"],
        ["ns1.example.test."],
    ]
    sleep = Mock()
    service = DNSService(resolver, attempts=3, backoff_seconds=0.1, sleep=sleep)

    result = service.lookup("example.test")

    assert result.statuses["A"] == "error"
    assert result.errors["A"]
    assert result.statuses["MX"] == "success"
    assert result.statuses["TXT"] == "success"
    assert result.statuses["NS"] == "success"
    assert sleep.call_args_list[0].args == (0.1,)
    assert sleep.call_args_list[1].args == (0.2,)
    assert resolver.resolve.call_count == 6
