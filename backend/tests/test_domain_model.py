"""Unit tests for domain-only API input validation."""

import pytest
from pydantic import ValidationError

from app.models.domain import DomainRequest


@pytest.mark.parametrize(
    ("value", "normalized"),
    [
        ("example.com", "example.com"),
        (" EXAMPLE.COM. ", "example.com"),
        ("münich.example", "xn--mnich-kva.example"),
    ],
)
def test_valid_domain_is_normalized(value: str, normalized: str) -> None:
    """Valid domains are trimmed, lowercased, and IDNs become ASCII labels."""
    assert DomainRequest(domain=value).domain == normalized


@pytest.mark.parametrize(
    "value",
    [
        "https://example.com",
        "example.com/path",
        "example.com:443",
        "127.0.0.1",
        "2001:db8::1",
        "localhost",
        "bad..example.com",
        "-bad.example.com",
        "bad_.example.com",
        "example.123",
    ],
)
def test_invalid_domain_is_rejected_with_clear_message(value: str) -> None:
    """URLs, IP addresses, and malformed domain labels are not accepted."""
    with pytest.raises(ValidationError) as exc_info:
        DomainRequest(domain=value)

    assert "valid domain name" in exc_info.value.errors()[0]["msg"]
