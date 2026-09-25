"""Typed request and response schemas for the DNS endpoint."""

from pydantic import BaseModel

from app.models.domain import DomainRequest


class DNSLookupRequest(DomainRequest):
    """Request body for common DNS record lookups."""


class DNSLookupResponse(BaseModel):
    """DNS records and an independent status for each requested type."""

    domain: str
    records: dict[str, list[str]]
    statuses: dict[str, str]
    errors: dict[str, str]
