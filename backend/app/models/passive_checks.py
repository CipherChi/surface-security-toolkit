"""Typed response schemas for passive domain data-source checks."""

from typing import Literal

from pydantic import BaseModel

CheckStatus = Literal["success", "not_found", "error", "unavailable"]


class CRTShResponse(BaseModel):
    """Certificate transparency result."""

    domain: str
    subdomains: list[str]
    status: CheckStatus
    error: str | None = None


class WhoisResponse(BaseModel):
    """Selected WHOIS registration information."""

    domain: str
    data: dict[str, str | list[str] | None]
    status: CheckStatus
    error: str | None = None


class TLSCertificate(BaseModel):
    """Public certificate metadata returned by a TLS inspection."""

    issuer: dict[str, str]
    subject: dict[str, str]
    valid_from: str | None
    valid_until: str | None
    days_until_expiry: int | None
    is_expired: bool | None
    subject_alt_names: list[str]
    serial_number: str | None
    version: int | None


class TLSResponse(BaseModel):
    """TLS inspection status and optional certificate metadata."""

    domain: str
    certificate: TLSCertificate | None = None
    status: CheckStatus
    error: str | None = None


class VirusTotalResponse(BaseModel):
    """VirusTotal domain report and availability status."""

    domain: str
    data: dict[str, object]
    status: CheckStatus
    error: str | None = None
