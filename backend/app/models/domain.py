"""Shared domain request schema for data-source checks."""

import ipaddress
import re

from pydantic import BaseModel, Field, field_validator


class DomainRequest(BaseModel):
    """Request body containing the domain to inspect."""

    domain: str = Field(description="Domain name to query")

    @field_validator("domain", mode="before")
    @classmethod
    def validate_domain(cls, value: object) -> str:
        """Normalize IDNs and reject URLs, IP addresses, and malformed names."""
        message = (
            "Enter a valid domain name such as example.com; do not include a URL, "
            "port, path, or IP address."
        )
        if not isinstance(value, str):
            raise ValueError(message)

        candidate = value.strip()
        if candidate.endswith("."):
            candidate = candidate[:-1]
        if not candidate or any(character in candidate for character in "/:@?#*\\"):
            raise ValueError(message)

        try:
            ipaddress.ip_address(candidate)
        except ValueError:
            pass
        else:
            raise ValueError(message)

        try:
            ascii_domain = candidate.encode("idna").decode("ascii").lower()
        except UnicodeError as exc:
            raise ValueError(message) from exc

        if len(ascii_domain) > 253:
            raise ValueError(message)
        labels = ascii_domain.split(".")
        if len(labels) < 2 or labels[-1].isdigit() or any(
            len(label) > 63
            or re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label) is None
            for label in labels
        ):
            raise ValueError(message)
        return ascii_domain
