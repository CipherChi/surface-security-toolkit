"""Request and response models for passive email exposure checks."""

from typing import Literal

from pydantic import BaseModel, Field, field_validator


class EmailRequest(BaseModel):
    email: str = Field(min_length=3, max_length=254)

    @field_validator("email")
    @classmethod
    def validate_email_shape(cls, value: str) -> str:
        normalized = value.strip().lower()
        if normalized.count("@") != 1:
            raise ValueError("Enter a valid email address.")
        local, domain = normalized.rsplit("@", 1)
        if not local or len(local) > 64 or not domain or "." not in domain:
            raise ValueError("Enter a valid email address.")
        if any(ch.isspace() for ch in normalized) or domain.startswith(".") or domain.endswith("."):
            raise ValueError("Enter a valid email address.")
        if any(not label or len(label) > 63 or label.startswith("-") or label.endswith("-") for label in domain.split(".")):
            raise ValueError("Enter a valid email address.")
        return normalized


class EmailSignal(BaseModel):
    signal: str
    status: Literal["checked", "not_checked", "exposed", "clean"]
    details: str
    source_url: str | None = None


class EmailResponse(BaseModel):
    email: str
    domain: str
    signals: list[EmailSignal]
