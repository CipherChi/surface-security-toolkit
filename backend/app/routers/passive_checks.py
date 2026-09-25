"""HTTP routes for certificate transparency, WHOIS, and TLS checks."""

import logging
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status

from app.models.domain import DomainRequest
from app.models.email import EmailRequest, EmailResponse
from app.models.passive_checks import (
    CRTShResponse,
    TLSCertificate,
    TLSResponse,
    VirusTotalResponse,
    WhoisResponse,
)
from app.services.crtsh_service import CRTShService
from app.services.tls_service import TLSService
from app.services.whois_service import WhoisService
from app.services.virustotal_service import VirusTotalService
from app.services.email_service import EmailService
from app.utils.rate_limit import domain_check_limit

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1", tags=["Passive checks"])
_crtsh_service = CRTShService()
_whois_service = WhoisService()
_tls_service = TLSService()
_virustotal_service = VirusTotalService()
_email_service = EmailService()


def get_crtsh_service() -> CRTShService:
    """Return the shared crt.sh service instance."""
    return _crtsh_service


def get_whois_service() -> WhoisService:
    """Return the shared WHOIS service instance."""
    return _whois_service


def get_tls_service() -> TLSService:
    """Return the shared TLS service instance."""
    return _tls_service


def get_virustotal_service() -> VirusTotalService:
    """Return the shared VirusTotal service instance."""
    return _virustotal_service


def get_email_service() -> EmailService:
    """Return the shared email check service instance."""
    return _email_service


@router.post("/email", response_model=EmailResponse, summary="Check public email exposure signals")
@domain_check_limit
def check_email(
    request: Request,
    payload: EmailRequest,
    service: Annotated[EmailService, Depends(get_email_service)],
) -> EmailResponse:
    """Check email-domain MX, optional HIBP breach data, and public Gravatar presence."""
    logger.info("email exposure lookup requested")
    try:
        domain, signals = service.check(payload.email)
    except Exception as exc:
        logger.exception("Unexpected email service failure", extra={"error": type(exc).__name__})
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="The email exposure lookup could not complete.",
        ) from exc
    return EmailResponse(email=payload.email, domain=domain, signals=signals)


@router.post("/crtsh", response_model=CRTShResponse, summary="Find certificate transparency names")
@domain_check_limit
def lookup_crtsh(
    request: Request,
    payload: DomainRequest,
    service: Annotated[CRTShService, Depends(get_crtsh_service)],
) -> CRTShResponse:
    """Return domain names found in crt.sh certificate records."""
    logger.info("crt.sh lookup requested", extra={"domain": payload.domain})
    try:
        result = service.lookup(payload.domain)
    except Exception as exc:
        logger.exception(
            "Unexpected crt.sh service failure",
            extra={"domain": payload.domain, "error": type(exc).__name__},
        )
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="The certificate transparency lookup could not complete.",
        ) from exc
    return CRTShResponse(
        domain=payload.domain,
        subdomains=result.subdomains,
        status=result.status,
        error=result.error,
    )


@router.post("/whois", response_model=WhoisResponse, summary="Look up domain registration")
@domain_check_limit
def lookup_whois(
    request: Request,
    payload: DomainRequest,
    service: Annotated[WhoisService, Depends(get_whois_service)],
) -> WhoisResponse:
    """Return selected public registration fields for a domain."""
    logger.info("WHOIS lookup requested", extra={"domain": payload.domain})
    try:
        result = service.lookup_domain(payload.domain)
    except Exception as exc:
        logger.exception(
            "Unexpected WHOIS service failure",
            extra={"domain": payload.domain, "error": type(exc).__name__},
        )
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="The WHOIS lookup could not complete.",
        ) from exc
    return WhoisResponse(domain=payload.domain, data=result.data, status=result.status, error=result.error)


@router.post("/tls", response_model=TLSResponse, summary="Inspect a domain TLS certificate")
@domain_check_limit
def inspect_tls(
    request: Request,
    payload: DomainRequest,
    service: Annotated[TLSService, Depends(get_tls_service)],
) -> TLSResponse:
    """Inspect the certificate presented by a domain on TCP port 443."""
    logger.info("TLS certificate inspection requested", extra={"domain": payload.domain})
    try:
        result = service.inspect(payload.domain)
    except Exception as exc:
        logger.exception(
            "Unexpected TLS inspection failure",
            extra={"domain": payload.domain, "error": type(exc).__name__},
        )
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="The TLS certificate inspection could not complete.",
        ) from exc
    certificate = TLSCertificate.model_validate(result.certificate) if result.certificate else None
    return TLSResponse(
        domain=payload.domain,
        certificate=certificate,
        status=result.status,
        error=result.error,
    )


@router.post(
    "/virustotal",
    response_model=VirusTotalResponse,
    summary="Look up VirusTotal domain reputation",
    description="Reads an existing VirusTotal domain report; it does not submit or trigger a scan.",
)
@domain_check_limit
def lookup_virustotal(
    request: Request,
    payload: DomainRequest,
    service: Annotated[VirusTotalService, Depends(get_virustotal_service)],
) -> VirusTotalResponse:
    """Return VirusTotal reputation metadata, or unavailable without a key."""
    logger.info("VirusTotal lookup requested", extra={"domain": payload.domain})
    try:
        result = service.lookup_domain(payload.domain)
    except Exception as exc:
        logger.exception(
            "Unexpected VirusTotal service failure",
            extra={"domain": payload.domain, "error": type(exc).__name__},
        )
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="The VirusTotal lookup could not complete.",
        ) from exc
    return VirusTotalResponse(
        domain=payload.domain,
        data=result.data,
        status=result.status,
        error=result.error,
    )
