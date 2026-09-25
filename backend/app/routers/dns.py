"""HTTP routes for DNS lookups."""

import logging
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status

from app.models.dns import DNSLookupRequest, DNSLookupResponse
from app.services.dns_service import DNSService
from app.utils.rate_limit import domain_check_limit

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1", tags=["DNS"])
_dns_service = DNSService()


def get_dns_service() -> DNSService:
    """Return the shared DNS service instance."""
    return _dns_service


@router.post(
    "/dns",
    response_model=DNSLookupResponse,
    summary="Look up common DNS records",
    description="Queries public A, MX, TXT, and NS DNS records for a domain.",
)
@domain_check_limit
def lookup_dns(
    request: Request,
    payload: DNSLookupRequest,
    dns_service: Annotated[DNSService, Depends(get_dns_service)],
) -> DNSLookupResponse:
    """Return DNS records with per-record status and partial error details."""
    logger.info("DNS lookup requested", extra={"domain": payload.domain})
    try:
        result = dns_service.lookup(payload.domain)
    except Exception as exc:
        logger.exception(
            "Unexpected DNS service failure",
            extra={"domain": payload.domain, "error": type(exc).__name__},
        )
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="The DNS lookup service could not complete the request.",
        ) from exc

    return DNSLookupResponse(
        domain=payload.domain,
        records=result.records,
        statuses=result.statuses,
        errors=result.errors,
    )
