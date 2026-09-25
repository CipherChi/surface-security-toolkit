"""FastAPI application entry point."""

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi.errors import RateLimitExceeded

from app.routers.dns import router as dns_router
from app.routers.passive_checks import router as passive_checks_router
from app.utils.rate_limit import limiter

app = FastAPI(
    title="Passive OSINT Exposure Checker",
    description="Read-only checks against public, passive domain data sources.",
    version="0.1.0",
)
app.state.limiter = limiter
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)
app.include_router(dns_router)
app.include_router(passive_checks_router)


@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request: Request, exc: RateLimitExceeded) -> JSONResponse:
    """Return a concise JSON response when a client exceeds the shared limit."""
    return JSONResponse(
        status_code=429,
        content={"detail": "Too many checks. Please wait before trying again."},
        headers={"Retry-After": "60"},
    )


@app.get("/health", tags=["Health"], summary="Check API health")
def health_check() -> dict[str, str]:
    """Return a lightweight API health response."""
    return {"status": "ok"}
