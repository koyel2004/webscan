"""
SentinelScan FastAPI Application Entrypoint
Configures CORS, defensive application security headers, exception handlers,
and database lifecycle hooks.
"""
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from app.api import api_router
from app.core.config import settings
from app.core.exceptions import (
    FindingNotFoundError,
    ScanNotFoundError,
    SSRFSecurityViolation,
    TargetValidationError,
)
from app.core.logging import logger
from app.database.session import Base, engine


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Adds defensive HTTP security headers to all SentinelScan API responses."""

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "accelerometer=(), camera=(), geolocation=(), gyroscope=(), microphone=()"
        response.headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'none';"
        return response


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup and shutdown hooks."""
    logger.info(f"Starting {settings.APP_NAME} v{settings.APP_VERSION} ({settings.ENVIRONMENT})")
    # Ensure database tables exist
    try:
        Base.metadata.create_all(bind=engine)
        logger.info("Database schemas verified.")
    except Exception as e:
        logger.error(f"Error initializing database schemas: {e}")
    yield
    logger.info(f"Shutting down {settings.APP_NAME}")


app = FastAPI(
    title=f"{settings.APP_NAME} API",
    version=settings.APP_VERSION,
    description="Automated Web Security Assessment and Vulnerability Analysis Platform",
    lifespan=lifespan,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
)

# Defensive Security Headers Middleware
app.add_middleware(SecurityHeadersMiddleware)

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)


# Exception Handlers
@app.exception_handler(TargetValidationError)
async def target_validation_handler(request: Request, exc: TargetValidationError):
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={"error": "TargetValidationError", "message": exc.message, "details": exc.details}
    )


@app.exception_handler(SSRFSecurityViolation)
async def ssrf_violation_handler(request: Request, exc: SSRFSecurityViolation):
    logger.warning(f"SSRF violation attempt from {request.client.host if request.client else 'unknown'}: {exc.message}")
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={"error": "SSRFSecurityViolation", "message": exc.message, "details": exc.details}
    )


@app.exception_handler(ScanNotFoundError)
async def scan_not_found_handler(request: Request, exc: ScanNotFoundError):
    return JSONResponse(
        status_code=status.HTTP_404_NOT_FOUND,
        content={"error": "ScanNotFound", "message": exc.message}
    )


@app.exception_handler(FindingNotFoundError)
async def finding_not_found_handler(request: Request, exc: FindingNotFoundError):
    return JSONResponse(
        status_code=status.HTTP_404_NOT_FOUND,
        content={"error": "FindingNotFound", "message": exc.message}
    )


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.exception(f"Unhandled exception on {request.method} {request.url.path}: {exc}")
    # Return generic error without exposing internal tracebacks
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"error": "InternalServerError", "message": "An unexpected server error occurred."}
    )


# Register API Routes (support both unversioned /api and versioned /api/v1)
app.include_router(api_router, prefix="/api")
app.include_router(api_router, prefix="/api/v1")


@app.get("/")
def root():
    return {
        "app": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "status": "online",
        "docs": "/api/docs",
    }
