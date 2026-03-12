"""
EASM Platform FastAPI Application

Main application entry point with complete REST API for Sprint 3.

Features:
- JWT authentication
- Multi-tenant isolation
- Comprehensive API endpoints
- Global rate limiting (100/min GET, 30/min mutations) with Redis storage
- Per-endpoint rate limit overrides (e.g. 5/min on login)
- Health monitoring
- OpenAPI documentation
"""

from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
from slowapi.errors import RateLimitExceeded
import logging
import time

from app.config import settings
from app.api.middleware import register_middleware
from app.metrics import PrometheusMiddleware, metrics_endpoint
from app.api.routers import (
    auth_router,
    tenants_router,
    assets_router,
    services_router,
    certificates_router,
    endpoints_router,
    findings_router,
    onboarding_router,
    scanning_router,
    projects_router,
    dashboard_router,
    graph_router,
    issues_router,
    alert_policies_router,
    reports_router,
    suppressions_router,
    threat_intel_admin_router,
    threat_intel_tenant_router,
    tickets_router,
    saml_router,
    siem_router,
    report_schedules_router,
    users_router,
    invitations_router,
    search_router,
    audit_router,
)

logger = logging.getLogger(__name__)

# Import shared rate limiter instance and constants
from app.rate_limiter import (
    limiter,
    MUTATION_DEFAULT_LIMIT,
    MUTATION_METHODS,
    RATE_LIMIT_EXEMPT_PATHS,
    _get_rate_limit_key,
)
from app.api.dependencies import get_current_user

# Create FastAPI app with comprehensive metadata
app = FastAPI(
    title=settings.app_name,
    description="""
# External Attack Surface Management (EASM) Platform API

A comprehensive platform for continuous attack surface discovery, monitoring, and vulnerability management.

## Features

- **Multi-tenant Architecture**: Complete tenant isolation with role-based access control
- **Asset Discovery**: Automated discovery of domains, subdomains, IPs, and services
- **Enrichment Pipeline**: Deep scanning with HTTPx, Naabu, TLSx, and Katana
- **Vulnerability Scanning**: Integrated Nuclei for CVE detection
- **Certificate Monitoring**: TLS/SSL certificate tracking and expiry alerts
- **Web Crawling**: Comprehensive endpoint discovery and API mapping
- **Dashboard & Analytics**: Rich statistics and trend analysis

## Authentication

All API endpoints (except /health and /api/v1/auth/login) require JWT authentication:

1. Login with credentials to receive access and refresh tokens
2. Include access token in Authorization header: `Bearer <token>`
3. Refresh token when it expires using /api/v1/auth/refresh

## Rate Limits

- **GET/HEAD/OPTIONS**: 100 requests per minute (global default)
- **POST/PUT/PATCH/DELETE**: 30 requests per minute (mutation default)
- Authenticated users are rate-limited by user ID; anonymous by IP
- Some endpoints have stricter limits (e.g. login: 5/min, registration: 3/hour)
- Redis-backed storage for accurate counting across workers

## Multi-tenancy

All data endpoints are tenant-scoped:
- Users can only access tenants they belong to
- Superusers have access to all tenants
- Tenant ID is part of the API path: `/api/v1/tenants/{tenant_id}/...`
    """,
    version="3.0.0",
    debug=settings.debug,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
    terms_of_service="https://example.com/terms",
    contact={
        "name": "EASM Platform Support",
        "url": "https://example.com/support",
        "email": "support@example.com"
    },
    license_info={
        "name": "Proprietary",
        "url": "https://example.com/license"
    }
)

# Add rate limiting state
app.state.limiter = limiter

# Middleware stack (order matters)
# 1. GZip compression for responses > 1KB
app.add_middleware(GZipMiddleware, minimum_size=1000)

# 2. CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=settings.cors_allow_credentials,
    allow_methods=settings.cors_allow_methods,
    allow_headers=settings.cors_allow_headers,
)

# 3. Security headers, request ID, request logging, trusted hosts (production)
register_middleware(app)

# 4. Prometheus request metrics
app.add_middleware(PrometheusMiddleware)


# ---------------------------------------------------------------------------
# Mutation rate-limiting middleware
# ---------------------------------------------------------------------------
# SlowAPI's ``default_limits`` covers ALL endpoints uniformly (100/min).
# This middleware adds a *stricter* layer for state-changing HTTP methods
# (POST/PUT/PATCH/DELETE) at 30/min.  It uses the ``limits`` library
# directly (already a transitive dependency of slowapi) so that we can
# keep a separate rate window without interfering with per-endpoint
# ``@limiter.limit()`` overrides.
#
# If an endpoint already has a specific ``@limiter.limit()`` decorator the
# SlowAPI handler enforces that limit.  This middleware adds an
# *additional* mutation budget on top (defense in depth).
# ---------------------------------------------------------------------------

# Initialise mutation limiter components once at module level.
# Wrapped in try/except so that import or connection errors do not
# prevent the application from starting.
_mutation_limiter_strategy = None
_mutation_rate = None

try:
    from limits import parse as _parse_rate
    from limits.storage import storage_from_string as _storage_from_string
    from limits.strategies import FixedWindowRateLimiter as _FixedWindowRateLimiter

    _mutation_rate = _parse_rate(MUTATION_DEFAULT_LIMIT)
    try:
        _mutation_storage = _storage_from_string(settings.redis_url)
    except (OSError, ValueError) as _redis_exc:
        logger.warning(
            "Redis unavailable for mutation rate limiter; falling back to in-memory storage: %s",
            _redis_exc,
        )
        _mutation_storage = _storage_from_string("memory://")
    _mutation_limiter_strategy = _FixedWindowRateLimiter(_mutation_storage)
except ImportError:
    logger.warning("limits library not available; mutation rate limiting will be disabled")
except (OSError, ValueError):
    logger.exception("Failed to initialise mutation rate limiter")


@app.middleware("http")
async def mutation_rate_limit_middleware(request: Request, call_next):
    """Enforce a stricter rate limit for mutation HTTP methods."""
    # Only apply to mutation methods
    if request.method not in MUTATION_METHODS:
        return await call_next(request)

    # Skip exempt paths (health, docs)
    if request.url.path in RATE_LIMIT_EXEMPT_PATHS:
        return await call_next(request)

    # Skip if mutation limiter was not initialised
    if _mutation_limiter_strategy is None or _mutation_rate is None:
        return await call_next(request)

    try:
        # Build key: "mutation_limit:<identity>"
        identity = _get_rate_limit_key(request)
        key = f"mutation_limit:{identity}"

        if not _mutation_limiter_strategy.hit(_mutation_rate, key):
            logger.warning(
                "Mutation rate limit exceeded for %s on %s %s",
                identity,
                request.method,
                request.url.path,
            )
            return JSONResponse(
                status_code=429,
                headers={"Retry-After": "60"},
                content={
                    "error": "RateLimitExceeded",
                    "detail": "Too many mutation requests. Please try again later.",
                    "status_code": 429,
                    "retry_after": 60,
                },
            )
    except Exception:
        # Rate limiting must never break the application; log and continue
        logger.exception("Mutation rate limit middleware error; skipping check")

    return await call_next(request)


# Exception handlers
@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    """Handle HTTP exceptions with consistent format"""
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": exc.__class__.__name__,
            "detail": exc.detail,
            "status_code": exc.status_code
        }
    )


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """Handle validation errors with detailed information"""
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "error": "ValidationError",
            "detail": "Request validation failed",
            "status_code": 422,
            "errors": exc.errors()
        }
    )


@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request: Request, exc: RateLimitExceeded):
    """
    Handle rate limit exceeded with Retry-After header.

    The Retry-After header tells clients how many seconds to wait before
    retrying.  This follows RFC 6585 Section 4 and RFC 7231 Section 7.1.3.
    """
    # Extract wait time from the exception detail if available
    retry_after = 60  # Default: retry after 60 seconds
    detail_str = str(getattr(exc, "detail", ""))
    # slowapi detail format: "Rate limit exceeded: N per M <period>"
    # Try to extract the period for a more accurate Retry-After
    if "per minute" in detail_str or "/minute" in detail_str:
        retry_after = 60
    elif "per hour" in detail_str or "/hour" in detail_str:
        retry_after = 3600
    elif "per second" in detail_str or "/second" in detail_str:
        retry_after = 1

    return JSONResponse(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        headers={"Retry-After": str(retry_after)},
        content={
            "error": "RateLimitExceeded",
            "detail": "Too many requests. Please try again later.",
            "status_code": 429,
            "retry_after": retry_after,
        },
    )


@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    """
    Handle all unhandled exceptions

    Security (Sprint 3 Enhancement):
        - Never expose internal details in production
        - Log full error server-side
        - Return generic message to client
        - Prevents information leakage via error messages

    OWASP: A09:2021 - Security Logging and Monitoring Failures
    """
    # Log full error with stack trace (server-side only)
    logger.error(
        f"Unhandled exception: {exc}",
        exc_info=True,
        extra={
            "path": request.url.path,
            "method": request.method,
            "client_ip": request.client.host if request.client else "unknown",
            "user_agent": request.headers.get("user-agent", "unknown")
        }
    )

    # Return generic error to client (environment-based)
    if settings.environment == "production":
        # Production: Generic message only (no internal details)
        detail = "Internal server error. Please contact support if this persists."
    else:
        # Development: Show error details for debugging
        detail = f"{exc.__class__.__name__}: {str(exc)}"

    return JSONResponse(
        status_code=500,
        content={
            "error": "InternalServerError",
            "detail": detail,
            "status_code": 500
        }
    )


# Root endpoint
@app.get("/", tags=["Root"])
@limiter.limit("60/minute")
def root(request: Request):
    """
    API root endpoint

    Returns basic API information and available endpoints
    """
    return {
        "message": "EASM Platform API",
        "version": "3.0.0",
        "sprint": "Sprint 3 - Complete REST API",
        "docs": "/api/docs",
        "health": "/health",
        "authentication": "/api/v1/auth/login"
    }

@app.get("/metrics", include_in_schema=False)
async def metrics(request: Request):
    """Prometheus metrics scrape endpoint (no auth required)."""
    return metrics_endpoint(request)


@app.get("/health")
def health_check():
    """
    Health check endpoint for load balancers.

    Returns only healthy/unhealthy status per service.
    Internal errors are logged server-side but never exposed to callers.
    """
    from app.database import engine
    import redis
    from minio import Minio
    from minio.error import S3Error

    health_status = {
        "status": "healthy",
        "services": {}
    }

    # Check PostgreSQL database
    try:
        from sqlalchemy import text
        with engine.connect() as conn:
            conn.execute(text("SELECT 1")).fetchone()
        health_status["services"]["database"] = "ok"
    except Exception as e:
        # Broad catch: any DB error (connection, auth, timeout) means unhealthy
        logger.error("Database health check failed: %s", e)
        health_status["services"]["database"] = "error"
        health_status["status"] = "unhealthy"

    # Check Redis
    try:
        r = redis.from_url(settings.redis_url, socket_connect_timeout=2)
        r.ping()
        r.close()
        health_status["services"]["redis"] = "ok"
    except Exception as e:
        # Broad catch: any Redis error (connection, auth, timeout) means unhealthy
        logger.error("Redis health check failed: %s", e)
        health_status["services"]["redis"] = "error"
        health_status["status"] = "unhealthy"

    # Check MinIO
    try:
        client = Minio(
            settings.minio_endpoint,
            access_key=settings.minio_access_key,
            secret_key=settings.minio_secret_key,
            secure=settings.minio_secure
        )
        list(client.list_buckets())
        health_status["services"]["minio"] = "ok"
    except Exception as e:
        # Broad catch: any MinIO/S3 error (connection, auth, timeout) means unhealthy
        logger.error("MinIO health check failed: %s", e)
        health_status["services"]["minio"] = "error"
        health_status["status"] = "unhealthy"

    # Return 503 if unhealthy so load balancers remove this instance
    if health_status["status"] == "unhealthy":
        raise HTTPException(status_code=503, detail={"status": "unhealthy"})

    return health_status

# Include routers
app.include_router(onboarding_router)  # Public onboarding (no auth required)
app.include_router(auth_router)
app.include_router(tenants_router)
app.include_router(assets_router)
app.include_router(services_router)
app.include_router(certificates_router)
app.include_router(endpoints_router)
app.include_router(findings_router)
app.include_router(scanning_router)
app.include_router(projects_router)
app.include_router(dashboard_router)
app.include_router(graph_router)
app.include_router(issues_router)
app.include_router(alert_policies_router)
app.include_router(reports_router)
app.include_router(suppressions_router)
app.include_router(threat_intel_admin_router)
app.include_router(threat_intel_tenant_router)
app.include_router(tickets_router)
app.include_router(saml_router)
app.include_router(siem_router)
app.include_router(report_schedules_router)
app.include_router(users_router)
app.include_router(invitations_router)
app.include_router(search_router)
app.include_router(audit_router)


# Startup and shutdown events
@app.on_event("startup")
async def startup_event():
    """
    Application startup event

    Performs initialization tasks:
    - Log startup information
    - Verify database connectivity
    - Initialize caches
    """
    from app.rate_limiter import GLOBAL_DEFAULT_LIMIT

    logger.info("="*80)
    logger.info(f"Starting {settings.app_name} v3.0.0")
    logger.info(f"Environment: {settings.environment}")
    logger.info(f"Debug mode: {settings.debug}")
    logger.info(f"API Documentation: http://{settings.api_host}:{settings.api_port}/api/docs")
    logger.info(f"Rate limits: GET={GLOBAL_DEFAULT_LIMIT}, mutations={MUTATION_DEFAULT_LIMIT}, storage=Redis")
    logger.info("="*80)

    # Test database connection
    try:
        from app.database import engine
        from sqlalchemy import text
        from sqlalchemy.exc import SQLAlchemyError
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        logger.info("Database connection: OK")
    except (SQLAlchemyError, OSError) as e:
        logger.error("Database connection failed: %s", e)

    # Test Redis connection
    try:
        import redis
        r = redis.from_url(settings.redis_url, socket_connect_timeout=2)
        r.ping()
        r.close()
        logger.info("Redis connection: OK")
    except (redis.exceptions.RedisError, OSError) as e:
        logger.error("Redis connection failed: %s", e)

    logger.info("Application startup complete")


@app.on_event("shutdown")
async def shutdown_event():
    """
    Application shutdown event

    Performs cleanup tasks:
    - Close database connections
    - Flush logs
    - Clean up resources
    """
    logger.info("Shutting down EASM Platform API...")
    logger.info("Shutdown complete")


# API Statistics endpoint (requires authentication)
@app.get("/api/v1/stats", tags=["System"])
async def api_stats(
    current_user=Depends(get_current_user),
):
    """
    Get API statistics (authenticated).
    """
    return {
        "version": settings.app_version,
    }


if __name__ == "__main__":
    import uvicorn

    logger.info(f"Starting server on {settings.api_host}:{settings.api_port}")

    uvicorn.run(
        app,
        host=settings.api_host,
        port=settings.api_port,
        reload=settings.api_reload,
        workers=1 if settings.api_reload else settings.api_workers,
        log_level=settings.log_level.lower()
    )
