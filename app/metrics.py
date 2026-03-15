"""
Prometheus metrics for EASM Platform.

Exposes request count, duration, active connections, and error rate.
"""

from __future__ import annotations

import logging
import time

from prometheus_client import Counter, Histogram, Gauge, generate_latest, CONTENT_TYPE_LATEST
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

logger = logging.getLogger(__name__)

# Metrics
REQUEST_COUNT = Counter(
    "easm_http_requests_total",
    "Total HTTP requests",
    ["method", "endpoint", "status_code"],
)

REQUEST_DURATION = Histogram(
    "easm_http_request_duration_seconds",
    "HTTP request duration in seconds",
    ["method", "endpoint"],
    buckets=(0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0),
)

ACTIVE_REQUESTS = Gauge(
    "easm_http_active_requests",
    "Currently active HTTP requests",
)

ERROR_COUNT = Counter(
    "easm_http_errors_total",
    "Total HTTP errors (4xx and 5xx)",
    ["method", "endpoint", "status_code"],
)


def _normalize_path(path: str) -> str:
    """Normalize URL path to reduce cardinality.

    Replace numeric path segments with {id} to prevent metric explosion.
    """
    parts = path.strip("/").split("/")
    normalized = []
    for part in parts:
        if part.isdigit():
            normalized.append("{id}")
        else:
            normalized.append(part)
    return "/" + "/".join(normalized) if normalized else "/"


class PrometheusMiddleware(BaseHTTPMiddleware):
    """Middleware to collect request metrics for Prometheus."""

    async def dispatch(self, request: Request, call_next):
        # Skip metrics endpoint itself
        if request.url.path == "/metrics":
            return await call_next(request)

        method = request.method
        path = _normalize_path(request.url.path)

        ACTIVE_REQUESTS.inc()
        start = time.perf_counter()

        try:
            response = await call_next(request)
        except Exception:
            ERROR_COUNT.labels(method=method, endpoint=path, status_code="500").inc()
            REQUEST_COUNT.labels(method=method, endpoint=path, status_code="500").inc()
            raise
        finally:
            duration = time.perf_counter() - start
            ACTIVE_REQUESTS.dec()
            REQUEST_DURATION.labels(method=method, endpoint=path).observe(duration)

        status = str(response.status_code)
        REQUEST_COUNT.labels(method=method, endpoint=path, status_code=status).inc()

        if response.status_code >= 400:
            ERROR_COUNT.labels(method=method, endpoint=path, status_code=status).inc()

        return response


def metrics_endpoint(request: Request) -> Response:
    """Prometheus metrics scrape endpoint."""
    return Response(
        content=generate_latest(),
        media_type=CONTENT_TYPE_LATEST,
    )
