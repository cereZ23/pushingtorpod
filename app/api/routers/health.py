"""
Health check API router.

Provides liveness and readiness probes for load balancers and
orchestrators (e.g. Kubernetes, Docker health checks).

Endpoints:
    GET /health    - Liveness probe (DB + Redis)
    GET /ready     - Readiness probe (DB + Redis + Celery worker)
    GET /metrics   - App-level metrics (assets, findings, scans, uptime)

These endpoints do NOT require authentication.
"""

from __future__ import annotations

import logging
import time

import redis
from fastapi import APIRouter, Response
from fastapi.responses import JSONResponse
from sqlalchemy import func, text

from app.config import settings
from app.database import engine

logger = logging.getLogger(__name__)

router = APIRouter(tags=["Health"])

_start_time = time.monotonic()


def _check_database() -> str:
    """Verify database connectivity with a lightweight query."""
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1")).fetchone()
        return "ok"
    except Exception as exc:
        logger.error("Database health check failed: %s", exc)
        return "error"


def _check_redis() -> str:
    """Verify Redis connectivity with a PING command."""
    try:
        r = redis.from_url(settings.redis_url, socket_connect_timeout=2)
        r.ping()
        r.close()
        return "ok"
    except Exception as exc:
        logger.error("Redis health check failed: %s", exc)
        return "error"


def _check_worker() -> str:
    """Ping Celery workers to verify at least one is responsive."""
    try:
        from app.celery_app import celery as celery_app

        response = celery_app.control.ping(timeout=2)
        if response:
            return "ok"
        return "unknown"
    except Exception as exc:
        logger.warning("Celery worker ping failed: %s", exc)
        return "unknown"


@router.get("/health")
def liveness() -> Response:
    """
    Liveness probe.

    Checks database and Redis connectivity.
    Returns 200 when all checks pass, 503 when any check fails.
    """
    db_status = _check_database()
    redis_status = _check_redis()

    checks = {
        "database": db_status,
        "redis": redis_status,
    }

    healthy = all(v == "ok" for v in checks.values())

    payload = {
        "status": "ok" if healthy else "error",
        "checks": checks,
    }

    status_code = 200 if healthy else 503
    return JSONResponse(content=payload, status_code=status_code)


@router.get("/ready")
def readiness() -> Response:
    """
    Readiness probe.

    Checks database, Redis, and Celery worker availability.
    Returns 503 if database or Redis are unreachable.
    A worker being "unknown" is acceptable (does not cause 503).
    """
    db_status = _check_database()
    redis_status = _check_redis()
    worker_status = _check_worker()

    checks = {
        "database": db_status,
        "redis": redis_status,
        "worker": worker_status,
    }

    # Worker "unknown" is tolerable; only DB/Redis failures make us unready
    core_healthy = db_status == "ok" and redis_status == "ok"

    payload = {
        "status": "ready" if core_healthy else "error",
        "checks": checks,
    }

    status_code = 200 if core_healthy else 503
    return JSONResponse(content=payload, status_code=status_code)


@router.get("/health/metrics")
def health_metrics() -> Response:
    """
    App-level business metrics for monitoring dashboards.

    Returns tenant count, asset/finding totals, scan run stats,
    and process uptime. Complements Prometheus /metrics with
    business-level counters. Does NOT require authentication.
    """
    from app.database import SessionLocal
    from app.models.database import Tenant, Asset, Finding, FindingStatus

    uptime_seconds = round(time.monotonic() - _start_time, 1)
    data: dict = {"uptime_seconds": uptime_seconds}

    try:
        db = SessionLocal()
        try:
            data["tenants"] = db.execute(text("SELECT count(*) FROM tenants")).scalar()
            data["assets_active"] = db.execute(text("SELECT count(*) FROM assets WHERE is_active = true")).scalar()
            data["findings_open"] = db.execute(text("SELECT count(*) FROM findings WHERE status = 'open'")).scalar()

            scan_row = db.execute(
                text(
                    "SELECT count(*), "
                    "       count(*) FILTER (WHERE status = 'completed'), "
                    "       count(*) FILTER (WHERE status = 'failed') "
                    "FROM scan_runs"
                )
            ).fetchone()
            if scan_row:
                data["scan_runs_total"] = scan_row[0]
                data["scan_runs_completed"] = scan_row[1]
                data["scan_runs_failed"] = scan_row[2]
        finally:
            db.close()
    except Exception as exc:
        logger.error("Metrics query failed: %s", exc)
        data["error"] = "metrics_query_failed"

    db_status = _check_database()
    redis_status = _check_redis()
    data["database"] = db_status
    data["redis"] = redis_status

    return JSONResponse(content=data)
