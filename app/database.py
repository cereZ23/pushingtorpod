"""
Database connection and session management

Provides both sync and async SQLAlchemy engines with optimized
connection pooling and session factories for dependency injection.

Sync engine (engine / SessionLocal / get_db):
    Used by the majority of endpoints and all Celery tasks.

Async engine (async_engine / AsyncSessionLocal / get_async_db):
    Used by high-traffic endpoints converted to async for better
    concurrency under load.
"""

from collections.abc import AsyncGenerator
from typing import Generator

from sqlalchemy import create_engine, event
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import Pool
import logging

from app.config import settings

logger = logging.getLogger(__name__)

# ─── Sync engine (production default) ────────────────────────────

engine = create_engine(
    settings.database_url,
    pool_pre_ping=settings.postgres_pool_pre_ping,
    pool_size=settings.postgres_pool_size,
    max_overflow=settings.postgres_max_overflow,
    pool_recycle=settings.postgres_pool_recycle,
    echo=settings.debug,
)


@event.listens_for(Pool, "connect")
def set_postgres_pragmas(dbapi_conn, connection_record):
    """Set PostgreSQL connection parameters"""
    cursor = dbapi_conn.cursor()
    cursor.execute("SET statement_timeout = 30000")  # 30 seconds
    cursor.close()


@event.listens_for(Pool, "checkout")
def receive_checkout(dbapi_conn, connection_record, connection_proxy):
    """Log connection checkout for monitoring"""
    logger.debug("Database connection checked out from pool")


@event.listens_for(engine, "before_cursor_execute")
def _apply_tenant_guc(conn, cursor, statement, parameters, context, executemany):
    """Push the active tenant into a transaction-local GUC for Postgres RLS.

    RLS policies read ``app.current_tenant_id`` / ``app.cross_tenant``. Setting
    them (transaction-local) before every statement keeps them in sync with the
    request/task tenant context even when the context is set mid-transaction
    (e.g. the scan pipeline). No-op behaviour while the app connects as the DB
    owner (which bypasses RLS); it becomes load-bearing after the cutover to the
    non-owner role. Fail-open: never break a query if the GUC set fails.
    """
    try:
        from app.core.tenant_context import get_current_tenant, is_cross_tenant_allowed

        tid = get_current_tenant()
        cursor.execute("SELECT set_config('app.current_tenant_id', %s, true)", ("" if tid is None else str(tid),))
        cursor.execute(
            "SELECT set_config('app.cross_tenant', %s, true)", ("on" if is_cross_tenant_allowed() else "off",)
        )
    except Exception:  # pragma: no cover - defensive
        pass


SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db() -> Generator[Session, None, None]:
    """Sync database session dependency (used by most endpoints)."""
    db = SessionLocal()
    try:
        yield db
    except Exception as e:
        logger.error(f"Database session error: {e}")
        db.rollback()
        raise
    finally:
        db.close()


# ─── Async engine ────────────────────────────────────────────────

async_engine = create_async_engine(
    settings.async_database_url,
    pool_pre_ping=True,
    pool_size=settings.postgres_pool_size,
    max_overflow=settings.postgres_max_overflow,
    pool_recycle=settings.postgres_pool_recycle,
    echo=settings.debug,
)

AsyncSessionLocal = async_sessionmaker(
    async_engine,
    class_=AsyncSession,
    expire_on_commit=False,
)

# Apply the same tenant GUC on the async engine (runs in SQLAlchemy's greenlet).
event.listen(async_engine.sync_engine, "before_cursor_execute", _apply_tenant_guc)


async def get_async_db() -> AsyncGenerator[AsyncSession, None]:
    """Async database session dependency for high-traffic endpoints."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
        except Exception as e:
            logger.error(f"Async database session error: {e}")
            await session.rollback()
            raise


# ─── Tenant isolation guard ──────────────────────────────────────
# Importing registers the do_orm_execute listener (audit mode by default).
from app.core.tenant_guard import register_tenant_guard  # noqa: E402

register_tenant_guard()
