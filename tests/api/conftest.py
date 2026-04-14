"""
Shared fixtures for API tests.

Provides a working api_client fixture that overrides the database dependency
so tests run against the test PostgreSQL database without needing MinIO or
external tools.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def api_client(db_session):
    """FastAPI test client with test database injected.

    Overrides sync and async get_db locations so every router uses the
    transactional test session.  Disables rate limiting to prevent
    cross-test 429 interference.
    """
    from app.main import app
    from app.api.dependencies import get_db as deps_get_db, get_async_db
    from app.database import get_db as db_get_db

    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    async def override_get_async_db():
        """Yield the sync session for async endpoints.

        TestClient runs everything in a synchronous context so the
        sync session works here.
        """
        yield db_session

    app.dependency_overrides[deps_get_db] = override_get_db
    app.dependency_overrides[db_get_db] = override_get_db
    app.dependency_overrides[get_async_db] = override_get_async_db

    # Disable rate limiter for test isolation
    if hasattr(app.state, "limiter"):
        app.state.limiter.enabled = False

    test_client = TestClient(app)
    yield test_client

    app.dependency_overrides.clear()
    # Re-enable rate limiter
    if hasattr(app.state, "limiter"):
        app.state.limiter.enabled = True
