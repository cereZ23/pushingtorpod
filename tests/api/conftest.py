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

    Overrides both get_db locations (app.database and app.api.dependencies)
    so every router uses the transactional test session.
    No authentication override — callers get 401 on protected endpoints,
    which is the correct behaviour for unauthenticated tests.
    """
    from app.main import app
    from app.api.dependencies import get_db as deps_get_db
    from app.database import get_db as db_get_db

    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    app.dependency_overrides[deps_get_db] = override_get_db
    app.dependency_overrides[db_get_db] = override_get_db

    test_client = TestClient(app)
    yield test_client

    app.dependency_overrides.clear()
