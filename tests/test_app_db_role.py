"""The sync DB URL can use a dedicated app role (RLS); async/migrations stay owner."""

from unittest.mock import patch

from app.config import settings


def test_sync_url_prefers_app_db_user():
    with patch.object(settings, "app_db_user", "easm_app"), patch.object(settings, "app_db_password", "secret"):
        assert "://easm_app:secret@" in settings.database_url


def test_sync_url_falls_back_to_postgres_user():
    with patch.object(settings, "app_db_user", None), patch.object(settings, "app_db_password", None):
        assert f"://{settings.postgres_user}:{settings.postgres_password}@" in settings.database_url


def test_async_url_always_uses_postgres_user():
    # async engine must NOT use the app role (asyncpg + RLS GUC issue)
    with patch.object(settings, "app_db_user", "easm_app"), patch.object(settings, "app_db_password", "secret"):
        assert f"://{settings.postgres_user}:" in settings.async_database_url
        assert "easm_app" not in settings.async_database_url
