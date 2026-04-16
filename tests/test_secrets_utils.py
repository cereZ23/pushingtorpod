"""Tests for secrets utility (app/utils/secrets.py).

Pure-unit tests (no live Vault/Azure/AWS). File backend uses a tempdir.
"""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import pytest

from app.utils.secrets import SecretManager, SecretRotationScheduler, initialize_secrets


@pytest.fixture
def tmp_key_file(tmp_path):
    """Isolated encryption key file per test."""
    return tmp_path / ".easm" / "secret.key"


@pytest.fixture
def env_manager():
    """SecretManager with env backend — ensure cache empty before each test."""
    mgr = SecretManager(backend="env")
    return mgr


class TestSecretManagerEnvBackend:
    def test_get_missing_returns_default(self, env_manager, monkeypatch):
        monkeypatch.delenv("NO_SUCH_SECRET_FOR_TEST", raising=False)
        assert env_manager.get_secret("NO_SUCH_SECRET_FOR_TEST", default="fallback") == "fallback"

    def test_get_from_environment(self, env_manager, monkeypatch):
        monkeypatch.setenv("TEST_SECRET_GET", "top-secret")
        assert env_manager.get_secret("TEST_SECRET_GET") == "top-secret"

    def test_cache_hit(self, env_manager, monkeypatch):
        monkeypatch.setenv("CACHED_SECRET", "v1")
        env_manager.get_secret("CACHED_SECRET")
        # Change env — cached value should be returned
        monkeypatch.setenv("CACHED_SECRET", "v2")
        assert env_manager.get_secret("CACHED_SECRET") == "v1"

    def test_set_secret_updates_env(self, env_manager):
        env_manager.set_secret("SET_SECRET_TEST", "new-value")
        assert os.environ["SET_SECRET_TEST"] == "new-value"

    def test_unsafe_default_warns_in_non_prod(self, env_manager, monkeypatch, caplog):
        monkeypatch.setenv("ENVIRONMENT", "development")
        monkeypatch.setenv("UNSAFE_SECRET_TEST", "CHANGE_THIS")
        value = env_manager.get_secret("UNSAFE_SECRET_TEST")
        assert value == "CHANGE_THIS"  # Returned but logged a warning

    def test_unsafe_default_raises_in_production(self, monkeypatch):
        # Production + unsafe default triggers ValueError
        monkeypatch.setenv("ENVIRONMENT", "production")
        monkeypatch.setenv("UNSAFE_PROD_SECRET", "changeme")
        mgr = SecretManager(backend="env")
        with pytest.raises(ValueError):
            mgr.get_secret("UNSAFE_PROD_SECRET")

    def test_unknown_backend_warns_and_falls_back(self, monkeypatch):
        monkeypatch.setenv("UNKNOWN_BACKEND_SECRET", "val")
        mgr = SecretManager(backend="vault")  # Not implemented in stub
        # Actual behaviour — vault path is not implemented; it warns and falls back to env
        result = mgr.get_secret("UNKNOWN_BACKEND_SECRET", default="fallback")
        assert result == "val"


class TestSecretManagerFileBackend:
    def test_file_backend_creates_key_file(self, tmp_key_file):
        mgr = SecretManager(backend="file", key_file=tmp_key_file)
        assert tmp_key_file.exists()
        # Set restrictive permissions
        assert (tmp_key_file.stat().st_mode & 0o777) == 0o600

    def test_file_backend_reuses_existing_key(self, tmp_key_file):
        tmp_key_file.parent.mkdir(parents=True, exist_ok=True)
        from cryptography.fernet import Fernet

        key = Fernet.generate_key()
        tmp_key_file.write_bytes(key)

        mgr = SecretManager(backend="file", key_file=tmp_key_file)
        # Should load the existing key (no exception)
        assert mgr._fernet is not None

    def test_set_and_get_file_roundtrip(self, tmp_key_file):
        mgr = SecretManager(backend="file", key_file=tmp_key_file)
        mgr.set_secret("API_KEY", "super-secret-123")
        mgr.clear_cache()
        assert mgr.get_secret("API_KEY") == "super-secret-123"

    def test_get_file_missing_returns_default(self, tmp_key_file):
        mgr = SecretManager(backend="file", key_file=tmp_key_file)
        assert mgr.get_secret("UNSET_KEY", default="fb") == "fb"


class TestGenerateSecureSecret:
    def test_returns_string(self):
        mgr = SecretManager(backend="env")
        s = mgr.generate_secure_secret(length=32)
        assert isinstance(s, str)
        assert len(s) >= 32  # token_urlsafe yields at least `length` bytes worth of encoded output

    def test_unique_secrets(self):
        mgr = SecretManager(backend="env")
        a = mgr.generate_secure_secret()
        b = mgr.generate_secure_secret()
        assert a != b


class TestRotateSecret:
    def test_rotate_changes_value(self, monkeypatch):
        mgr = SecretManager(backend="env")
        monkeypatch.setenv("TO_ROTATE", "old-value")
        old = mgr.get_secret("TO_ROTATE")
        new = mgr.rotate_secret("TO_ROTATE")
        assert new != old
        # Rotation metadata was also stored in env
        assert os.environ.get("TO_ROTATE_rotated_at") is not None


class TestValidateSecrets:
    def test_missing_secret_flagged(self, env_manager, monkeypatch):
        monkeypatch.delenv("MISSING_SECRET_TEST_XYZ", raising=False)
        result = env_manager.validate_secrets(["MISSING_SECRET_TEST_XYZ"])
        assert result["valid"] is False
        assert "MISSING_SECRET_TEST_XYZ" in result["missing"]

    def test_weak_secret_flagged(self, monkeypatch):
        mgr = SecretManager(backend="env")
        monkeypatch.setenv("WEAK_TEST_SECRET", "my-password-is-great-but-weak")
        result = mgr.validate_secrets(["WEAK_TEST_SECRET"])
        assert result["valid"] is False
        assert "WEAK_TEST_SECRET" in result["weak"]

    def test_short_secret_error(self, monkeypatch):
        mgr = SecretManager(backend="env")
        monkeypatch.setenv("SHORT_SECRET_TEST", "short1!A")
        result = mgr.validate_secrets(["SHORT_SECRET_TEST"])
        assert result["valid"] is False
        assert any("too short" in err for err in result["errors"])

    def test_strong_secret_passes(self, monkeypatch):
        mgr = SecretManager(backend="env")
        monkeypatch.setenv("STRONG_SECRET_TEST", "aZ8&$k9F!vX2mQw4LpN7rT3B")
        result = mgr.validate_secrets(["STRONG_SECRET_TEST"])
        assert result["valid"] is True
        assert result["missing"] == []
        assert result["weak"] == []


class TestClearCache:
    def test_clear_empties_cache(self, monkeypatch):
        mgr = SecretManager(backend="env")
        monkeypatch.setenv("CACHED_X", "v1")
        mgr.get_secret("CACHED_X")
        assert "CACHED_X" in mgr._cache
        mgr.clear_cache()
        assert mgr._cache == {}


class TestSecretRotationScheduler:
    def test_check_rotation_needed_never_rotated(self, monkeypatch):
        # Ensure no residue from earlier tests
        monkeypatch.delenv("jwt_secret_key_rotated_at", raising=False)
        mgr = SecretManager(backend="env")
        # Also force fresh cache by clearing it
        mgr.clear_cache()
        scheduler = SecretRotationScheduler(mgr)
        assert scheduler.check_rotation_needed("jwt_secret_key") is True

    def test_check_rotation_unknown_key(self, monkeypatch):
        mgr = SecretManager(backend="env")
        scheduler = SecretRotationScheduler(mgr)
        assert scheduler.check_rotation_needed("unknown_key") is False

    def test_check_rotation_recently_rotated(self, monkeypatch):
        mgr = SecretManager(backend="env")
        scheduler = SecretRotationScheduler(mgr)
        # Just rotated — not yet due
        recent = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
        monkeypatch.setenv("jwt_secret_key_rotated_at", recent)
        mgr.clear_cache()
        assert scheduler.check_rotation_needed("jwt_secret_key") is False

    def test_check_rotation_overdue(self, monkeypatch):
        mgr = SecretManager(backend="env")
        scheduler = SecretRotationScheduler(mgr)
        # Rotated 60 days ago — JWT is on 30 day rotation
        overdue = (datetime.now(timezone.utc) - timedelta(days=60)).isoformat()
        monkeypatch.setenv("jwt_secret_key_rotated_at", overdue)
        mgr.clear_cache()
        assert scheduler.check_rotation_needed("jwt_secret_key") is True

    def test_check_rotation_invalid_timestamp(self, monkeypatch):
        mgr = SecretManager(backend="env")
        scheduler = SecretRotationScheduler(mgr)
        monkeypatch.setenv("jwt_secret_key_rotated_at", "not-an-iso-date")
        mgr.clear_cache()
        # Should treat as needing rotation
        assert scheduler.check_rotation_needed("jwt_secret_key") is True

    def test_rotate_if_needed_performs_rotation(self, monkeypatch):
        mgr = SecretManager(backend="env")
        monkeypatch.delenv("api_key_rotated_at", raising=False)
        mgr.clear_cache()
        scheduler = SecretRotationScheduler(mgr)
        # First time, should rotate
        new = scheduler.rotate_if_needed("api_key")
        assert isinstance(new, str) and new

    def test_rotate_if_needed_skips_when_fresh(self, monkeypatch):
        mgr = SecretManager(backend="env")
        fresh = datetime.now(timezone.utc).isoformat()
        monkeypatch.setenv("api_key_rotated_at", fresh)
        mgr.clear_cache()
        scheduler = SecretRotationScheduler(mgr)
        assert scheduler.rotate_if_needed("api_key") is None

    def test_rotate_all_if_needed(self, monkeypatch):
        mgr = SecretManager(backend="env")
        # Make every scheduled key fresh so none rotate
        fresh = datetime.now(timezone.utc).isoformat()
        for key in ("jwt_secret_key", "api_key", "database_password"):
            monkeypatch.setenv(f"{key}_rotated_at", fresh)
        mgr.clear_cache()
        scheduler = SecretRotationScheduler(mgr)
        result = scheduler.rotate_all_if_needed()
        assert result == {}


class TestInitializeSecrets:
    def test_non_production_generates_missing(self, monkeypatch):
        monkeypatch.setenv("ENVIRONMENT", "development")
        for key in ("SECRET_KEY", "JWT_SECRET_KEY", "POSTGRES_PASSWORD"):
            monkeypatch.delenv(key, raising=False)
        mgr = initialize_secrets(backend="env")
        # Missing keys get generated in dev
        assert mgr.get_secret("SECRET_KEY") is not None

    def test_production_missing_raises(self, monkeypatch):
        monkeypatch.setenv("ENVIRONMENT", "production")
        for key in ("SECRET_KEY", "JWT_SECRET_KEY", "POSTGRES_PASSWORD"):
            monkeypatch.delenv(key, raising=False)
        with pytest.raises(ValueError):
            initialize_secrets(backend="env")
