"""Tests for JWT/API-key pure functions in app/utils/auth.py.

Focuses on functions that do NOT require DB access:
- create_access_token / create_refresh_token
- verify_token
- generate_api_key / hash_api_key
- AuthenticationError / AuthorizationError exception classes
"""

from __future__ import annotations

from datetime import timedelta
from unittest.mock import patch

import pytest

from app.utils.auth import (
    AuthenticationError,
    AuthorizationError,
    create_access_token,
    create_refresh_token,
    generate_api_key,
    hash_api_key,
    verify_token,
)


# Use HS256 for tests (no key pair required).
@pytest.fixture(autouse=True)
def _use_hs256_algorithm():
    with patch("app.utils.auth.settings") as mock_settings:
        mock_settings.jwt_secret_key = "test-hs256-secret-key-32-chars!!"
        mock_settings.jwt_algorithm = "HS256"
        mock_settings.jwt_access_token_expire_minutes = 30
        mock_settings.jwt_refresh_token_expire_days = 7
        yield mock_settings


class TestCreateAccessToken:
    def test_returns_string(self):
        token = create_access_token(user_id=1, email="u@example.com")
        assert isinstance(token, str)
        assert len(token) > 0
        # JWT has 3 dot-separated segments
        assert token.count(".") == 2

    def test_payload_round_trip(self):
        token = create_access_token(user_id=42, email="x@example.com")
        decoded = verify_token(token)
        assert decoded["sub"] == "42"
        assert decoded["email"] == "x@example.com"
        assert decoded["type"] == "access"

    def test_custom_expires_delta(self):
        token = create_access_token(user_id=1, email="a@b.c", expires_delta=timedelta(minutes=1))
        decoded = verify_token(token)
        # Token should be decodable and have valid exp claim
        assert "exp" in decoded
        assert "iat" in decoded


class TestCreateRefreshToken:
    def test_returns_string(self):
        token = create_refresh_token(user_id=10, email="r@example.com")
        assert isinstance(token, str)
        assert token.count(".") == 2

    def test_payload_has_refresh_type(self):
        token = create_refresh_token(user_id=10, email="r@example.com")
        decoded = verify_token(token)
        assert decoded["type"] == "refresh"
        assert decoded["sub"] == "10"
        assert decoded["email"] == "r@example.com"


class TestVerifyToken:
    def test_invalid_token_raises(self):
        with pytest.raises(AuthenticationError):
            verify_token("not-a-jwt")

    def test_tampered_token_raises(self):
        token = create_access_token(user_id=1, email="a@b.c")
        tampered = token[:-5] + "AAAAA"
        with pytest.raises(AuthenticationError):
            verify_token(tampered)

    def test_wrong_signature_raises(self):
        token = create_access_token(user_id=1, email="a@b.c")
        with patch("app.utils.auth.settings") as mock_settings:
            mock_settings.jwt_secret_key = "different-secret-key-32-bytes-ok"
            mock_settings.jwt_algorithm = "HS256"
            with pytest.raises(AuthenticationError):
                verify_token(token)

    def test_expired_token_raises(self):
        # Expired 1 minute ago
        token = create_access_token(user_id=1, email="a@b.c", expires_delta=timedelta(minutes=-1))
        with pytest.raises(AuthenticationError):
            verify_token(token)


class TestGenerateApiKey:
    def test_returns_hex_string(self):
        key = generate_api_key()
        assert isinstance(key, str)
        assert len(key) == 64  # 32 bytes → 64 hex chars
        int(key, 16)  # valid hex

    def test_unique_keys(self):
        k1 = generate_api_key()
        k2 = generate_api_key()
        assert k1 != k2


class TestHashApiKey:
    def test_returns_64_char_hex(self):
        h = hash_api_key("my-test-key")
        assert len(h) == 64
        int(h, 16)

    def test_deterministic(self):
        h1 = hash_api_key("same-key")
        h2 = hash_api_key("same-key")
        assert h1 == h2

    def test_different_keys_different_hashes(self):
        h1 = hash_api_key("key-a")
        h2 = hash_api_key("key-b")
        assert h1 != h2

    def test_different_secrets_different_hashes(self):
        h_default = hash_api_key("same")
        with patch("app.utils.auth.settings") as mock_settings:
            mock_settings.jwt_secret_key = "totally-different-secret-pad-bytes"
            mock_settings.jwt_algorithm = "HS256"
            h_other = hash_api_key("same")
        assert h_default != h_other


class TestExceptionClasses:
    def test_authentication_error_is_exception(self):
        assert issubclass(AuthenticationError, Exception)
        err = AuthenticationError("bad creds")
        assert str(err) == "bad creds"

    def test_authorization_error_is_exception(self):
        assert issubclass(AuthorizationError, Exception)
        err = AuthorizationError("no access")
        assert str(err) == "no access"
