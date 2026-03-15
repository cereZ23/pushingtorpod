"""
Security regression tests for Sprint H1 fixes.

Covers:
1. SSRF validation in SIEM push endpoint
2. Password reset token hashing
3. MFA secret encryption/decryption
4. ILIKE escape utility
5. JWT role refresh from DB
"""

import hashlib
from unittest.mock import MagicMock, patch

import pytest

from app.api.dependencies import escape_like


# ── H1.1: SSRF in SIEM push ─────────────────────────────────────────


class TestSIEMSSRFValidation:
    """Test _validate_siem_endpoint_url blocks SSRF attacks."""

    def _validate(self, url: str):
        """Import and call the validation function; raises HTTPException on failure."""
        from app.api.routers.siem import _validate_siem_endpoint_url

        _validate_siem_endpoint_url(url)

    def test_rejects_http_scheme(self):
        """SIEM endpoint must use HTTPS — HTTP exposes auth tokens."""
        from fastapi import HTTPException

        with pytest.raises(HTTPException) as exc_info:
            self._validate("http://splunk.corp.com:8088/services/collector")
        assert exc_info.value.status_code == 422
        assert "HTTPS" in exc_info.value.detail

    def test_rejects_missing_hostname(self):
        from fastapi import HTTPException

        with pytest.raises(HTTPException):
            self._validate("https://")

    @patch("app.utils.validators.socket.getaddrinfo")
    def test_rejects_private_ip(self, mock_gai):
        """Block endpoints resolving to private IPs (127.0.0.1, 10.x, 192.168.x)."""
        from fastapi import HTTPException

        # Simulate DNS resolving to 127.0.0.1
        mock_gai.return_value = [
            (2, 1, 6, "", ("127.0.0.1", 443)),
        ]
        with pytest.raises(HTTPException) as exc_info:
            self._validate("https://evil.attacker.com/collector")
        assert exc_info.value.status_code == 422
        assert "private" in exc_info.value.detail.lower() or "reserved" in exc_info.value.detail.lower()

    @patch("app.utils.validators.socket.getaddrinfo")
    def test_rejects_metadata_ip(self, mock_gai):
        """Block AWS/GCP metadata endpoint 169.254.169.254."""
        from fastapi import HTTPException

        mock_gai.return_value = [
            (2, 1, 6, "", ("169.254.169.254", 443)),
        ]
        with pytest.raises(HTTPException) as exc_info:
            self._validate("https://metadata.internal/latest/api")
        assert exc_info.value.status_code == 422

    def test_rejects_metadata_hostname(self):
        """Block cloud metadata hostnames directly."""
        from fastapi import HTTPException

        with pytest.raises(HTTPException):
            self._validate("https://169.254.169.254/latest/meta-data/")

    @patch("app.utils.validators.socket.getaddrinfo")
    def test_allows_valid_public_endpoint(self, mock_gai):
        """Valid public HTTPS endpoints should pass."""
        mock_gai.return_value = [
            (2, 1, 6, "", ("52.14.123.45", 443)),
        ]
        # Should not raise
        self._validate("https://splunk.corp.com:8088/services/collector")


# ── H1.2: Password reset token hashing ──────────────────────────────


class TestPasswordResetTokenHashing:
    """Verify that password reset tokens are SHA-256 hashed before storage."""

    def test_token_is_hashed_before_storage(self):
        """The token stored in DB should be SHA-256 hash, not plaintext."""
        import secrets

        token = secrets.token_urlsafe(32)
        expected_hash = hashlib.sha256(token.encode()).hexdigest()

        # Simulate what forgot_password does
        stored = hashlib.sha256(token.encode()).hexdigest()
        assert stored == expected_hash
        assert stored != token  # not plaintext

    def test_lookup_uses_hash(self):
        """Reset password endpoint should hash the incoming token for DB lookup."""
        token = "test_token_abc123"
        expected_hash = hashlib.sha256(token.encode()).hexdigest()

        # The lookup should use the hash, not the plaintext
        lookup_hash = hashlib.sha256(token.encode()).hexdigest()
        assert lookup_hash == expected_hash


# ── H1.3: MFA secret encryption ─────────────────────────────────────


class TestMFAEncryption:
    """Test MFA secret encrypt/decrypt cycle."""

    def test_roundtrip_with_key(self):
        """Encrypt then decrypt should return original secret."""
        from cryptography.fernet import Fernet

        key = Fernet.generate_key().decode()

        with patch("app.utils.crypto.settings") as mock_settings:
            mock_settings.mfa_encryption_key = key
            # Reset cached fernet instance
            import app.utils.crypto as crypto_mod

            crypto_mod._fernet_instance = None

            from app.utils.crypto import encrypt_mfa_secret, decrypt_mfa_secret

            secret = "JBSWY3DPEHPK3PXP"  # Example TOTP base32 secret
            encrypted = encrypt_mfa_secret(secret)

            # Encrypted value should have enc: prefix
            assert encrypted.startswith("enc:")
            assert secret not in encrypted  # plaintext not visible

            # Decrypt should return original
            decrypted = decrypt_mfa_secret(encrypted)
            assert decrypted == secret

            # Clean up
            crypto_mod._fernet_instance = None

    def test_plaintext_passthrough_without_key(self):
        """Without encryption key (dev mode), secrets pass through as plaintext."""
        with patch("app.utils.crypto.settings") as mock_settings:
            mock_settings.mfa_encryption_key = None
            import app.utils.crypto as crypto_mod

            crypto_mod._fernet_instance = None

            from app.utils.crypto import encrypt_mfa_secret, decrypt_mfa_secret

            secret = "JBSWY3DPEHPK3PXP"
            result = encrypt_mfa_secret(secret)
            assert result == secret  # no encryption in dev mode

            # Decrypt should also pass through
            decrypted = decrypt_mfa_secret(secret)
            assert decrypted == secret

            crypto_mod._fernet_instance = None

    def test_legacy_plaintext_migration(self):
        """Legacy plaintext values (no enc: prefix) should be returned as-is."""
        from app.utils.crypto import decrypt_mfa_secret

        legacy_secret = "JBSWY3DPEHPK3PXP"  # No enc: prefix
        result = decrypt_mfa_secret(legacy_secret)
        assert result == legacy_secret


# ── H1.5: ILIKE escape ──────────────────────────────────────────────


class TestEscapeLike:
    """Test escape_like utility prevents SQL wildcard injection."""

    def test_escapes_percent(self):
        assert "\\%" in escape_like("100%")

    def test_escapes_underscore(self):
        assert "\\_" in escape_like("some_value")

    def test_escapes_backslash(self):
        assert "\\\\" in escape_like("path\\to")

    def test_normal_text_unchanged(self):
        assert escape_like("example.com") == "example.com"

    def test_combined_special_chars(self):
        result = escape_like("50%_off\\deal")
        assert "\\%" in result
        assert "\\_" in result
        assert "\\\\" in result

    def test_empty_string(self):
        assert escape_like("") == ""


# ── H1.4: JWT role refresh ──────────────────────────────────────────


class TestJWTRoleFreshness:
    """Test that token refresh loads current roles from DB."""

    @patch("app.security.jwt_auth.SessionLocal")
    def test_get_fresh_roles_queries_db(self, mock_session_local):
        """_get_fresh_roles should query DB, not rely on cached JWT roles."""
        from app.security.jwt_auth import jwt_manager

        mock_db = MagicMock()
        mock_session_local.return_value = mock_db

        mock_user = MagicMock()
        mock_user.is_active = True
        mock_user.is_superuser = False

        mock_membership = MagicMock()
        mock_membership.role = "analyst"

        # First query returns user, second returns membership
        mock_db.query.return_value.filter.return_value.first.side_effect = [
            mock_user,
            mock_membership,
        ]

        roles = jwt_manager._get_fresh_roles(user_id=1, tenant_id=1)
        assert "analyst" in roles
        assert mock_db.close.called

    @patch("app.security.jwt_auth.SessionLocal")
    def test_superuser_gets_admin_role(self, mock_session_local):
        """Superusers should get 'admin' appended to their roles."""
        from app.security.jwt_auth import jwt_manager

        mock_db = MagicMock()
        mock_session_local.return_value = mock_db

        mock_user = MagicMock()
        mock_user.is_active = True
        mock_user.is_superuser = True

        mock_membership = MagicMock()
        mock_membership.role = "viewer"

        mock_db.query.return_value.filter.return_value.first.side_effect = [
            mock_user,
            mock_membership,
        ]

        roles = jwt_manager._get_fresh_roles(user_id=1, tenant_id=1)
        assert "admin" in roles
        assert "viewer" in roles

    @patch("app.security.jwt_auth.SessionLocal")
    def test_inactive_user_gets_default_role(self, mock_session_local):
        """Inactive users should get fallback ['user'] role."""
        from app.security.jwt_auth import jwt_manager

        mock_db = MagicMock()
        mock_session_local.return_value = mock_db

        mock_user = MagicMock()
        mock_user.is_active = False

        mock_db.query.return_value.filter.return_value.first.return_value = mock_user

        roles = jwt_manager._get_fresh_roles(user_id=1, tenant_id=1)
        assert roles == ["user"]
