"""
Encryption utilities for sensitive data at rest.

Provides Fernet (AES-128-CBC + HMAC-SHA256) encryption for secrets
like MFA TOTP keys that must be stored in the database but need
protection against database compromise.
"""

from __future__ import annotations

import logging
from typing import Optional

from app.config import settings

logger = logging.getLogger(__name__)

_fernet_instance = None
_fernet_checked = False


def _get_fernet():
    """Lazy-init Fernet cipher from MFA_ENCRYPTION_KEY setting.

    In production, raises RuntimeError immediately if the key is missing
    so the application refuses to operate without proper encryption.
    In non-production environments (development, test), returns None to
    allow plaintext fallback.
    """
    global _fernet_instance, _fernet_checked
    if not _fernet_checked:
        _fernet_checked = True
        key = settings.mfa_encryption_key
        if not key:
            if settings.environment == "production":
                raise RuntimeError(
                    "MFA_ENCRYPTION_KEY must be set in production. "
                    "Refusing to start: MFA secrets cannot be stored "
                    "or decrypted with a missing encryption key."
                )
            logger.warning(
                "MFA_ENCRYPTION_KEY not configured — MFA secrets will be "
                "stored in plaintext (acceptable in %s environment only)",
                settings.environment,
            )
        else:
            from cryptography.fernet import Fernet
            _fernet_instance = Fernet(key.encode())
    return _fernet_instance


def encrypt_mfa_secret(plaintext: str) -> str:
    """Encrypt an MFA TOTP secret for storage.

    If no encryption key is configured (dev mode), returns plaintext unchanged.
    Encrypted values are prefixed with ``enc:`` so we can distinguish them
    from legacy plaintext values during migration.

    Args:
        plaintext: Base32-encoded TOTP secret.

    Returns:
        Encrypted string prefixed with ``enc:`` or plaintext if no key.

    Raises:
        RuntimeError: If called in production without MFA_ENCRYPTION_KEY.
    """
    f = _get_fernet()
    if f is None:
        # Non-production: _get_fernet already logged a warning
        return plaintext
    token = f.encrypt(plaintext.encode()).decode()
    return f"enc:{token}"


def decrypt_mfa_secret(stored: str) -> str:
    """Decrypt an MFA TOTP secret from storage.

    Handles both encrypted (``enc:`` prefix) and legacy plaintext values,
    enabling transparent migration.

    Args:
        stored: Value from the ``mfa_secret`` database column.

    Returns:
        Plaintext Base32-encoded TOTP secret.
    """
    if not stored.startswith("enc:"):
        # Legacy plaintext value — return as-is
        return stored
    f = _get_fernet()
    if f is None:
        raise ValueError(
            "MFA_ENCRYPTION_KEY is required to decrypt MFA secrets "
            "but is not configured"
        )
    encrypted_token = stored[4:]  # strip "enc:" prefix
    return f.decrypt(encrypted_token.encode()).decode()
