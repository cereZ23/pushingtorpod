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


def _get_fernet():
    """Lazy-init Fernet cipher from MFA_ENCRYPTION_KEY setting."""
    global _fernet_instance
    if _fernet_instance is None:
        key = settings.mfa_encryption_key
        if not key:
            return None
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
    """
    f = _get_fernet()
    if f is None:
        logger.debug("MFA encryption key not configured — storing plaintext (dev mode)")
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
