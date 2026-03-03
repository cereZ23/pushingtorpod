"""
Encryption utilities for ticketing configuration secrets.

Uses AES-GCM (via Fernet-compatible API from the cryptography library)
to encrypt/decrypt ticketing provider credentials before storing them
in the database.

The encryption key is derived from settings.secret_key using PBKDF2.
"""

import base64
import json
import logging
from typing import Optional

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

logger = logging.getLogger(__name__)

# Static salt - combined with the secret_key to derive the Fernet key.
# In a production system this could be per-tenant, but for simplicity
# we use a fixed salt since secret_key already provides entropy.
_SALT = b"easm-ticketing-config-v1"


def _derive_key(secret_key: str) -> bytes:
    """
    Derive a 32-byte Fernet key from the application secret_key.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=_SALT,
        iterations=480_000,
    )
    return base64.urlsafe_b64encode(kdf.derive(secret_key.encode("utf-8")))


def encrypt_config(config: dict, secret_key: str) -> str:
    """
    Encrypt a configuration dictionary to a base64-encoded string.

    Args:
        config: Plain-text configuration dict (e.g., {url, email, api_token, ...})
        secret_key: Application secret key for key derivation.

    Returns:
        Encrypted, base64-encoded string suitable for storage in TEXT column.
    """
    key = _derive_key(secret_key)
    fernet = Fernet(key)
    plaintext = json.dumps(config).encode("utf-8")
    return fernet.encrypt(plaintext).decode("utf-8")


def decrypt_config(encrypted: str, secret_key: str) -> Optional[dict]:
    """
    Decrypt an encrypted configuration string back to a dictionary.

    Args:
        encrypted: Encrypted base64-encoded string from the database.
        secret_key: Application secret key for key derivation.

    Returns:
        Decrypted configuration dict, or None if decryption fails.
    """
    try:
        key = _derive_key(secret_key)
        fernet = Fernet(key)
        plaintext = fernet.decrypt(encrypted.encode("utf-8"))
        return json.loads(plaintext.decode("utf-8"))
    except (InvalidToken, json.JSONDecodeError, Exception) as exc:
        logger.error("Failed to decrypt ticketing config: %s", type(exc).__name__)
        return None


def mask_config(config: dict) -> dict:
    """
    Return a copy of the config with sensitive fields masked.

    Used for API responses so credentials are never exposed.
    """
    sensitive_keys = {"api_token", "password", "secret", "token", "private_key"}
    masked = {}
    for key, value in config.items():
        if key.lower() in sensitive_keys and isinstance(value, str) and len(value) > 4:
            masked[key] = value[:2] + "*" * (len(value) - 4) + value[-2:]
        else:
            masked[key] = value
    return masked
