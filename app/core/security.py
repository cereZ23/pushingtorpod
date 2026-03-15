"""
Security utilities for EASM Platform

Implements:
- RS256/HS256 key management (SecurityKeys) — used by jwt_auth.JWTManager
- Password hashing with bcrypt (cost factor 12)
- API key generation and validation
- Cryptographic utilities (constant-time compare, token hashing)

JWT token creation/verification/revocation lives in app.security.jwt_auth
(single canonical implementation).

OWASP References:
- A02:2021 - Cryptographic Failures
- A07:2021 - Identification and Authentication Failures
"""

import os
import secrets
import hmac
import hashlib
import logging
from typing import Optional, Tuple
from pathlib import Path

from passlib.context import CryptContext
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import redis

from app.config import settings

logger = logging.getLogger(__name__)

# Password hashing context with bcrypt cost factor 12 (OWASP recommended)
pwd_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto",
    bcrypt__rounds=12  # Cost factor for bcrypt (higher = slower but more secure)
)


class SecurityKeys:
    """
    Manage JWT signing keys (RSA for production, HMAC for development)

    Production: Uses RS256 with RSA key pairs (private key for signing, public for verification)
    Development: Uses HS256 with symmetric secret (fallback for easier setup)
    """

    def __init__(self):
        self.algorithm = settings.jwt_algorithm
        self.private_key = None
        self.public_key = None
        self.secret_key = None

        if self.algorithm.startswith('RS'):
            # RSA keys for production (asymmetric)
            self._load_or_generate_rsa_keys()
        else:
            # Symmetric secret for development (HS256)
            self.secret_key = settings.jwt_secret_key

    def _load_or_generate_rsa_keys(self):
        """Load or generate RSA key pair for JWT signing"""
        private_key_path = Path("keys/jwt_private.pem")
        public_key_path = Path("keys/jwt_public.pem")

        try:
            if private_key_path.exists() and public_key_path.exists():
                # Load existing keys
                passphrase = settings.jwt_private_key_passphrase
                with open(private_key_path, "rb") as f:
                    self.private_key = serialization.load_pem_private_key(
                        f.read(),
                        password=passphrase.encode() if passphrase else None,
                        backend=default_backend()
                    )
                with open(public_key_path, "rb") as f:
                    self.public_key = serialization.load_pem_public_key(
                        f.read(),
                        backend=default_backend()
                    )
                logger.info("Loaded RSA keys from disk")
                # Warn if key files have overly permissive permissions
                self._check_key_permissions(private_key_path, public_key_path)
            else:
                # Generate new keys
                logger.warning("RSA keys not found, generating new keys")
                self._generate_rsa_keys(private_key_path, public_key_path)
        except Exception as e:
            logger.error(f"Failed to load RSA keys: {e}")
            # Fallback to HMAC — security downgrade
            if settings.environment == "production":
                logger.error(
                    "SECURITY DOWNGRADE: Falling back from RS256 to HS256 in production. "
                    "Fix RSA key configuration to restore asymmetric signing."
                )
            else:
                logger.warning("Falling back to HS256 with symmetric secret (non-production)")
            self.algorithm = "HS256"
            self.secret_key = settings.jwt_secret_key

    def _generate_rsa_keys(self, private_path: Path, public_path: Path):
        """Generate new RSA key pair"""
        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        # Generate public key
        public_key = private_key.public_key()

        # Save keys
        private_path.parent.mkdir(parents=True, exist_ok=True)

        passphrase = settings.jwt_private_key_passphrase
        enc_algo = (
            serialization.BestAvailableEncryption(passphrase.encode())
            if passphrase
            else serialization.NoEncryption()
        )
        with open(private_path, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=enc_algo,
            ))

        with open(public_path, "wb") as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))

        # Set restrictive permissions on generated key files
        os.chmod(private_path, 0o600)
        os.chmod(public_path, 0o644)

        self.private_key = private_key
        self.public_key = public_key
        logger.info("Generated new RSA keys")

    @staticmethod
    def _check_key_permissions(private_path: Path, public_path: Path):
        """Check RSA key file permissions and warn if too permissive"""
        priv_mode = os.stat(private_path).st_mode & 0o777
        if priv_mode & 0o077:
            logger.warning(
                "RSA private key %s has permissive mode %03o — should be 600",
                private_path, priv_mode,
            )
        pub_mode = os.stat(public_path).st_mode & 0o777
        if pub_mode & 0o002:
            logger.warning(
                "RSA public key %s is world-writable (mode %03o) — should be 644",
                public_path, pub_mode,
            )

    def get_signing_key(self):
        """Get key for signing JWTs"""
        if self.algorithm.startswith('RS'):
            return self.private_key
        return self.secret_key

    def get_verification_key(self):
        """Get key for verifying JWTs"""
        if self.algorithm.startswith('RS'):
            return self.public_key
        return self.secret_key


# Global security keys instance
_security_keys = SecurityKeys()


def get_redis_client() -> redis.Redis:
    """Get Redis client for token revocation"""
    return redis.Redis(
        host=settings.redis_host,
        port=settings.redis_port,
        db=settings.redis_db,
        password=settings.redis_password,
        decode_responses=True,
        socket_connect_timeout=2,
        socket_timeout=2
    )


# ===========================
# Password Security Functions
# ===========================

def hash_password(password: str) -> str:
    """
    Hash password using bcrypt with cost factor 12

    Args:
        password: Plain text password

    Returns:
        Hashed password (bcrypt hash)

    Security:
        - Bcrypt automatically generates and stores salt
        - Cost factor 12 = ~250ms hashing time (OWASP recommended)
        - Resistant to rainbow table attacks
    """
    if not password:
        raise ValueError("Password cannot be empty")

    if len(password) < 8:
        raise ValueError("Password must be at least 8 characters")

    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify password against bcrypt hash

    Args:
        plain_password: Plain text password to verify
        hashed_password: Bcrypt hash to compare against

    Returns:
        True if password matches, False otherwise

    Security:
        - Uses constant-time comparison to prevent timing attacks
        - Automatically handles salt extraction from hash
    """
    try:
        return pwd_context.verify(plain_password, hashed_password)
    except Exception as e:
        logger.warning(f"Password verification failed: {e}")
        return False


# ===========================
# API Key Functions
# ===========================

def generate_api_key(prefix: str = "easm") -> Tuple[str, str]:
    """
    Generate secure API key with prefix

    Args:
        prefix: Key prefix for identification (e.g., "easm", "test")

    Returns:
        Tuple of (api_key, api_key_hash)
        - api_key: The actual key to give to user (only shown once)
        - api_key_hash: Hash to store in database

    Format: {prefix}_{random_bytes}
    Example: easm_abc123def456...

    Security:
        - 256-bit random key (cryptographically secure)
        - Hash stored in DB (bcrypt), not plaintext
        - Prefix allows key rotation by version
    """
    # Generate 256-bit random key
    random_part = secrets.token_urlsafe(32)
    api_key = f"{prefix}_{random_part}"

    # Hash for storage (bcrypt)
    api_key_hash = hash_password(api_key)

    return api_key, api_key_hash


def verify_api_key(api_key: str, api_key_hash: str) -> bool:
    """
    Verify API key against stored hash

    Args:
        api_key: Plain API key from request
        api_key_hash: Bcrypt hash from database

    Returns:
        True if API key is valid

    Security:
        - Constant-time comparison (via bcrypt)
        - Prevents timing attacks
    """
    return verify_password(api_key, api_key_hash)


def generate_api_key_simple(length: int = 32) -> str:
    """
    Generate simple API key (legacy support)

    Args:
        length: Number of bytes for key

    Returns:
        URL-safe random string

    Note:
        Prefer generate_api_key() for new implementations.
        This is for backward compatibility.
    """
    return secrets.token_urlsafe(length)


# ===========================
# Cryptographic Utilities
# ===========================

def constant_time_compare(a: str, b: str) -> bool:
    """
    Constant-time string comparison

    Args:
        a: First string
        b: Second string

    Returns:
        True if strings are equal

    Security:
        - Prevents timing attacks
        - Use for comparing secrets, tokens, hashes
    """
    return hmac.compare_digest(a.encode(), b.encode())


def generate_random_token(nbytes: int = 32) -> str:
    """
    Generate cryptographically secure random token

    Args:
        nbytes: Number of random bytes

    Returns:
        URL-safe random string

    Use cases:
        - CSRF tokens
        - Password reset tokens
        - Email verification tokens
        - Session identifiers
    """
    return secrets.token_urlsafe(nbytes)


def hash_token(token: str) -> str:
    """
    Hash token for storage (SHA-256)

    Args:
        token: Token to hash

    Returns:
        Hex-encoded SHA-256 hash

    Use case:
        - Store hashed version of reset tokens in DB
        - Prevents token leakage if DB is compromised
    """
    return hashlib.sha256(token.encode()).hexdigest()


# ===========================
# Initialization
# ===========================

def initialize_security():
    """
    Initialize security subsystem

    - Loads/generates RSA keys
    - Validates configuration
    - Tests Redis connection
    """
    logger.info(f"Initializing security subsystem with algorithm: {_security_keys.algorithm}")

    # Test Redis connection
    try:
        redis_client = get_redis_client()
        redis_client.ping()
        redis_client.close()
        logger.info("Redis connection successful")
    except Exception as e:
        logger.error(f"Redis connection failed: {e}")
        logger.warning("Token revocation will not work without Redis")

    logger.info("Security subsystem initialized")


# Initialize on module load
initialize_security()
