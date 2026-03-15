"""
Core security and infrastructure modules

This package contains:
- security: RSA/HMAC key management, password hashing, API key management
- rate_limiter: Distributed rate limiting with Redis
- config: Enhanced configuration management
- audit: Security audit logging

JWT authentication is handled by app.security.jwt_auth (single canonical
implementation).  The re-exports below keep backward compatibility for
callers that imported from app.core.
"""

from app.core.security import (
    hash_password,
    verify_password,
    generate_api_key,
    verify_api_key,
)
from app.core.audit import log_audit_event, AuditEventType

__all__ = [
    "hash_password",
    "verify_password",
    "generate_api_key",
    "verify_api_key",
    "log_audit_event",
    "AuditEventType",
]
