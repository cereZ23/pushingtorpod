"""
Sprint 0-2 Security Integration Tests

Validates the security hardening introduced across sprints 0, 2, and 3:

  1. Rate limiting on the login endpoint (Sprint 0)
  2. Sortable column whitelist on the assets endpoint (Sprint 2)
  3. ILIKE escape for user-supplied search input (Sprint 2)
  4. Health endpoint hardened -- no infrastructure details leaked (Sprint 2)
  5. /api/v1/stats requires authentication (Sprint 2)
  6. SSO-only users cannot authenticate via password (Sprint 3)
  7. SAML endpoints return 404 when SAML is disabled (Sprint 3)

Tests connect to the PostgreSQL instance from docker-compose for full
schema compatibility (JSONB, enums, etc.) and use transaction rollback
for per-test isolation.
"""

from __future__ import annotations

import logging
import os
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Generator
from unittest.mock import patch

import jwt as pyjwt
import pytest
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from dotenv import load_dotenv
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

# Load .env so DB credentials are available
_env_path = Path(__file__).parent.parent / ".env"
if _env_path.exists():
    load_dotenv(dotenv_path=_env_path)

# ---------------------------------------------------------------------------
# Model imports -- ensures all tables are registered on Base.metadata
# ---------------------------------------------------------------------------
import app.models  # noqa: F401 -- triggers __init__ side-effects
from app.models.database import Base, Asset, AssetType, Tenant
from app.models.auth import User, TenantMembership

# Dependencies and utilities under test
from app.api.dependencies import escape_like, get_db

logger = logging.getLogger(__name__)


# ===========================================================================
# Deterministic RSA key pair used for JWT signing in tests.
# Generated once at module level to keep test startup fast.
# ===========================================================================
_TEST_PRIVATE_KEY = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend(),
)
_TEST_PUBLIC_KEY = _TEST_PRIVATE_KEY.public_key()


def _make_access_token(
    user_id: int,
    tenant_id: int,
    roles: list[str] | None = None,
    expires_minutes: int = 30,
) -> str:
    """Create a signed RS256 access token for test use."""
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user_id),
        "tenant_id": tenant_id,
        "roles": roles or ["member"],
        "exp": now + timedelta(minutes=expires_minutes),
        "iat": now,
        "type": "access",
        "jti": f"test-jti-{user_id}-{time.monotonic_ns()}",
    }
    return pyjwt.encode(payload, _TEST_PRIVATE_KEY, algorithm="RS256")


# ===========================================================================
# Fixtures
# ===========================================================================


@pytest.fixture(scope="module")
def _pg_engine():
    """Module-scoped PostgreSQL engine from docker-compose.

    Inside Docker the service name is ``postgres:5432``.
    On the host machine the forwarded port is ``127.0.0.1:15432``.
    We honour ``POSTGRES_HOST`` / ``POSTGRES_PORT`` env vars set by the
    docker-compose ``api`` service, then fall back to the host mapping.
    """
    pg_host = os.environ.get("POSTGRES_HOST", "127.0.0.1")
    pg_port = os.environ.get("POSTGRES_PORT", "15432")
    pg_user = os.environ.get("POSTGRES_USER", "easm")
    pg_pass = os.environ.get("POSTGRES_PASSWORD",
                             os.environ.get("DB_PASSWORD", "easm_password"))
    pg_db = os.environ.get("POSTGRES_DB", "easm")

    database_url = os.environ.get(
        "TEST_DATABASE_URL",
        f"postgresql://{pg_user}:{pg_pass}@{pg_host}:{pg_port}/{pg_db}",
    )
    engine = create_engine(database_url, echo=False)
    Base.metadata.create_all(engine)

    # Ensure SSO columns exist on the users table (model may be ahead of
    # applied Alembic migrations) and that hashed_password is nullable for
    # SSO-only users.
    from sqlalchemy import text, inspect as sa_inspect
    with engine.connect() as conn:
        inspector = sa_inspect(engine)
        existing_cols = {c["name"] for c in inspector.get_columns("users")}
        if "sso_provider" not in existing_cols:
            conn.execute(text(
                "ALTER TABLE users ADD COLUMN sso_provider VARCHAR(50)"
            ))
        if "sso_subject_id" not in existing_cols:
            conn.execute(text(
                "ALTER TABLE users ADD COLUMN sso_subject_id VARCHAR(255)"
            ))
        # Make hashed_password nullable (required for SSO-only user tests).
        # This is idempotent -- running it on an already-nullable column is a no-op.
        conn.execute(text(
            "ALTER TABLE users ALTER COLUMN hashed_password DROP NOT NULL"
        ))
        conn.commit()

    yield engine
    engine.dispose()


@pytest.fixture()
def db_session(_pg_engine) -> Generator[Session, None, None]:
    """Per-test database session wrapped in a transaction for rollback."""
    connection = _pg_engine.connect()
    transaction = connection.begin()
    session = sessionmaker(bind=connection)()

    yield session

    session.close()
    transaction.rollback()
    connection.close()


@pytest.fixture()
def test_tenant(db_session: Session) -> Tenant:
    """A Tenant row for test isolation."""
    tenant = Tenant(
        name="Sprint02 Security Test Tenant",
        slug=f"sprint02-sec-{time.monotonic_ns()}",
        contact_policy="security@test.example",
    )
    db_session.add(tenant)
    db_session.flush()
    db_session.refresh(tenant)
    return tenant


@pytest.fixture()
def test_user(db_session: Session, test_tenant: Tenant) -> User:
    """A regular user with a hashed password and membership."""
    user = User(
        email=f"regular-{time.monotonic_ns()}@test.example",
        username=f"regular_user_{time.monotonic_ns()}",
        hashed_password=User.hash_password("Passw0rd!23"),
        full_name="Regular Test User",
        is_active=True,
        is_superuser=False,
    )
    db_session.add(user)
    db_session.flush()

    membership = TenantMembership(
        user_id=user.id,
        tenant_id=test_tenant.id,
        role="admin",
        is_active=True,
    )
    db_session.add(membership)
    db_session.flush()
    db_session.refresh(user)
    return user


@pytest.fixture()
def sso_only_user(db_session: Session, test_tenant: Tenant) -> User:
    """A user provisioned via SAML with no local password."""
    user = User(
        email=f"sso-user-{time.monotonic_ns()}@corp.example",
        username=f"sso_user_{time.monotonic_ns()}",
        hashed_password=None,
        full_name="SSO Only User",
        is_active=True,
        is_superuser=False,
        sso_provider="saml",
        sso_subject_id="_saml_nameid_abc123",
    )
    db_session.add(user)
    db_session.flush()

    membership = TenantMembership(
        user_id=user.id,
        tenant_id=test_tenant.id,
        role="member",
        is_active=True,
    )
    db_session.add(membership)
    db_session.flush()
    db_session.refresh(user)
    return user


@pytest.fixture()
def sample_assets(db_session: Session, test_tenant: Tenant) -> list[Asset]:
    """Three assets with varying risk scores for sort testing."""
    assets = [
        Asset(
            tenant_id=test_tenant.id,
            identifier="alpha.example.com",
            type=AssetType.SUBDOMAIN,
            risk_score=30.0,
            is_active=True,
        ),
        Asset(
            tenant_id=test_tenant.id,
            identifier="beta.example.com",
            type=AssetType.SUBDOMAIN,
            risk_score=80.0,
            is_active=True,
        ),
        Asset(
            tenant_id=test_tenant.id,
            identifier="gamma.example.com",
            type=AssetType.SUBDOMAIN,
            risk_score=10.0,
            is_active=True,
        ),
    ]
    db_session.add_all(assets)
    db_session.flush()
    for a in assets:
        db_session.refresh(a)
    return assets


@pytest.fixture()
def client(db_session: Session) -> Generator[TestClient, None, None]:
    """FastAPI TestClient backed by the test PostgreSQL session.

    Patches:
    - ``get_db`` (from app.api.dependencies) yields the test session.
    - ``JWTManager.verify_token`` bypasses Redis revocation checks and uses
      the deterministic RSA public key.
    """
    import app.main as main_module
    from app.main import app

    # ---- Override get_db ----
    def _override_get_db() -> Generator[Session, None, None]:
        yield db_session

    app.dependency_overrides[get_db] = _override_get_db

    # ---- Patch JWT verification to use test RSA keys, skip Redis ----
    _original_verify = None
    try:
        from app.security.jwt_auth import jwt_manager

        def _mock_verify_token(credentials):
            token = credentials.credentials
            try:
                payload = pyjwt.decode(
                    token,
                    _TEST_PUBLIC_KEY,
                    algorithms=["RS256"],
                )
            except Exception as exc:
                # Catch broadly: PyJWTError, DecodeError, UnicodeDecodeError,
                # InvalidSignatureError, etc.
                from fastapi import HTTPException, status
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail=f"Token validation failed: {exc}",
                )
            return payload

        _original_verify = jwt_manager.verify_token
        jwt_manager.verify_token = _mock_verify_token
    except Exception:
        pass

    # ---- Patch jwt_manager token creation to use test keys ----
    _original_create_access = None
    _original_create_refresh = None
    try:
        from app.security.jwt_auth import jwt_manager as jm

        _original_create_access = jm.create_access_token
        _original_create_refresh = jm.create_refresh_token

        def _test_create_access(subject, tenant_id, roles=None,
                                expires_delta=None, additional_claims=None):
            if expires_delta is None:
                expires_delta = timedelta(minutes=30)
            now = datetime.now(timezone.utc)
            payload = {
                "sub": subject,
                "tenant_id": tenant_id,
                "roles": roles or ["user"],
                "exp": now + expires_delta,
                "iat": now,
                "type": "access",
                "jti": f"test-access-{time.monotonic_ns()}",
            }
            if additional_claims:
                payload.update(additional_claims)
            return pyjwt.encode(payload, _TEST_PRIVATE_KEY, algorithm="RS256")

        def _test_create_refresh(subject, tenant_id, expires_delta=None):
            if expires_delta is None:
                expires_delta = timedelta(days=7)
            now = datetime.now(timezone.utc)
            payload = {
                "sub": subject,
                "tenant_id": tenant_id,
                "exp": now + expires_delta,
                "iat": now,
                "type": "refresh",
                "jti": f"test-refresh-{time.monotonic_ns()}",
            }
            return pyjwt.encode(payload, _TEST_PRIVATE_KEY, algorithm="RS256")

        jm.create_access_token = _test_create_access
        jm.create_refresh_token = _test_create_refresh
    except Exception:
        pass

    test_client = TestClient(app, raise_server_exceptions=False)
    yield test_client

    # ---- Teardown ----
    app.dependency_overrides.clear()
    if _original_verify is not None:
        from app.security.jwt_auth import jwt_manager as jm2
        jm2.verify_token = _original_verify
    if _original_create_access is not None:
        from app.security.jwt_auth import jwt_manager as jm3
        jm3.create_access_token = _original_create_access
        jm3.create_refresh_token = _original_create_refresh


@pytest.fixture()
def auth_headers(test_user: User, test_tenant: Tenant) -> dict[str, str]:
    """Authorization header with a valid RS256 JWT for ``test_user``."""
    token = _make_access_token(
        user_id=test_user.id,
        tenant_id=test_tenant.id,
        roles=["admin"],
    )
    return {"Authorization": f"Bearer {token}"}


# ===========================================================================
# 1. Rate limiting on login (Sprint 0)
# ===========================================================================


class TestLoginRateLimit:
    """Verify that POST /api/v1/auth/login is rate-limited."""

    def test_login_endpoint_exists_and_accepts_valid_credentials(
        self,
        client: TestClient,
        test_user: User,
    ):
        """The login endpoint should exist and return 200 for correct
        credentials."""
        response = client.post(
            "/api/v1/auth/login",
            json={
                "email": test_user.email,
                "password": "Passw0rd!23",
            },
        )
        assert response.status_code == 200, response.text
        data = response.json()
        assert "access_token" in data
        assert "refresh_token" in data
        assert data["token_type"] == "bearer"

    def test_login_returns_401_for_invalid_credentials(
        self,
        client: TestClient,
    ):
        """Invalid email/password should yield 401, not 500."""
        response = client.post(
            "/api/v1/auth/login",
            json={
                "email": "nobody@void.example",
                "password": "doesnotmatter",
            },
        )
        assert response.status_code == 401

    def test_login_rate_limit_decorator_is_applied(self):
        """Verify the login route has a slowapi rate limit decorator
        configured to 5/minute by inspecting the source code."""
        import inspect
        from app.api.routers import auth as auth_module

        source = inspect.getsource(auth_module)
        # The decorator should appear as @limiter.limit("5/minute") or similar
        assert "limiter.limit" in source, (
            "auth router must use @limiter.limit on login endpoint"
        )
        assert "5/minute" in source, (
            "Login rate limit should be set to 5/minute"
        )


# ===========================================================================
# 2. Sortable column whitelist (Sprint 2)
# ===========================================================================


class TestAssetSortWhitelist:
    """Verify that the assets list endpoint validates sort_by against an
    allowlist and falls back gracefully for unknown columns."""

    def test_sort_by_identifier_returns_200(
        self,
        client: TestClient,
        auth_headers: dict,
        test_tenant: Tenant,
        sample_assets: list[Asset],
    ):
        """Sorting by 'identifier' (an allowed column) should succeed."""
        url = f"/api/v1/tenants/{test_tenant.id}/assets?sort_by=identifier&sort_order=asc"
        response = client.get(url, headers=auth_headers)
        assert response.status_code == 200, response.text
        body = response.json()
        items = body["data"]
        identifiers = [i["identifier"] for i in items]
        assert identifiers == sorted(identifiers), (
            "Assets should be sorted alphabetically by identifier"
        )

    def test_sort_by_risk_score_returns_200(
        self,
        client: TestClient,
        auth_headers: dict,
        test_tenant: Tenant,
        sample_assets: list[Asset],
    ):
        """Sorting by 'risk_score' (allowed) should succeed."""
        url = f"/api/v1/tenants/{test_tenant.id}/assets?sort_by=risk_score&sort_order=desc"
        response = client.get(url, headers=auth_headers)
        assert response.status_code == 200, response.text
        body = response.json()
        items = body["data"]
        scores = [i["risk_score"] for i in items]
        assert scores == sorted(scores, reverse=True), (
            "Assets should be sorted descending by risk_score"
        )

    def test_sort_by_invalid_column_falls_back_to_default(
        self,
        client: TestClient,
        auth_headers: dict,
        test_tenant: Tenant,
        sample_assets: list[Asset],
    ):
        """An invalid sort column (e.g. 'hacked') should NOT crash.
        The endpoint must fall back to the default sort column."""
        url = f"/api/v1/tenants/{test_tenant.id}/assets?sort_by=hacked"
        response = client.get(url, headers=auth_headers)
        # Must not crash (no 500, no 422)
        assert response.status_code == 200, (
            f"Invalid sort_by should fall back, got {response.status_code}: {response.text}"
        )

    def test_sort_by_sql_injection_attempt_is_safe(
        self,
        client: TestClient,
        auth_headers: dict,
        test_tenant: Tenant,
        sample_assets: list[Asset],
    ):
        """Passing a SQL fragment as sort_by must not cause server errors."""
        url = (
            f"/api/v1/tenants/{test_tenant.id}/assets"
            "?sort_by=identifier;DROP+TABLE+assets--"
        )
        response = client.get(url, headers=auth_headers)
        assert response.status_code == 200, (
            "SQL injection in sort_by should be safely ignored"
        )

    def test_allowed_sort_columns_whitelist_exists(self):
        """The router source must declare ALLOWED_SORT_COLUMNS."""
        import inspect
        from app.api.routers import assets as assets_module

        source = inspect.getsource(assets_module)
        assert "ALLOWED_SORT_COLUMNS" in source, (
            "assets router must define an ALLOWED_SORT_COLUMNS whitelist"
        )


# ===========================================================================
# 3. ILIKE escape (Sprint 2)
# ===========================================================================


class TestILikeEscape:
    """Verify the escape_like utility and its integration in search."""

    def test_escape_like_percent(self):
        """The % wildcard must be escaped so it matches literally."""
        assert escape_like("100%") == "100\\%"

    def test_escape_like_underscore(self):
        """The _ single-char wildcard must be escaped."""
        assert escape_like("test_user") == "test\\_user"

    def test_escape_like_backslash(self):
        """Existing backslashes must be doubled."""
        assert escape_like("path\\to\\file") == "path\\\\to\\\\file"

    def test_escape_like_combined(self):
        """Multiple special characters in one string are all escaped."""
        result = escape_like("%_\\mix")
        assert result == "\\%\\_\\\\mix"

    def test_escape_like_plain_text_unchanged(self):
        """Normal strings pass through untouched."""
        assert escape_like("hello") == "hello"

    def test_search_with_percent_does_not_match_everything(
        self,
        client: TestClient,
        auth_headers: dict,
        test_tenant: Tenant,
        sample_assets: list[Asset],
    ):
        """Searching for literal '%' must NOT return all assets (the way
        an un-escaped ILIKE '%' pattern would)."""
        url = f"/api/v1/tenants/{test_tenant.id}/assets?search=%25"
        response = client.get(url, headers=auth_headers)
        assert response.status_code == 200
        body = response.json()
        # None of the sample identifiers contain a literal '%'
        assert body["meta"]["total"] == 0, (
            "Search for literal '%' should match zero assets because "
            "the wildcard is escaped"
        )

    def test_search_with_underscore_does_not_match_single_char(
        self,
        client: TestClient,
        auth_headers: dict,
        test_tenant: Tenant,
        sample_assets: list[Asset],
    ):
        """Searching for literal '_' must NOT match single-character
        positions (SQL ILIKE semantics)."""
        url = f"/api/v1/tenants/{test_tenant.id}/assets?search=_"
        response = client.get(url, headers=auth_headers)
        assert response.status_code == 200
        body = response.json()
        # None of the sample identifiers contain a literal '_'
        assert body["meta"]["total"] == 0, (
            "Underscore wildcard should be escaped and match nothing"
        )


# ===========================================================================
# 4. Health endpoint hardened (Sprint 2)
# ===========================================================================


class TestHealthEndpointHardened:
    """Verify GET /health does not leak infrastructure details."""

    def test_health_returns_expected_shape(self, client: TestClient):
        """Response must have 'status' and 'services' keys only."""
        response = client.get("/health")
        # May return 200 (healthy) or 503 (unhealthy) depending on service
        # availability. Both are acceptable in a test environment.
        assert response.status_code in (200, 503)
        data = response.json()
        # If 503, the response is wrapped in the HTTPException handler
        if response.status_code == 503:
            detail = data.get("detail", data)
            if isinstance(detail, dict):
                assert detail.get("status") in ("unhealthy", "error")
            return

        assert "status" in data
        assert "services" in data
        assert data["status"] in ("healthy", "unhealthy")

    def test_health_service_values_are_ok_or_error(self, client: TestClient):
        """Each service status must be either 'ok' or 'error', with no
        stack traces or connection strings."""
        response = client.get("/health")
        if response.status_code == 503:
            # Unhealthy path -- the detail is minimal
            return

        data = response.json()
        services = data.get("services", {})
        for svc_name, svc_status in services.items():
            assert svc_status in ("ok", "error"), (
                f"Service '{svc_name}' has unexpected status: {svc_status!r}. "
                "Only 'ok' or 'error' are allowed."
            )

    def test_health_does_not_leak_connection_strings(
        self,
        client: TestClient,
    ):
        """The response body must not contain database URLs, passwords,
        or exception messages."""
        response = client.get("/health")
        body = response.text.lower()
        leak_indicators = [
            "password",
            "traceback",
            "postgresql://",
            "redis://",
            "connection refused",
            "operationalerror",
            "errno",
        ]
        for indicator in leak_indicators:
            assert indicator not in body, (
                f"Health endpoint leaks infrastructure detail: found '{indicator}'"
            )


# ===========================================================================
# 5. Stats endpoint requires authentication (Sprint 2)
# ===========================================================================


class TestStatsRequiresAuth:
    """Verify GET /api/v1/stats is not accessible without a valid token."""

    def test_stats_without_token_returns_401_or_403(
        self,
        client: TestClient,
    ):
        """An unauthenticated request to /stats must be rejected."""
        response = client.get("/api/v1/stats")
        assert response.status_code in (401, 403), (
            f"Expected 401/403 for unauthenticated /stats, got {response.status_code}"
        )

    def test_stats_with_invalid_token_returns_401(
        self,
        client: TestClient,
    ):
        """A request with a wrongly-signed Bearer token must be rejected."""
        # Create a structurally valid JWT signed with a *different* RSA key
        # so PyJWT raises InvalidSignatureError rather than a raw decode crash.
        wrong_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend(),
        )
        bad_token = pyjwt.encode(
            {"sub": "999", "type": "access", "exp": 9999999999},
            wrong_key,
            algorithm="RS256",
        )
        headers = {"Authorization": f"Bearer {bad_token}"}
        response = client.get("/api/v1/stats", headers=headers)
        assert response.status_code in (401, 403), (
            f"Expected 401/403 for wrongly-signed token, got {response.status_code}"
        )

    def test_stats_with_valid_token_returns_200(
        self,
        client: TestClient,
        auth_headers: dict,
        test_user: User,
    ):
        """An authenticated request to /stats should succeed."""
        response = client.get("/api/v1/stats", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert "version" in data


# ===========================================================================
# 6. SSO-only user cannot password login (Sprint 3)
# ===========================================================================


class TestSsoOnlyUserRejected:
    """Verify that users with sso_provider set and no password are
    blocked from the password-based login flow."""

    def test_sso_user_password_login_returns_401(
        self,
        client: TestClient,
        sso_only_user: User,
    ):
        """SSO-only user must be rejected with a clear message."""
        response = client.post(
            "/api/v1/auth/login",
            json={
                "email": sso_only_user.email,
                "password": "AnythingHere1",
            },
        )
        assert response.status_code == 401
        detail = response.json().get("detail", "")
        assert "sso" in detail.lower() or "identity provider" in detail.lower(), (
            f"Expected SSO-related rejection message, got: {detail!r}"
        )

    def test_sso_user_error_does_not_reveal_password_absence(
        self,
        client: TestClient,
        sso_only_user: User,
    ):
        """The error message must NOT say 'password is null' or expose
        internal implementation details."""
        response = client.post(
            "/api/v1/auth/login",
            json={
                "email": sso_only_user.email,
                "password": "AnythingHere1",
            },
        )
        detail = response.json().get("detail", "")
        forbidden_phrases = ["null", "none", "hashed_password", "column"]
        for phrase in forbidden_phrases:
            assert phrase not in detail.lower(), (
                f"Error message leaks internal detail: found '{phrase}' in: {detail!r}"
            )

    def test_regular_user_can_still_login(
        self,
        client: TestClient,
        test_user: User,
    ):
        """Ensure the SSO guard does not break normal password login."""
        response = client.post(
            "/api/v1/auth/login",
            json={
                "email": test_user.email,
                "password": "Passw0rd!23",
            },
        )
        assert response.status_code == 200


# ===========================================================================
# 7. SAML endpoints disabled when not configured (Sprint 3)
# ===========================================================================


class TestSamlDisabled:
    """Verify SAML SSO routes return 404 when saml_enabled=False."""

    def test_saml_login_returns_404_when_disabled(
        self,
        client: TestClient,
    ):
        """GET /api/v1/auth/saml/login must 404 when SAML is off."""
        with patch("app.api.routers.saml.settings") as mock_settings:
            mock_settings.saml_enabled = False
            response = client.get("/api/v1/auth/saml/login")

        # The endpoint calls _require_saml_enabled() which checks settings
        assert response.status_code == 404, (
            f"Expected 404 for SAML login when disabled, got {response.status_code}"
        )

    def test_saml_metadata_returns_404_when_disabled(
        self,
        client: TestClient,
    ):
        """GET /api/v1/auth/saml/metadata must 404 when SAML is off."""
        with patch("app.api.routers.saml.settings") as mock_settings:
            mock_settings.saml_enabled = False
            response = client.get("/api/v1/auth/saml/metadata")

        assert response.status_code == 404

    def test_saml_disabled_does_not_expose_idp_config(
        self,
        client: TestClient,
    ):
        """The 404 response must not include IdP URLs or entity IDs."""
        with patch("app.api.routers.saml.settings") as mock_settings:
            mock_settings.saml_enabled = False
            response = client.get("/api/v1/auth/saml/login")

        body = response.text.lower()
        leak_indicators = ["entity_id", "sso_url", "x509"]
        for indicator in leak_indicators:
            assert indicator not in body, (
                f"SAML 404 response leaks config detail: found '{indicator}'"
            )
