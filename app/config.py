"""
Centralized configuration management using Pydantic Settings

All configuration values are loaded from environment variables with
sensible defaults for development. Production deployments MUST override
sensitive defaults.
"""

from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import model_validator
from typing import Optional
from pathlib import Path


class Settings(BaseSettings):
    """Application settings with environment variable support"""

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", case_sensitive=False, extra="ignore")

    # Application
    app_name: str = "EASM Platform"
    app_version: str = "1.0.0"
    debug: bool = False
    environment: str = "development"

    # API Server
    api_host: str = "0.0.0.0"
    api_port: int = 8000
    api_workers: int = 4
    api_reload: bool = False

    # Security (Sprint 2 - Critical Vulnerability Fix #3)
    # IMPORTANT: These values MUST be set via environment variables in production
    # Development fallback values provided for local testing only
    secret_key: str = "dev_secret_key_INSECURE_DO_NOT_USE_IN_PRODUCTION_" + "x" * 32
    api_key_header: str = "X-API-Key"
    cors_origins: list[str] = ["http://localhost:3000", "http://localhost:13000"]
    cors_allow_credentials: bool = True
    cors_allow_methods: list[str] = ["GET", "POST", "PUT", "DELETE", "PATCH"]
    cors_allow_headers: list[str] = ["Authorization", "Content-Type", "X-Request-ID", "Accept"]

    # JWT Authentication (Sprint 2 - Critical Vulnerability Fix #3, Sprint 3 - Enhanced RS256)
    # RS256 (asymmetric) recommended for production - more secure, allows public key distribution
    # HS256 (symmetric) fallback for development - simpler setup, requires shared secret
    jwt_secret_key: str = "dev_jwt_secret_INSECURE_DO_NOT_USE_IN_PRODUCTION_" + "x" * 32
    jwt_algorithm: str = "RS256"  # RS256 (asymmetric) for production, HS256 (symmetric) for dev
    jwt_private_key_path: Optional[str] = None  # Path to RS256 private key (PEM format)
    jwt_public_key_path: Optional[str] = None  # Path to RS256 public key (PEM format)
    jwt_access_token_expire_minutes: int = 30
    jwt_refresh_token_expire_days: int = 7

    # Database
    postgres_host: str = "localhost"
    postgres_port: int = 15432
    postgres_db: str = "easm"
    postgres_user: str = "easm"
    postgres_password: str = "easm_dev_password"
    postgres_pool_size: int = 20
    postgres_max_overflow: int = 40
    postgres_pool_pre_ping: bool = True
    postgres_pool_recycle: int = 3600

    @property
    def database_url(self) -> str:
        """Construct PostgreSQL connection URL"""
        return (
            f"postgresql://{self.postgres_user}:{self.postgres_password}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )

    @property
    def async_database_url(self) -> str:
        """Construct async PostgreSQL connection URL"""
        return (
            f"postgresql+asyncpg://{self.postgres_user}:{self.postgres_password}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )

    # Redis
    redis_host: str = "localhost"
    redis_port: int = 16379
    redis_db: int = 0
    redis_password: Optional[str] = "easm_redis_dev"

    @property
    def redis_url(self) -> str:
        """Construct Redis connection URL"""
        if self.redis_password:
            return f"redis://:{self.redis_password}@{self.redis_host}:{self.redis_port}/{self.redis_db}"
        return f"redis://{self.redis_host}:{self.redis_port}/{self.redis_db}"

    # Celery
    celery_broker_url: Optional[str] = None
    celery_result_backend: Optional[str] = None
    celery_task_always_eager: bool = False
    celery_worker_prefetch_multiplier: int = 4
    # Recycle the prefork worker after every single task so any residual
    # memory growth (chromium contexts, httpx SSL state, scan buffers, ...)
    # is reclaimed between scans instead of accumulating until the cgroup
    # OOM killer fires. Scan tasks are minutes-to-hours long, so the fork
    # respawn overhead (~1s) is negligible. See the 12 GB OOM loop we hit
    # during IFO tier-3 scans for the incident rationale.
    celery_worker_max_tasks_per_child: int = 1

    @property
    def celery_broker(self) -> str:
        """Get Celery broker URL"""
        return self.celery_broker_url or self.redis_url

    @property
    def celery_backend(self) -> str:
        """Get Celery result backend URL"""
        return self.celery_result_backend or self.redis_url

    # MinIO / S3
    minio_endpoint: str = "localhost:19000"
    minio_access_key: str = "minioadmin"
    minio_secret_key: str = "minioadmin"
    minio_secure: bool = False
    minio_bucket_prefix: str = "easm"

    # MaxMind GeoLite2 database paths
    # Download free databases from https://www.maxmind.com/en/geoip-databases
    geoip_city_db_path: Optional[str] = "/app/data/geoip/GeoLite2-City.mmdb"
    geoip_asn_db_path: Optional[str] = "/app/data/geoip/GeoLite2-ASN.mmdb"

    # Tool Execution Security
    tool_execution_timeout: int = 600
    tool_execution_max_output_size: int = 100 * 1024 * 1024  # 100MB
    tool_temp_dir: Optional[Path] = None
    tool_allowed_tools: set[str] = {
        "subfinder",
        "dnsx",
        "httpx",
        "naabu",
        "katana",
        "nuclei",
        "tlsx",
        "uncover",
        "notify",
        "amass",  # Sprint 1.7: OWASP Amass for enhanced subdomain enumeration
        "alterx",
        "puredns",
        "cdncheck",
        "cloudlist",
        "fingerprintx",
    }

    # Discovery Pipeline
    discovery_batch_size: int = 100
    discovery_subfinder_timeout: int = 300
    discovery_amass_timeout: int = 600
    discovery_amass_enabled: bool = True
    discovery_dnsx_timeout: int = 300
    discovery_httpx_timeout: int = 600
    discovery_naabu_timeout: int = 600
    discovery_nuclei_timeout: int = 1800

    # New tool timeouts
    alterx_timeout: int = 300  # 5 min
    puredns_timeout: int = 1800  # 30 min (174k+ candidates at 200/s)
    cdncheck_timeout: int = 120  # 2 min
    cloudlist_timeout: int = 300  # 5 min
    fingerprintx_timeout: int = 300  # 5 min
    interactsh_enabled: bool = True  # OOB callback detection for T3 scans
    interactsh_server: str = "oast.pro"  # Public interactsh server
    puredns_resolvers_path: str = "/app/data/resolvers.txt"
    puredns_wordlist_path: str = "/app/data/dns-wordlist.txt"

    # Enrichment Pipeline (Sprint 2)
    enrichment_enabled: bool = True
    enrichment_auto_trigger: bool = True  # Automatically trigger enrichment after discovery
    enrichment_batch_size: int = 100  # Max assets to enrich per run

    # HTTPx - Web Technology Fingerprinting
    httpx_timeout: int = 600  # 10 minutes (300s was too short for 500+ hosts)
    httpx_rate_limit: int = 150  # Requests per second
    httpx_response_size_limit: int = 1048576  # 1MB max response size

    # Naabu - Port Scanning
    naabu_timeout: int = 600  # 10 minutes
    naabu_rate_limit: int = 1000  # Packets per second
    naabu_default_ports: str = "top-1000"  # top-100, top-1000, or "1-65535"
    naabu_blocked_ports: list[int] = [22, 445, 3389, 3306, 5432]  # SSH, SMB, RDP, MySQL, PostgreSQL

    # TLSx - TLS/SSL Certificate Analysis
    tlsx_timeout: int = 300  # 5 minutes
    tlsx_expiry_warning_days: int = 30  # Alert if cert expires within N days

    # Katana - Web Crawling
    katana_timeout: int = 300  # 5 minutes
    katana_max_depth: int = 2  # Maximum crawl depth
    katana_max_pages: int = 500  # Maximum pages per domain
    katana_respect_robots: bool = True  # Respect robots.txt

    # Rate Limiting
    rate_limit_enabled: bool = True
    rate_limit_requests_per_minute: int = 60
    rate_limit_requests_per_hour: int = 1000

    # Data Retention
    data_retention_days: int = 90  # Delete scan_runs/phase_results older than N days

    # Logging
    log_level: str = "INFO"
    log_format: str = "json"  # json or text
    log_file: Optional[Path] = None
    log_rotation_size: str = "100MB"
    log_retention_days: int = 30

    # Monitoring
    sentry_dsn: Optional[str] = None
    sentry_environment: Optional[str] = None
    sentry_traces_sample_rate: float = 0.1

    # Visual Recon (Phase 7 - headless browser screenshots)
    visual_recon_enabled: bool = True
    visual_recon_max_screenshots: int = 200  # Max screenshots per pipeline run
    visual_recon_batch_size: int = 10  # Concurrent browser pages
    visual_recon_timeout_ms: int = 30000  # Navigation timeout per page in ms
    visual_recon_viewport_width: int = 1920
    visual_recon_viewport_height: int = 1080
    visual_recon_thumb_width: int = 320
    visual_recon_thumb_height: int = 240

    # Alerting & Notifications
    alert_cooldown_minutes: int = 60
    alert_max_per_run: int = 50
    slack_webhook_url: Optional[str] = None
    smtp_host: Optional[str] = None
    smtp_port: int = 587
    smtp_from: Optional[str] = None
    smtp_user: Optional[str] = None
    smtp_password: Optional[str] = None
    webhook_url: Optional[str] = None
    webhook_secret: Optional[str] = None

    # MFA Secret Encryption
    # MUST be a valid Fernet key in production (32 url-safe base64-encoded bytes)
    # Generate with: python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
    mfa_encryption_key: Optional[str] = None  # None = plaintext (dev only)
    jwt_private_key_passphrase: Optional[str] = None  # None = no passphrase (dev only)

    # SAML SSO
    saml_enabled: bool = False
    saml_idp_entity_id: Optional[str] = None
    saml_idp_sso_url: Optional[str] = None
    saml_idp_slo_url: Optional[str] = None
    saml_idp_x509_cert: Optional[str] = None
    saml_sp_entity_id: str = "easm-platform"
    saml_sp_acs_url: Optional[str] = None  # e.g. https://easm.example.com/api/v1/auth/saml/acs
    saml_default_tenant_id: int = 1
    saml_default_role: str = "member"
    saml_auto_provision: bool = True  # auto-create users on first SAML login
    saml_frontend_url: str = "http://localhost:13000"  # frontend URL for post-login redirect

    # Metrics
    metrics_token: Optional[str] = None

    # Feature Flags
    feature_uncover_enabled: bool = True
    feature_nuclei_enabled: bool = True
    feature_visual_recon_enabled: bool = True
    feature_notifications_enabled: bool = False

    @model_validator(mode="after")
    def validate_production_secrets(self):
        """
        ENHANCED Sprint 2 Security: Validate production secrets

        Ensures all sensitive configuration values are properly set in production
        with strong, randomly-generated values.

        Raises:
            ValueError: If production environment has weak/default secrets
        """
        if self.environment == "production":
            errors = []

            # Sprint 2 Enhancement: Comprehensive weak secret detection
            weak_patterns = [
                "CHANGE_THIS",
                "changeme",
                "INSECURE",
                "DO_NOT_USE",
                "dev_",
                "test_",
                "default",
                "password",
                "secret",
                "123456",
                "admin",
                "root",
                "qwerty",
            ]

            # Check SECRET_KEY
            if any(pattern in self.secret_key for pattern in weak_patterns) or len(self.secret_key) < 64:
                errors.append(
                    "SECRET_KEY must be set with a cryptographically strong random value (min 64 chars) in production. "
                    'Generate with: python -c "import secrets; print(secrets.token_urlsafe(64))"'
                )

            # Check JWT_SECRET_KEY
            if any(pattern in self.jwt_secret_key for pattern in weak_patterns) or len(self.jwt_secret_key) < 64:
                errors.append(
                    "JWT_SECRET_KEY must be set with a cryptographically strong random value (min 64 chars) in production. "
                    'Generate with: python -c "import secrets; print(secrets.token_urlsafe(64))"'
                )

            # Check database password
            if (
                any(pattern in self.postgres_password.lower() for pattern in weak_patterns)
                or len(self.postgres_password) < 16
            ):
                errors.append(
                    "POSTGRES_PASSWORD must be set with a strong password (min 16 chars) in production. "
                    'Generate with: python -c "import secrets; print(secrets.token_urlsafe(32))"'
                )

            # Check MinIO credentials
            if any(pattern in self.minio_access_key.lower() for pattern in weak_patterns):
                errors.append("MINIO_ACCESS_KEY must be changed from defaults in production")

            if (
                any(pattern in self.minio_secret_key.lower() for pattern in weak_patterns)
                or len(self.minio_secret_key) < 32
            ):
                errors.append(
                    "MINIO_SECRET_KEY must be set with a strong random value (min 32 chars) in production. "
                    'Generate with: python -c "import secrets; print(secrets.token_urlsafe(32))"'
                )

            # Check CORS configuration
            if "*" in self.cors_origins:
                errors.append(
                    "CORS_ORIGINS must not include wildcard ('*') in production. Specify exact allowed origins."
                )

            # Check that Redis password is set in production
            if not self.redis_password:
                errors.append("REDIS_PASSWORD must be set in production to secure Redis access")

            if errors:
                error_msg = "\n\n" + "=" * 80 + "\n"
                error_msg += "PRODUCTION CONFIGURATION ERRORS DETECTED\n"
                error_msg += "=" * 80 + "\n\n"
                error_msg += "The following configuration issues MUST be fixed before deploying to production:\n\n"
                for i, error in enumerate(errors, 1):
                    error_msg += f"{i}. {error}\n\n"
                error_msg += "=" * 80 + "\n"
                error_msg += "Set ENVIRONMENT=development to bypass these checks for local development.\n"
                error_msg += "=" * 80 + "\n"
                raise ValueError(error_msg)

        return self


# Global settings instance
settings = Settings()


def get_settings() -> Settings:
    """
    Get settings instance for dependency injection

    Returns:
        Settings instance
    """
    return settings
