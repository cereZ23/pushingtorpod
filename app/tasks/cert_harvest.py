"""
Certificate harvesting task using Python ssl + cryptography.

Extracts TLS certificates from hosts with has_tls=true in services,
without requiring external tools like tlsx.
"""

import ssl
import socket
import logging
from datetime import datetime, timezone
from typing import Optional

from cryptography import x509
from cryptography.x509.oid import NameOID

from app.celery_app import celery
from app.models.database import Asset, AssetType
from app.models.enrichment import Certificate
from app.utils.logger import TenantLoggerAdapter

logger = logging.getLogger(__name__)


def fetch_certificate(host: str, port: int = 443, timeout: float = 10.0) -> Optional[dict]:
    """
    Fetch and parse TLS certificate from host:port.

    Returns certificate dict or None on failure.
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # Accept self-signed too

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert_bin = ssock.getpeercert(binary_form=True)
                tls_version = ssock.version()
                cipher = ssock.cipher()

                if not cert_bin:
                    return None

                return _parse_cert(cert_bin, tls_version, cipher, host, port)
    except (socket.timeout, socket.gaierror, ConnectionRefusedError,
            ConnectionResetError, OSError, ssl.SSLError) as e:
        logger.debug(f"Cannot fetch cert from {host}:{port}: {e}")
        return None


def _parse_cert(
    cert_der: bytes,
    tls_version: Optional[str],
    cipher: Optional[tuple],
    host: str,
    port: int,
) -> Optional[dict]:
    """Parse DER-encoded certificate using cryptography library."""
    try:
        cert = x509.load_der_x509_certificate(cert_der)
    except Exception:
        return None

    # Subject CN
    cn_attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    subject_cn = cn_attrs[0].value if cn_attrs else ""

    # Issuer
    issuer_org = cert.issuer.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
    issuer_cn = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
    issuer_parts = []
    if issuer_org:
        issuer_parts.append(issuer_org[0].value)
    if issuer_cn:
        issuer_parts.append(issuer_cn[0].value)
    issuer = " / ".join(issuer_parts) if issuer_parts else ""

    # Serial
    serial_number = format(cert.serial_number, "X")

    # Dates (compatible with older cryptography versions)
    not_before = getattr(cert, "not_valid_before_utc", None) or cert.not_valid_before
    not_after = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after

    # Make naive for DB storage
    if not_before and not_before.tzinfo is not None:
        not_before = not_before.replace(tzinfo=None)
    if not_after and not_after.tzinfo is not None:
        not_after = not_after.replace(tzinfo=None)

    # Expiry
    now = datetime.now(timezone.utc)
    is_expired = False
    days_until_expiry = None
    if not_after:
        delta = not_after - now
        days_until_expiry = delta.days
        is_expired = days_until_expiry < 0

    # SANs
    san_domains = []
    try:
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        san_domains = san_ext.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        pass

    # Self-signed heuristic
    is_self_signed = cert.subject == cert.issuer

    # Wildcard
    is_wildcard = subject_cn.startswith("*.") or any(s.startswith("*.") for s in san_domains)

    # Signature algorithm
    sig_algorithm = cert.signature_algorithm_oid._name
    has_weak_signature = any(w in sig_algorithm.lower() for w in ["md5", "sha1"]) if sig_algorithm else False

    # Key info
    pub_key = cert.public_key()
    pub_key_bits = getattr(pub_key, "key_size", None)
    pub_key_algorithm = type(pub_key).__name__.replace("_", "").replace("PublicKey", "")

    return {
        "host": host,
        "port": str(port),
        "serial_number": serial_number,
        "subject_cn": subject_cn,
        "issuer": issuer,
        "not_before": not_before,
        "not_after": not_after,
        "is_expired": is_expired,
        "days_until_expiry": days_until_expiry,
        "san_domains": san_domains,
        "signature_algorithm": sig_algorithm,
        "public_key_algorithm": pub_key_algorithm,
        "public_key_bits": pub_key_bits,
        "is_self_signed": is_self_signed,
        "is_wildcard": is_wildcard,
        "has_weak_signature": has_weak_signature,
        "tls_version": tls_version,
        "tls_fingerprint": None,
        "cipher_suites": [cipher[0]] if cipher else None,
    }


@celery.task(name="tasks.harvest_certificates", bind=True, max_retries=1)
def harvest_certificates(self, tenant_id: int) -> dict:
    """
    Harvest TLS certificates for all assets with has_tls=true services.

    Uses Python ssl + cryptography - no external tools needed.
    """
    from app.database import SessionLocal
    from app.repositories.certificate_repository import CertificateRepository
    from app.models.database import Service

    db = SessionLocal()
    tenant_logger = TenantLoggerAdapter(logger, {"tenant_id": tenant_id})

    try:
        # Find all assets that have TLS services
        tls_assets = (
            db.query(Asset, Service.port)
            .join(Service, Service.asset_id == Asset.id)
            .filter(
                Asset.tenant_id == tenant_id,
                Service.has_tls == True,
            )
            .distinct()
            .all()
        )

        if not tls_assets:
            tenant_logger.info("No TLS assets found for certificate harvesting")
            return {"certificates_discovered": 0, "status": "no_tls_assets"}

        tenant_logger.info(f"Harvesting certificates from {len(tls_assets)} TLS asset/port combos")

        cert_repo = CertificateRepository(db)
        total_created = 0
        total_updated = 0
        total_errors = 0

        # Group by asset to batch upserts
        certs_by_asset: dict[int, list[dict]] = {}

        for asset, port in tls_assets:
            target_port = port or 443
            host = asset.identifier

            tenant_logger.debug(f"Fetching cert from {host}:{target_port}")
            cert_data = fetch_certificate(host, target_port, timeout=10.0)

            if cert_data:
                certs_by_asset.setdefault(asset.id, []).append(cert_data)

                # Also update service TLS fields
                svc = (
                    db.query(Service)
                    .filter(
                        Service.asset_id == asset.id,
                        Service.port == target_port,
                    )
                    .first()
                )
                if svc:
                    svc.tls_version = cert_data.get("tls_version")
                    svc.tls_fingerprint = cert_data.get("tls_fingerprint")
            else:
                total_errors += 1

        # Bulk upsert certificates per asset
        for asset_id, asset_certs in certs_by_asset.items():
            result = cert_repo.bulk_upsert(asset_id, asset_certs)
            total_created += result["created"]
            total_updated += result["updated"]

        db.commit()

        tenant_logger.info(
            f"Certificate harvest complete: {total_created} new, "
            f"{total_updated} updated, {total_errors} errors"
        )

        return {
            "certificates_discovered": total_created + total_updated,
            "certificates_created": total_created,
            "certificates_updated": total_updated,
            "errors": total_errors,
            "status": "completed",
        }

    except Exception as e:
        tenant_logger.error(f"Certificate harvest failed: {e}", exc_info=True)
        db.rollback()
        return {"error": str(e), "certificates_discovered": 0, "status": "failed"}
    finally:
        db.close()
