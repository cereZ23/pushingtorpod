"""Tests for the tool-invariant scan-health gate (app.services.scan_health)."""

from unittest.mock import patch

from app.models.database import Asset, AssetType, Service
from app.services.scan_health import validate_scan_health


def _no_close(session):
    """Wrap a session so the gate's db.close() doesn't tear down the fixture."""
    session.close = lambda: None  # type: ignore[assignment]
    return session


def test_empty_tenant_discovery_fails(db_session, tenant):
    """A tenant with no assets must fail the discovery invariant."""
    with patch("app.services.scan_health.SessionLocal", return_value=_no_close(db_session)):
        result = validate_scan_health(tenant.id, scan_run_id=1, pipeline_stats={})

    assert result["overall"] == "fail"
    assert result["degraded"] is True
    assert "discovery" in result["failures"]


def test_https_service_without_cert_degrades(db_session, tenant):
    """Live HTTPS services with zero certificates => tlsx silently failed => DEGRADED."""
    asset = Asset(tenant_id=tenant.id, identifier="www.example.com", type=AssetType.SUBDOMAIN)
    db_session.add(asset)
    db_session.commit()
    db_session.refresh(asset)

    # A live HTTPS service, but no Certificate rows for the tenant.
    db_session.add(Service(asset_id=asset.id, port=443, protocol="https", http_status=200, has_tls=True))
    db_session.commit()

    with patch("app.services.scan_health.SessionLocal", return_value=_no_close(db_session)):
        result = validate_scan_health(tenant.id, scan_run_id=2, pipeline_stats={})

    assert result["degraded"] is True
    assert "tls_certs" in result["failures"]
    # httpx succeeded (there IS a live service), so http_probe must pass
    statuses = {c["name"]: c["status"] for c in result["checks"]}
    assert statuses["http_probe"] == "pass"
    assert statuses["tls_certs"] == "fail"


def test_fatal_phase_marks_degraded(db_session, tenant):
    """A fatal pipeline phase (via pipeline_stats) forces a degraded verdict."""
    asset = Asset(tenant_id=tenant.id, identifier="ok.example.com", type=AssetType.SUBDOMAIN)
    db_session.add(asset)
    db_session.commit()

    with patch("app.services.scan_health.SessionLocal", return_value=_no_close(db_session)):
        result = validate_scan_health(tenant.id, scan_run_id=3, pipeline_stats={"_fatal": True})

    assert result["degraded"] is True
    assert "pipeline" in result["failures"]
