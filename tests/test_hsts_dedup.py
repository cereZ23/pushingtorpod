"""Tests for HSTS finding deduplication (one finding per asset, not per port)."""

from __future__ import annotations

from unittest.mock import MagicMock

from app.models.database import Asset, AssetType, Service


def _make_asset(identifier="test.example.com"):
    a = MagicMock(spec=Asset)
    a.identifier = identifier
    a.type = AssetType.SUBDOMAIN
    return a


def _make_tls_service(port, hsts_value=None, http_headers=None):
    svc = MagicMock(spec=Service)
    svc.port = port
    svc.has_tls = True
    svc.http_status = 200
    svc.http_title = "Test"
    svc.http_headers = http_headers or ({"strict-transport-security": hsts_value} if hsts_value else {})
    svc.product = None
    svc.protocol = "https"
    return svc


class TestHSTSDedup:
    def test_no_hsts_one_finding_per_asset(self):
        from app.tasks.misconfig import check_hdr_004

        asset = _make_asset()
        services = [_make_tls_service(443), _make_tls_service(8443)]
        findings = check_hdr_004(asset, services, [], None)

        # Should produce exactly 1 finding, not 2
        assert len(findings) == 1
        assert findings[0]["control_id"] == "HDR-004"
        assert "ports" in findings[0]["evidence"]

    def test_valid_hsts_no_finding(self):
        from app.tasks.misconfig import check_hdr_004

        asset = _make_asset()
        services = [_make_tls_service(443, hsts_value="max-age=31536000; includeSubDomains")]
        findings = check_hdr_004(asset, services, [], None)

        assert len(findings) == 0

    def test_weak_hsts_one_finding(self):
        from app.tasks.misconfig import check_hdr_004

        asset = _make_asset()
        services = [
            _make_tls_service(443, hsts_value="max-age=3600"),
            _make_tls_service(8443, hsts_value="max-age=7200"),
        ]
        findings = check_hdr_004(asset, services, [], None)

        assert len(findings) == 1
        assert "too short" in findings[0]["name"].lower()

    def test_mixed_valid_and_weak_no_finding(self):
        from app.tasks.misconfig import check_hdr_004

        asset = _make_asset()
        services = [
            _make_tls_service(443, hsts_value="max-age=31536000"),
            _make_tls_service(8443, hsts_value="max-age=3600"),
        ]
        findings = check_hdr_004(asset, services, [], None)

        # Port 443 has valid HSTS → asset is covered
        assert len(findings) == 0
