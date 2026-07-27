"""Tests for HSTS finding deduplication (one finding per asset, not per port)."""

from __future__ import annotations

import json
from types import SimpleNamespace


def _make_asset(identifier="test.example.com"):
    return SimpleNamespace(identifier=identifier, type=SimpleNamespace(value="subdomain"))


def _make_tls_service(port, hsts_value=None):
    # Always include at least one header so _get_http_headers returns non-empty
    # (empty dict means "no headers collected" and gets skipped)
    headers = {"content-type": "text/html"}
    if hsts_value is not None:
        headers["strict-transport-security"] = hsts_value
    return SimpleNamespace(
        port=port,
        has_tls=True,
        http_status=200,
        http_title="My Site",
        http_headers=json.dumps(headers),
        product=None,
        protocol="https",
    )


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


class _FakeQuery:
    def filter(self, *a, **k):
        return self

    def first(self):
        return None


class _FakeDB:
    """Minimal db stub: no existing findings, records what gets added."""

    def __init__(self):
        self.added = []

    def query(self, *a, **k):
        return _FakeQuery()

    def add(self, obj):
        self.added.append(obj)


def _member(identifier, asset_id, *, max_age=None):
    ev = {"ports": [443], "confidence": 0.85, "remediation": "Set HSTS."}
    if max_age is not None:
        ev["max_age_seconds"] = max_age
        ev["hsts_value"] = f"max-age={max_age}"
    from app.models.database import FindingSeverity

    return {
        "asset": SimpleNamespace(id=asset_id, identifier=identifier),
        "name": "HSTS",
        "severity_enum": FindingSeverity.LOW if max_age is not None else FindingSeverity.MEDIUM,
        "evidence": ev,
    }


class TestHSTSRootConsolidation:
    """Orchestrator-level: many subdomains under one root -> one finding."""

    def _control(self):
        return {"id": "HDR-004", "category": "Security Headers", "confidence": 0.85}

    def _stats(self):
        return {
            "findings_created": 0,
            "findings_updated": 0,
            "controls_by_category": {"Security Headers": {"executed": 0, "findings": 0}},
        }

    def test_many_subdomains_collapse_to_one(self):
        from app.tasks.misconfig import _consolidate_root_scoped

        db = _FakeDB()
        by_root = {
            "example.com": [
                _member("www.example.com", 1),
                _member("api.example.com", 2),
                _member("mail.example.com", 3),
            ]
        }
        _consolidate_root_scoped(
            db,
            tenant_id=1,
            control=self._control(),
            by_root=by_root,
            assets_by_identifier={},
            stats=self._stats(),
        )

        assert len(db.added) == 1
        f = db.added[0]
        assert f.template_id == "HDR-004:root:example.com"
        assert f.host == "example.com"
        assert f.evidence["affected_count"] == 3
        hosts = {h["host"] for h in f.evidence["affected_hosts"]}
        assert hosts == {"www.example.com", "api.example.com", "mail.example.com"}

    def test_severity_escalates_to_worst(self):
        from app.tasks.misconfig import _consolidate_root_scoped
        from app.models.database import FindingSeverity

        db = _FakeDB()
        by_root = {
            "example.com": [
                _member("weak.example.com", 1, max_age=3600),  # LOW (weak)
                _member("missing.example.com", 2),  # MEDIUM (missing)
            ]
        }
        _consolidate_root_scoped(
            db,
            tenant_id=1,
            control=self._control(),
            by_root=by_root,
            assets_by_identifier={},
            stats=self._stats(),
        )
        assert db.added[0].severity == FindingSeverity.MEDIUM

    def test_attaches_to_root_asset_when_present(self):
        from app.tasks.misconfig import _consolidate_root_scoped

        db = _FakeDB()
        root_asset = SimpleNamespace(id=99, identifier="example.com")
        by_root = {"example.com": [_member("www.example.com", 1)]}
        _consolidate_root_scoped(
            db,
            tenant_id=1,
            control=self._control(),
            by_root=by_root,
            assets_by_identifier={"example.com": root_asset},
            stats=self._stats(),
        )
        assert db.added[0].asset_id == 99

    def test_falls_back_to_representative_subdomain(self):
        from app.tasks.misconfig import _consolidate_root_scoped

        db = _FakeDB()
        # No example.com asset -> attach to the first affected subdomain (id 1).
        by_root = {"example.com": [_member("www.example.com", 1), _member("api.example.com", 2)]}
        _consolidate_root_scoped(
            db,
            tenant_id=1,
            control=self._control(),
            by_root=by_root,
            assets_by_identifier={},
            stats=self._stats(),
        )
        assert db.added[0].asset_id == 1
