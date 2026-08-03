"""Traccia A: the DNS/network nuclei pass must NOT load Katana endpoints.

HTTP endpoint paths are meaningless for dns/network templates and were inflating that pass toward
the per-batch timeout. ``run_nuclei_scan(include_katana_endpoints=False)`` must skip the endpoint
LOADER entirely (not merely produce an empty result), so the opt-out is an explicit contract rather
than an inference from template names. These tests spy on the loader seam and assert call vs no-call.
"""

from __future__ import annotations

import app.tasks.scanning as scanning
from app.models.database import Asset, AssetType


class _FakeNuclei:
    """Stand-in for NucleiService so the scan reaches the Katana gate without executing nuclei."""

    def __init__(self, tenant_id):
        self.tenant_id = tenant_id

    async def scan_urls_batched(self, **kwargs):
        return {"findings": [], "stats": {"findings_count": 0}, "errors": [], "truncated": False}


def _run_with_spy(db_session, tenant, monkeypatch, *, include):
    # run_nuclei_scan opens its own session via `from app.database import SessionLocal`.
    monkeypatch.setattr("app.database.SessionLocal", lambda: db_session)
    monkeypatch.setattr(db_session, "close", lambda: None)
    monkeypatch.setattr(scanning, "NucleiService", _FakeNuclei)
    monkeypatch.setattr(scanning, "update_asset_risk_scores", lambda *a, **k: 0)

    calls = {"n": 0}

    def spy(db, tenant_id, asset_ids):
        calls["n"] += 1
        return []

    monkeypatch.setattr(scanning, "_query_katana_endpoints", spy)

    asset = Asset(tenant_id=tenant.id, identifier="dnsnet.test.com", type=AssetType.SUBDOMAIN, is_active=True)
    db_session.add(asset)
    db_session.commit()

    result = scanning.run_nuclei_scan(
        tenant.id,
        [asset.id],
        templates=["dns/", "network/"],
        include_katana_endpoints=include,
    )
    return calls["n"], result


def test_dns_network_pass_does_not_call_endpoint_loader(db_session, test_tenant, monkeypatch):
    n, result = _run_with_spy(db_session, test_tenant, monkeypatch, include=False)
    assert n == 0  # the LOADER itself was never called — not just an empty result
    assert result.get("status") == "success"


def test_http_pass_still_calls_endpoint_loader(db_session, test_tenant, monkeypatch):
    n, result = _run_with_spy(db_session, test_tenant, monkeypatch, include=True)
    assert n == 1  # default/HTTP passes still enrich targets with Katana endpoints
    assert result.get("status") == "success"


def test_run_nuclei_scan_is_registered_celery_task():
    # Regression: the @celery.task decorator must stay on run_nuclei_scan, not slip onto the
    # _query_katana_endpoints helper inserted just above it (which would silently break task
    # registration and invocation).
    assert scanning.run_nuclei_scan.name == "app.tasks.scanning.run_nuclei_scan"
    assert hasattr(scanning.run_nuclei_scan, "delay")
    # the loader seam is a plain function, NOT a task
    assert not hasattr(scanning._query_katana_endpoints, "delay")


def test_disabled_pass_not_truncated_even_if_authorizations_explode(db_session, test_tenant, monkeypatch):
    # With enrichment disabled, NOTHING in the Katana path (query, authorization resolution,
    # filtering) may run — so a failure there must not mark the DNS/network pass truncated. Arm a
    # landmine in _active_authorizations and assert the disabled pass still reports coverage clean.
    import app.services.scope_authorization as scope_auth

    monkeypatch.setattr("app.database.SessionLocal", lambda: db_session)
    monkeypatch.setattr(db_session, "close", lambda: None)
    monkeypatch.setattr(scanning, "NucleiService", _FakeNuclei)
    monkeypatch.setattr(scanning, "update_asset_risk_scores", lambda *a, **k: 0)

    def _boom(*a, **k):
        raise RuntimeError("authorization backend down")

    monkeypatch.setattr(scope_auth, "_active_authorizations", _boom)

    asset = Asset(tenant_id=test_tenant.id, identifier="dnsnet2.test.com", type=AssetType.SUBDOMAIN, is_active=True)
    db_session.add(asset)
    db_session.commit()

    result = scanning.run_nuclei_scan(
        test_tenant.id, [asset.id], templates=["dns/", "network/"], include_katana_endpoints=False
    )
    assert result.get("status") == "success"
    assert result.get("truncated") is False  # a disabled pass is never truncated by a Katana failure
    assert result.get("katana_load_failed") is False
