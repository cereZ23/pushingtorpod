"""Base-URL helper (Sprint 3, step 3b-2b) — the http_endpoint pass uses these to drop the phase's
real base URLs from its endpoint candidate set (including odd ports like :8443)."""

from __future__ import annotations

from app.models.database import Asset, AssetType, Service
from app.services.scanning.base_urls import build_base_urls, build_base_urls_by_asset


def _asset(db, tenant, ident="app.curci.it", type_=AssetType.SUBDOMAIN):
    a = Asset(tenant_id=tenant.id, identifier=ident, type=type_, is_active=True)
    db.add(a)
    db.commit()
    db.refresh(a)
    return a


def _service(db, asset, *, port, has_tls, protocol="tcp", http_status=200):
    s = Service(asset_id=asset.id, port=port, protocol=protocol, has_tls=has_tls, http_status=http_status)
    db.add(s)
    db.commit()
    return s


def test_fallback_for_subdomain_without_services(db_session, test_tenant):
    a = _asset(db_session, test_tenant)
    assert build_base_urls_by_asset(db_session, [a])[a.id] == ["https://app.curci.it", "http://app.curci.it"]
    assert set(build_base_urls(db_session, [a])) == {"https://app.curci.it", "http://app.curci.it"}


def test_https_default_port_has_no_port_suffix(db_session, test_tenant):
    a = _asset(db_session, test_tenant)
    _service(db_session, a, port=443, has_tls=True)
    assert build_base_urls(db_session, [a]) == ["https://app.curci.it"]


def test_odd_port_is_kept_in_base_url(db_session, test_tenant):
    # the case the endpoint pass's base-URL drop must handle: a real base target on :8443
    a = _asset(db_session, test_tenant)
    _service(db_session, a, port=8443, has_tls=True)
    assert build_base_urls(db_session, [a]) == ["https://app.curci.it:8443"]


def test_scheme_from_tls_flag_not_transport_protocol(db_session, test_tenant):
    # protocol stores the transport ("tcp"); scheme must come from has_tls / port, not protocol
    a = _asset(db_session, test_tenant)
    _service(db_session, a, port=80, has_tls=False)
    assert build_base_urls(db_session, [a]) == ["http://app.curci.it"]
