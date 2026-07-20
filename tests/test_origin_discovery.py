"""Tests for WAF origin discovery (app/services/origin_discovery.py)."""

import json
from unittest.mock import MagicMock, patch

from app.models.database import Asset, AssetType
from app.services.origin_discovery import (
    _asset_ips,
    _is_public_ip,
    _looks_like_origin,
    _registrable_domain,
    gather_origin_candidates,
    verify_origin,
)


class TestPureHelpers:
    def test_is_public_ip(self):
        assert _is_public_ip("203.0.113.10") is True
        assert _is_public_ip("8.8.8.8") is True
        assert _is_public_ip("10.0.0.1") is False
        assert _is_public_ip("127.0.0.1") is False
        assert _is_public_ip("not-an-ip") is False

    def test_registrable_domain(self):
        assert _registrable_domain("www.example.com") == "example.com"
        assert _registrable_domain("a.b.example.com") == "example.com"
        assert _registrable_domain("example.com") == "example.com"

    def test_asset_ips_from_metadata_and_identifier(self):
        asset = Asset(
            identifier="host.example.com",
            type=AssetType.SUBDOMAIN,
            raw_metadata=json.dumps({"a": ["203.0.113.5", "203.0.113.6"]}),
        )
        assert _asset_ips(asset) == ["203.0.113.5", "203.0.113.6"]

        ip_asset = Asset(identifier="203.0.113.9", type=AssetType.IP, raw_metadata=None)
        assert _asset_ips(ip_asset) == ["203.0.113.9"]

    def test_looks_like_origin(self):
        assert _looks_like_origin({"reachable": True, "status": 200}) is True
        assert _looks_like_origin({"reachable": True, "status": 403}) is True
        assert _looks_like_origin({"reachable": True, "status": 500}) is False
        assert _looks_like_origin({"reachable": False}) is False


class TestGatherCandidates:
    def _asset(self, db, tenant_id, identifier, **kw):
        asset = Asset(tenant_id=tenant_id, identifier=identifier, type=AssetType.SUBDOMAIN, is_active=True, **kw)
        db.add(asset)
        db.commit()
        db.refresh(asset)
        return asset

    def test_non_fronted_sibling_ip_is_candidate(self, db_session, tenant):
        fronted = self._asset(
            db_session,
            tenant.id,
            "www.example.com",
            waf_name="cloudflare",
            raw_metadata=json.dumps({"a": ["104.16.0.1"]}),  # CDN IP
        )
        # A sibling that resolves directly (no WAF/CDN) → its IP is the candidate
        self._asset(
            db_session,
            tenant.id,
            "direct.example.com",
            raw_metadata=json.dumps({"a": ["203.0.113.10"]}),
        )
        # A sibling ALSO behind a WAF must be ignored
        self._asset(
            db_session,
            tenant.id,
            "cdn.example.com",
            cdn_name="akamai",
            raw_metadata=json.dumps({"a": ["203.0.113.99"]}),
        )
        # A different registrable domain must be ignored
        self._asset(
            db_session,
            tenant.id,
            "www.other.com",
            raw_metadata=json.dumps({"a": ["203.0.113.50"]}),
        )

        candidates = gather_origin_candidates(db_session, fronted, use_external=False)
        assert candidates == ["203.0.113.10"]

    def test_no_candidates_when_no_direct_siblings(self, db_session, tenant):
        fronted = self._asset(
            db_session,
            tenant.id,
            "www.lonely.com",
            waf_name="sucuri",
            raw_metadata=json.dumps({"a": ["104.16.0.2"]}),
        )
        assert gather_origin_candidates(db_session, fronted, use_external=False) == []

    def test_spf_ip_is_candidate(self, db_session, tenant):
        fronted = self._asset(
            db_session,
            tenant.id,
            "www.spf.com",
            waf_name="cloudflare",
            raw_metadata=json.dumps(
                {
                    "a": ["104.16.0.3"],
                    "txt": ["v=spf1 ip4:203.0.113.20 ip4:198.51.100.0/24 include:_spf.google.com -all"],
                }
            ),
        )
        candidates = gather_origin_candidates(db_session, fronted, use_external=False)
        # bare ip4 host is a candidate; the /24 range is skipped
        assert "203.0.113.20" in candidates
        assert "198.51.100.0" not in candidates

    def test_crtsh_source_merged_when_enabled(self, db_session, tenant):
        fronted = self._asset(
            db_session,
            tenant.id,
            "www.crt.com",
            waf_name="sucuri",
            raw_metadata=json.dumps({"a": ["104.16.0.4"]}),
        )
        with (
            patch(
                "app.services.origin_discovery._crtsh_hostnames",
                return_value={"origin.crt.com"},
            ),
            patch(
                "app.services.origin_discovery._resolve_ipv4",
                return_value=["203.0.113.30"],
            ),
        ):
            candidates = gather_origin_candidates(db_session, fronted, use_external=True)
        assert "203.0.113.30" in candidates


def _mock_client(resp=None, raise_first=False):
    client = MagicMock()
    client.__enter__.return_value = client
    client.__exit__.return_value = False
    if raise_first:
        client.get.side_effect = Exception("refused")
    else:
        client.get.return_value = resp
    return client


class TestVerifyOrigin:
    def test_reachable_origin(self):
        resp = MagicMock(status_code=200, headers={"server": "nginx"}, text="<title>My Site</title>")
        with patch("httpx.Client", return_value=_mock_client(resp)):
            result = verify_origin("www.example.com", "203.0.113.10", timeout=3)
        assert result["reachable"] is True
        assert result["status"] == 200
        assert result["server"] == "nginx"
        assert result["title"] == "My Site"
        assert result["scheme"] == "https"

    def test_unreachable_origin(self):
        with patch("httpx.Client", return_value=_mock_client(raise_first=True)):
            result = verify_origin("www.example.com", "203.0.113.10", timeout=3)
        assert result["reachable"] is False

    def test_private_ip_never_probed(self):
        with patch("httpx.Client") as client:
            result = verify_origin("www.example.com", "10.0.0.5", timeout=3)
        assert result["reachable"] is False
        client.assert_not_called()
