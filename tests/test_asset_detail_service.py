"""
Unit tests for app/services/asset_detail_service.py

Covers:
- AssetDetailService.get_detail happy path (subdomain asset with services/certs/endpoints/findings)
- Services/endpoints/certificates/findings/events serialization
- Technology stack aggregation (JSON list + list + web_server)
- HTTP info serialization
- DNS info builder (_build_dns_info) with raw_metadata, network enrichment, WHOIS, GeoIP
- Cloud provider detection (_detect_cloud_provider): headers, web_server, IP prefixes
- Service-type asset enrichment (_enrich_service_asset)
- Missing asset returns None
"""

from __future__ import annotations

import datetime as dt
import json
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from app.models.database import AssetType, FindingSeverity, FindingStatus, EventKind
from app.services.asset_detail_service import AssetDetailService, _CLOUD_HINTS


# ----------------------- helpers -----------------------


def _make_asset(
    asset_id=1,
    tenant_id=1,
    identifier="host.example.com",
    type_value=AssetType.SUBDOMAIN,
    raw_metadata=None,
    services=None,
    findings=None,
    events=None,
    is_active=True,
    risk_score=10.0,
):
    asset = SimpleNamespace()
    asset.id = asset_id
    asset.tenant_id = tenant_id
    asset.identifier = identifier
    asset.type = type_value
    asset.raw_metadata = raw_metadata
    asset.services = services or []
    asset.findings = findings or []
    asset.events = events or []
    asset.is_active = is_active
    asset.risk_score = risk_score
    asset.first_seen = dt.datetime(2024, 1, 1, 0, 0, 0, tzinfo=dt.timezone.utc)
    asset.last_seen = dt.datetime(2024, 1, 2, 0, 0, 0, tzinfo=dt.timezone.utc)
    asset.last_enriched_at = None
    asset.enrichment_status = "pending"
    asset.priority = "medium"
    asset.priority_updated_at = None
    asset.priority_auto_calculated = False
    asset.service_count = 0
    asset.certificate_count = 0
    asset.endpoint_count = 0
    asset.finding_count = 0
    return asset


def _make_service(**kw):
    defaults = {
        "id": 1,
        "asset_id": 1,
        "port": 443,
        "protocol": "https",
        "product": None,
        "version": None,
        "tls_fingerprint": None,
        "http_title": None,
        "http_status": None,
        "technologies": None,
        "web_server": None,
        "has_tls": False,
        "tls_version": None,
        "http_technologies": None,
        "response_time_ms": None,
        "content_length": None,
        "redirect_url": None,
        "enrichment_source": None,
        "enriched_at": None,
        "first_seen": None,
        "last_seen": None,
        "http_headers": None,
    }
    defaults.update(kw)
    return SimpleNamespace(**defaults)


def _make_finding(**kw):
    defaults = {
        "id": 1,
        "asset_id": 1,
        "source": "nuclei",
        "template_id": "t1",
        "name": "F1",
        "severity": FindingSeverity.HIGH,
        "cvss_score": 7.5,
        "cve_id": None,
        "status": FindingStatus.OPEN,
        "matched_at": "http://x",
        "host": "x",
        "matcher_name": "m",
        "fingerprint": "fp",
        "occurrence_count": 1,
        "first_seen": None,
        "last_seen": None,
    }
    defaults.update(kw)
    return SimpleNamespace(**defaults)


def _make_cert(**kw):
    defaults = {
        "id": 1,
        "subject_cn": "x.com",
        "issuer": "Let's Encrypt",
        "serial_number": "SN",
        "not_before": None,
        "not_after": None,
        "is_expired": False,
        "days_until_expiry": 90,
        "san_domains": ["x.com"],
        "signature_algorithm": "sha256",
        "public_key_algorithm": "RSA",
        "public_key_bits": 2048,
        "is_self_signed": False,
        "is_wildcard": False,
        "has_weak_signature": False,
        "first_seen": None,
        "last_seen": None,
    }
    defaults.update(kw)
    return SimpleNamespace(**defaults)


def _make_endpoint(**kw):
    defaults = {
        "id": 1,
        "url": "http://x/p",
        "path": "/p",
        "method": "GET",
        "status_code": 200,
        "content_type": "text/html",
        "endpoint_type": "page",
        "is_api": False,
        "is_external": False,
        "depth": 0,
        "last_seen": None,
    }
    defaults.update(kw)
    return SimpleNamespace(**defaults)


def _make_event(**kw):
    defaults = {
        "id": 1,
        "asset_id": 1,
        "kind": EventKind.NEW_ASSET,
        "payload": {"foo": "bar"},
        "created_at": dt.datetime(2024, 1, 1, 12, 0, 0),
    }
    defaults.update(kw)
    return SimpleNamespace(**defaults)


class _EmptyResult:
    def filter(self, *a, **kw):
        return self

    def filter_by(self, *a, **kw):
        return self

    def order_by(self, *a, **kw):
        return self

    def limit(self, *a, **kw):
        return self

    def first(self):
        return None

    def all(self):
        return []


def _ResultWith(first_val=None, all_val=None):
    obj = _EmptyResult()
    obj.first = lambda: first_val
    obj.all = lambda: all_val or []
    return obj


# ----------------------- tests for get_detail -----------------------


class TestAssetDetailServiceGetDetail:
    def test_returns_none_when_asset_not_found(self):
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = None
        svc = AssetDetailService(db)
        assert svc.get_detail(tenant_id=1, asset_id=999) is None

    def test_basic_subdomain_asset_shape(self):
        asset = _make_asset()
        db = MagicMock()
        db.query.side_effect = [
            _ResultWith(first_val=asset),
            _ResultWith(all_val=[]),
            _ResultWith(all_val=[]),
        ]
        svc = AssetDetailService(db)
        data = svc.get_detail(tenant_id=1, asset_id=1)
        assert data is not None
        assert data["services"] == []
        assert data["certificates"] == []
        assert data["endpoints"] == []
        assert data["findings"] == []
        assert data["events"] == []
        assert data["tech_stack"] == []
        assert data["http_info"] == []
        assert data["summary"]["total_services"] == 0

    def test_services_serialization(self):
        svc_obj = _make_service(
            port=443,
            product="nginx",
            version="1.18",
            http_title="Hello",
            http_status=200,
            technologies='["php"]',
            web_server="nginx",
            has_tls=True,
            http_technologies=["jquery"],
        )
        asset = _make_asset(services=[svc_obj])
        db = MagicMock()
        db.query.side_effect = [
            _ResultWith(first_val=asset),
            _ResultWith(all_val=[]),
            _ResultWith(all_val=[]),
        ]
        svc = AssetDetailService(db)
        data = svc.get_detail(1, 1)
        assert len(data["services"]) == 1
        s = data["services"][0]
        assert s["port"] == 443
        assert s["product"] == "nginx"
        assert "php" in data["tech_stack"]
        assert "jquery" in data["tech_stack"]
        assert "nginx" in data["tech_stack"]

    def test_http_info_includes_service_with_http(self):
        s1 = _make_service(port=443, http_status=200, http_title="T")
        s2 = _make_service(port=80, http_status=None, http_title=None)
        asset = _make_asset(services=[s1, s2])
        db = MagicMock()
        db.query.side_effect = [
            _ResultWith(first_val=asset),
            _ResultWith(all_val=[]),
            _ResultWith(all_val=[]),
        ]
        svc = AssetDetailService(db)
        data = svc.get_detail(1, 1)
        assert len(data["http_info"]) == 1
        assert data["http_info"][0]["port"] == 443

    def test_summary_aggregates(self):
        s1 = _make_service(port=443, has_tls=True)
        s2 = _make_service(port=80, has_tls=False, id=2)
        f1 = _make_finding(severity=FindingSeverity.CRITICAL, status=FindingStatus.OPEN)
        f2 = _make_finding(severity=FindingSeverity.LOW, status=FindingStatus.FIXED, id=2)
        asset = _make_asset(services=[s1, s2], findings=[f1, f2])
        db = MagicMock()
        db.query.side_effect = [
            _ResultWith(first_val=asset),
            _ResultWith(all_val=[]),
            _ResultWith(all_val=[]),
        ]
        svc = AssetDetailService(db)
        data = svc.get_detail(1, 1)
        assert data["summary"]["total_services"] == 2
        assert data["summary"]["total_findings"] == 2
        assert data["summary"]["open_findings"] == 1
        assert set(data["summary"]["open_ports"]) == {80, 443}
        assert data["summary"]["has_tls"] is True
        assert data["summary"]["has_http"] is True
        assert data["summary"]["severity_breakdown"]["critical"] == 1
        assert data["summary"]["severity_breakdown"]["low"] == 1

    def test_technology_invalid_json_is_ignored(self):
        s = _make_service(technologies="not-json-at-all")
        asset = _make_asset(services=[s])
        db = MagicMock()
        db.query.side_effect = [
            _ResultWith(first_val=asset),
            _ResultWith(all_val=[]),
            _ResultWith(all_val=[]),
        ]
        svc = AssetDetailService(db)
        data = svc.get_detail(1, 1)
        assert data["tech_stack"] == []

    def test_certificates_and_endpoints_included(self):
        cert = _make_cert(subject_cn="api.x.com")
        ep = _make_endpoint(url="http://x/api")
        asset = _make_asset()
        db = MagicMock()
        db.query.side_effect = [
            _ResultWith(first_val=asset),
            _ResultWith(all_val=[cert]),
            _ResultWith(all_val=[ep]),
        ]
        svc = AssetDetailService(db)
        data = svc.get_detail(1, 1)
        assert len(data["certificates"]) == 1
        assert data["certificates"][0]["subject_cn"] == "api.x.com"
        assert len(data["endpoints"]) == 1
        assert data["endpoints"][0]["url"] == "http://x/api"

    def test_events_sorted_desc_and_limited(self):
        evs = [
            _make_event(id=i, created_at=dt.datetime(2024, 1, 1, 0, 0, 0) + dt.timedelta(minutes=i)) for i in range(60)
        ]
        asset = _make_asset(events=evs)
        db = MagicMock()
        db.query.side_effect = [
            _ResultWith(first_val=asset),
            _ResultWith(all_val=[]),
            _ResultWith(all_val=[]),
        ]
        svc = AssetDetailService(db)
        data = svc.get_detail(1, 1)
        assert len(data["events"]) == 50
        assert data["events"][0]["id"] == 59


# ----------------------- tests for _build_dns_info -----------------------


class TestBuildDnsInfo:
    def _svc(self, db=None):
        return AssetDetailService(db or MagicMock())

    def test_no_metadata_returns_defaults(self):
        asset = _make_asset(raw_metadata=None)
        dns = self._svc()._build_dns_info(asset)
        assert dns["resolved_ips"] == []
        assert dns["reverse_dns"] is None
        assert dns["whois_summary"] is None
        assert dns["asn_info"] is None

    def test_ip_asset_uses_identifier_as_resolved_ip(self):
        asset = _make_asset(identifier="1.2.3.4", type_value=AssetType.IP)
        dns = self._svc()._build_dns_info(asset)
        assert dns["resolved_ips"] == ["1.2.3.4"]

    def test_raw_metadata_a_records(self):
        meta = json.dumps({"a_records": ["10.0.0.1", "10.0.0.2"]})
        asset = _make_asset(raw_metadata=meta)
        dns = self._svc()._build_dns_info(asset)
        assert set(dns["resolved_ips"]) == {"10.0.0.1", "10.0.0.2"}

    def test_raw_metadata_resolved_ips_preferred(self):
        meta = json.dumps({"resolved_ips": ["1.1.1.1"], "a_records": ["9.9.9.9"]})
        asset = _make_asset(raw_metadata=meta)
        dns = self._svc()._build_dns_info(asset)
        assert dns["resolved_ips"] == ["1.1.1.1"]

    def test_reverse_dns_from_network(self):
        meta = json.dumps({"network": {"reverse_dns": "x.example.com"}})
        asset = _make_asset(raw_metadata=meta)
        dns = self._svc()._build_dns_info(asset)
        assert dns["reverse_dns"] == "x.example.com"

    def test_reverse_dns_legacy_keys(self):
        meta = json.dumps({"rdns": "legacy.rev.dns"})
        asset = _make_asset(raw_metadata=meta)
        dns = self._svc()._build_dns_info(asset)
        assert dns["reverse_dns"] == "legacy.rev.dns"

    def test_asn_from_network(self):
        meta = json.dumps({"network": {"asn": "AS12345", "asn_org": "ACME", "country": "US"}})
        asset = _make_asset(raw_metadata=meta)
        dns = self._svc()._build_dns_info(asset)
        assert dns["asn_info"]["asn"] == "AS12345"
        assert dns["asn_info"]["org"] == "ACME"

    def test_asn_legacy(self):
        meta = json.dumps({"asn": {"asn": "AS42"}})
        asset = _make_asset(raw_metadata=meta)
        dns = self._svc()._build_dns_info(asset)
        assert dns["asn_info"]["asn"] == "AS42"

    def test_geoip_info(self):
        meta = json.dumps(
            {
                "network": {
                    "country": "US",
                    "country_code": "US",
                    "city": "SF",
                    "lat": 37.7,
                    "lon": -122.4,
                    "isp": "Comcast",
                }
            }
        )
        asset = _make_asset(raw_metadata=meta)
        dns = self._svc()._build_dns_info(asset)
        assert dns["geo_info"]["city"] == "SF"
        assert dns["geo_info"]["isp"] == "Comcast"

    def test_whois_summary(self):
        meta = json.dumps({"whois": {"registrar": "Namecheap"}})
        asset = _make_asset(raw_metadata=meta)
        dns = self._svc()._build_dns_info(asset)
        assert dns["whois_summary"]["registrar"] == "Namecheap"

    def test_explicit_cloud_provider_overrides_heuristic(self):
        meta = json.dumps({"cloud_provider": "DigitalOcean"})
        asset = _make_asset(raw_metadata=meta)
        dns = self._svc()._build_dns_info(asset)
        assert dns["cloud_provider"] == "DigitalOcean"

    def test_invalid_metadata_json_is_safe(self):
        asset = _make_asset(raw_metadata="not-json")
        dns = self._svc()._build_dns_info(asset)
        assert dns["resolved_ips"] == []

    def test_dict_metadata_is_rejected_gracefully(self):
        asset = _make_asset(raw_metadata={"already": "dict"})
        dns = self._svc()._build_dns_info(asset)
        assert dns["resolved_ips"] == []


# ----------------------- tests for _detect_cloud_provider -----------------------


class TestDetectCloudProvider:
    def _svc(self):
        return AssetDetailService(MagicMock())

    def test_cloudflare_header(self):
        s = _make_service()
        s.http_headers = {"Server": "cloudflare"}
        asset = _make_asset(services=[s])
        assert self._svc()._detect_cloud_provider([], asset) == "Cloudflare"

    def test_akamai_header(self):
        s = _make_service()
        s.http_headers = {"X-CDN": "AkamaiGHost"}
        asset = _make_asset(services=[s])
        assert self._svc()._detect_cloud_provider([], asset) == "Akamai"

    def test_aws_header(self):
        s = _make_service()
        s.http_headers = {"Server": "AmazonS3"}
        asset = _make_asset(services=[s])
        assert self._svc()._detect_cloud_provider([], asset) == "AWS"

    def test_gcp_header_google(self):
        s = _make_service()
        s.http_headers = {"Server": "gws"}
        asset = _make_asset(services=[s])
        assert self._svc()._detect_cloud_provider([], asset) == "GCP"

    def test_azure_header(self):
        s = _make_service()
        s.http_headers = {"X-Powered-By": "Microsoft-Azure"}
        asset = _make_asset(services=[s])
        assert self._svc()._detect_cloud_provider([], asset) == "Azure"

    def test_web_server_cloudflare(self):
        s = _make_service(web_server="cloudflare-nginx")
        asset = _make_asset(services=[s])
        assert self._svc()._detect_cloud_provider([], asset) == "Cloudflare"

    def test_web_server_akamai(self):
        s = _make_service(web_server="AkamaiGHost")
        asset = _make_asset(services=[s])
        assert self._svc()._detect_cloud_provider([], asset) == "Akamai"

    def test_ip_prefix_cloudflare(self):
        asset = _make_asset(services=[])
        ip = _CLOUD_HINTS["Cloudflare"][0] + "1.1"
        assert self._svc()._detect_cloud_provider([ip], asset) == "Cloudflare"

    def test_ip_prefix_aws(self):
        asset = _make_asset(services=[])
        # 44.x is AWS-only
        assert self._svc()._detect_cloud_provider(["44.1.2.3"], asset) == "AWS"

    def test_no_match(self):
        asset = _make_asset(services=[])
        assert self._svc()._detect_cloud_provider(["8.8.8.8"], asset) is None

    def test_empty_ips_and_no_headers(self):
        asset = _make_asset(services=[])
        assert self._svc()._detect_cloud_provider([], asset) is None

    def test_skips_empty_string_ip(self):
        asset = _make_asset(services=[])
        assert self._svc()._detect_cloud_provider(["", None], asset) is None


# ----------------------- tests for SERVICE-type asset enrichment -----------------------


class TestEnrichServiceAsset:
    def test_no_parent_found_leaves_response_unchanged(self):
        asset = _make_asset(
            identifier="smtp.x.com:5269",
            type_value=AssetType.SERVICE,
            services=[],
        )
        db = MagicMock()
        db.query.side_effect = [
            _ResultWith(first_val=asset),
            _ResultWith(all_val=[]),
            _ResultWith(all_val=[]),
            _ResultWith(first_val=None),  # parent not found
        ]
        svc = AssetDetailService(db)
        data = svc.get_detail(1, 1)
        assert "parent_asset" not in data
        assert data["services"] == []

    def test_service_asset_with_parent_matched_port(self):
        parent_svc = _make_service(port=5269, product="ejabberd", has_tls=False)
        parent_cert = _make_cert()
        parent_finding = _make_finding(severity=FindingSeverity.MEDIUM, status=FindingStatus.OPEN)
        parent = _make_asset(
            asset_id=2,
            identifier="smtp.x.com",
            type_value=AssetType.SUBDOMAIN,
            services=[parent_svc],
            findings=[parent_finding],
        )
        asset = _make_asset(
            identifier="smtp.x.com:5269",
            type_value=AssetType.SERVICE,
            services=[],
        )
        db = MagicMock()
        db.query.side_effect = [
            _ResultWith(first_val=asset),
            _ResultWith(all_val=[]),
            _ResultWith(all_val=[]),
            _ResultWith(first_val=parent),
            _ResultWith(all_val=[parent_cert]),
        ]
        svc = AssetDetailService(db)
        data = svc.get_detail(1, 1)
        assert data["parent_asset"]["id"] == 2
        assert data["parent_asset"]["identifier"] == "smtp.x.com"
        assert len(data["services"]) == 1
        assert data["services"][0]["port"] == 5269
        assert len(data["certificates"]) == 1
        assert len(data["findings"]) == 1
        assert data["summary"]["total_findings"] == 1

    def test_service_asset_no_port_in_identifier(self):
        parent = _make_asset(asset_id=3, identifier="bare.x.com", type_value=AssetType.SUBDOMAIN)
        asset = _make_asset(identifier="bare.x.com", type_value=AssetType.SERVICE, services=[])
        db = MagicMock()
        db.query.side_effect = [
            _ResultWith(first_val=asset),
            _ResultWith(all_val=[]),
            _ResultWith(all_val=[]),
            _ResultWith(first_val=parent),
            _ResultWith(all_val=[]),
        ]
        svc = AssetDetailService(db)
        data = svc.get_detail(1, 1)
        assert data["parent_asset"]["identifier"] == "bare.x.com"

    def test_service_asset_invalid_port(self):
        parent = _make_asset(asset_id=3, identifier="bar.x.com", type_value=AssetType.SUBDOMAIN)
        asset = _make_asset(identifier="bar.x.com:notaport", type_value=AssetType.SERVICE, services=[])
        db = MagicMock()
        db.query.side_effect = [
            _ResultWith(first_val=asset),
            _ResultWith(all_val=[]),
            _ResultWith(all_val=[]),
            _ResultWith(first_val=parent),
            _ResultWith(all_val=[]),
        ]
        svc = AssetDetailService(db)
        data = svc.get_detail(1, 1)
        assert data["parent_asset"]["identifier"] == "bar.x.com"
