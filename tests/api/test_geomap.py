"""
Geographic Map API Endpoint Tests

Tests for /api/v1/tenants/{tenant_id}/geomap endpoints:
- GET /assets  (GeoJSON FeatureCollection)
- GET /summary (country / cloud / CDN / WAF aggregates)

Covers app/api/routers/geomap.py
"""

from __future__ import annotations

import json

import pytest

from app.models.database import (
    Asset,
    AssetType,
    Finding,
    FindingSeverity,
    FindingStatus,
)


def _metadata_blob(
    *,
    ip="1.2.3.4",
    country="Italy",
    country_code="IT",
    city="Milan",
    region="Lombardy",
    asn="AS12345",
    asn_org="Example ISP",
    isp="ExampleNet",
    lat=45.4642,
    lon=9.19,
    cloud_provider=None,
    cdn=None,
    waf=None,
):
    blob = {
        "network": {
            "ip": ip,
            "country": country,
            "country_code": country_code,
            "city": city,
            "region": region,
            "asn": asn,
            "asn_org": asn_org,
            "isp": isp,
            "lat": lat,
            "lon": lon,
        }
    }
    if cloud_provider:
        blob["cloud_provider"] = cloud_provider
    if cdn:
        blob["cdn"] = cdn
    if waf:
        blob["waf"] = waf
    return json.dumps(blob)


@pytest.fixture
def geo_assets(db_session, test_tenant):
    """Create a set of assets with and without geo data."""
    assets = [
        Asset(
            tenant_id=test_tenant.id,
            identifier="milan.example.com",
            type=AssetType.SUBDOMAIN,
            risk_score=70.0,
            is_active=True,
            raw_metadata=_metadata_blob(
                country="Italy",
                country_code="IT",
                city="Milan",
                lat=45.46,
                lon=9.19,
                cloud_provider="AWS",
                cdn="Cloudflare",
                waf="ModSecurity",
            ),
        ),
        Asset(
            tenant_id=test_tenant.id,
            identifier="paris.example.com",
            type=AssetType.SUBDOMAIN,
            risk_score=40.0,
            is_active=True,
            raw_metadata=_metadata_blob(
                country="France",
                country_code="FR",
                city="Paris",
                lat=48.85,
                lon=2.35,
                cloud_provider="AWS",
                cdn="Fastly",
            ),
        ),
        # No geo data
        Asset(
            tenant_id=test_tenant.id,
            identifier="nogeo.example.com",
            type=AssetType.SUBDOMAIN,
            risk_score=10.0,
            is_active=True,
            raw_metadata=json.dumps({"network": {"ip": "10.0.0.1"}}),
        ),
        # Malformed metadata
        Asset(
            tenant_id=test_tenant.id,
            identifier="broken.example.com",
            type=AssetType.SUBDOMAIN,
            risk_score=5.0,
            is_active=True,
            raw_metadata="not a json string {{",
        ),
        # No metadata at all
        Asset(
            tenant_id=test_tenant.id,
            identifier="nometa.example.com",
            type=AssetType.SUBDOMAIN,
            risk_score=0.0,
            is_active=True,
            raw_metadata=None,
        ),
    ]
    db_session.add_all(assets)
    db_session.commit()
    for a in assets:
        db_session.refresh(a)
    return assets


@pytest.fixture
def geo_assets_with_findings(db_session, geo_assets):
    """Attach open findings to the Milan asset for severity aggregation."""
    milan = geo_assets[0]
    findings = [
        Finding(
            asset_id=milan.id,
            source="nuclei",
            template_id="tpl-1",
            name="Crit",
            severity=FindingSeverity.CRITICAL,
            cvss_score=9.5,
            status=FindingStatus.OPEN,
            evidence={},
        ),
        Finding(
            asset_id=milan.id,
            source="nuclei",
            template_id="tpl-2",
            name="High",
            severity=FindingSeverity.HIGH,
            cvss_score=7.5,
            status=FindingStatus.OPEN,
            evidence={},
        ),
        # Fixed finding -- should not be counted
        Finding(
            asset_id=milan.id,
            source="nuclei",
            template_id="tpl-fixed",
            name="Fixed",
            severity=FindingSeverity.LOW,
            cvss_score=3.0,
            status=FindingStatus.FIXED,
            evidence={},
        ),
    ]
    db_session.add_all(findings)
    db_session.commit()
    return findings


# ---------------------------------------------------------------------------
# /assets GeoJSON endpoint
# ---------------------------------------------------------------------------


class TestGeomapAssets:
    def test_geojson_empty(self, authenticated_client, test_tenant):
        response = authenticated_client.get(f"/api/v1/tenants/{test_tenant.id}/geomap/assets")
        assert response.status_code == 200
        data = response.json()
        assert data["type"] == "FeatureCollection"
        assert data["features"] == []
        assert data["total"] == 0

    def test_geojson_includes_valid_geo(self, authenticated_client, test_tenant, geo_assets):
        response = authenticated_client.get(f"/api/v1/tenants/{test_tenant.id}/geomap/assets")
        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 2  # Only milan + paris have valid lat/lon
        for feat in data["features"]:
            assert feat["type"] == "Feature"
            assert feat["geometry"]["type"] == "Point"
            assert len(feat["geometry"]["coordinates"]) == 2

    def test_geojson_excludes_invalid_geo(self, authenticated_client, test_tenant, geo_assets):
        response = authenticated_client.get(f"/api/v1/tenants/{test_tenant.id}/geomap/assets")
        data = response.json()
        idents = [f["properties"]["identifier"] for f in data["features"]]
        assert "milan.example.com" in idents
        assert "nogeo.example.com" not in idents
        assert "broken.example.com" not in idents
        assert "nometa.example.com" not in idents

    def test_geojson_severity_counts(self, authenticated_client, test_tenant, geo_assets_with_findings, geo_assets):
        response = authenticated_client.get(f"/api/v1/tenants/{test_tenant.id}/geomap/assets")
        data = response.json()
        milan = next(f for f in data["features"] if f["properties"]["identifier"] == "milan.example.com")
        findings = milan["properties"]["findings"]
        assert findings["critical"] == 1
        assert findings["high"] == 1
        assert findings.get("low", 0) == 0  # The FIXED finding shouldn't be counted
        assert milan["properties"]["total_findings"] == 2

    def test_geojson_without_filter_returns_all_geolocated(self, authenticated_client, test_tenant, geo_assets):
        """Sanity check: without filter, all geolocated subdomains appear."""
        response = authenticated_client.get(f"/api/v1/tenants/{test_tenant.id}/geomap/assets")
        assert response.status_code == 200
        data = response.json()
        # All features are subdomain in our fixture and carry that property.
        for feat in data["features"]:
            assert feat["properties"]["type"] in ("subdomain", "domain", "ip")

    def test_geojson_filter_by_min_risk(self, authenticated_client, test_tenant, geo_assets):
        response = authenticated_client.get(
            f"/api/v1/tenants/{test_tenant.id}/geomap/assets",
            params={"min_risk": 50},
        )
        data = response.json()
        for feat in data["features"]:
            assert feat["properties"]["risk_score"] >= 50

    def test_geojson_min_risk_out_of_range_returns_422(self, authenticated_client, test_tenant):
        response = authenticated_client.get(
            f"/api/v1/tenants/{test_tenant.id}/geomap/assets",
            params={"min_risk": 101},
        )
        assert response.status_code == 422

    def test_geojson_properties_contain_network_data(self, authenticated_client, test_tenant, geo_assets):
        response = authenticated_client.get(f"/api/v1/tenants/{test_tenant.id}/geomap/assets")
        data = response.json()
        milan = next(f for f in data["features"] if f["properties"]["identifier"] == "milan.example.com")
        props = milan["properties"]
        assert props["country"] == "Italy"
        assert props["country_code"] == "IT"
        assert props["city"] == "Milan"
        assert props["cloud_provider"] == "AWS"
        assert props["cdn"] == "Cloudflare"
        assert props["waf"] == "ModSecurity"

    def test_requires_authentication(self, client, test_tenant):
        response = client.get(f"/api/v1/tenants/{test_tenant.id}/geomap/assets")
        assert response.status_code in (401, 403)


# ---------------------------------------------------------------------------
# /summary aggregation endpoint
# ---------------------------------------------------------------------------


class TestGeomapSummary:
    def test_summary_empty(self, authenticated_client, test_tenant):
        response = authenticated_client.get(f"/api/v1/tenants/{test_tenant.id}/geomap/summary")
        assert response.status_code == 200
        data = response.json()
        assert data["total_assets"] == 0
        assert data["total_geolocated"] == 0
        assert data["countries"] == []

    def test_summary_counts(self, authenticated_client, test_tenant, geo_assets):
        response = authenticated_client.get(f"/api/v1/tenants/{test_tenant.id}/geomap/summary")
        assert response.status_code == 200
        data = response.json()
        assert data["total_assets"] == 5
        assert data["total_geolocated"] == 2

    def test_summary_country_aggregation(self, authenticated_client, test_tenant, geo_assets):
        response = authenticated_client.get(f"/api/v1/tenants/{test_tenant.id}/geomap/summary")
        data = response.json()
        countries = {c["country_code"]: c for c in data["countries"]}
        assert "IT" in countries
        assert "FR" in countries
        assert countries["IT"]["count"] == 1
        assert countries["IT"]["avg_risk"] == 70.0

    def test_summary_provider_aggregation(self, authenticated_client, test_tenant, geo_assets):
        response = authenticated_client.get(f"/api/v1/tenants/{test_tenant.id}/geomap/summary")
        data = response.json()
        cloud = {p["name"]: p["count"] for p in data["cloud_providers"]}
        assert cloud.get("AWS") == 2
        cdn = {p["name"]: p["count"] for p in data["cdn_providers"]}
        assert cdn.get("Cloudflare") == 1
        assert cdn.get("Fastly") == 1
        waf = {p["name"]: p["count"] for p in data["waf_providers"]}
        assert waf.get("ModSecurity") == 1

    def test_summary_providers_sorted_desc(self, authenticated_client, test_tenant, geo_assets):
        response = authenticated_client.get(f"/api/v1/tenants/{test_tenant.id}/geomap/summary")
        data = response.json()
        for provider_list in (
            data["cloud_providers"],
            data["cdn_providers"],
            data["waf_providers"],
        ):
            counts = [p["count"] for p in provider_list]
            assert counts == sorted(counts, reverse=True)

    def test_requires_authentication(self, client, test_tenant):
        response = client.get(f"/api/v1/tenants/{test_tenant.id}/geomap/summary")
        assert response.status_code in (401, 403)
