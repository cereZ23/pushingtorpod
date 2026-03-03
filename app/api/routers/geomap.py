"""
Geographic Map API Router

Provides GeoJSON endpoints for visualizing asset locations on a map,
along with aggregated geographic and infrastructure summary statistics.

Data source: GeoIP enrichment stored in Asset.raw_metadata (JSON text column)
under the ``network`` key (populated by app.services.network_intel).
"""

import json
import logging
from collections import defaultdict
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.api.dependencies import get_db, verify_tenant_access
from app.models.database import (
    Asset,
    Finding,
    FindingSeverity,
    FindingStatus,
    Tenant,
)

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/tenants/{tenant_id}/geomap",
    tags=["Geographic Map"],
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _verify_tenant_exists(db: Session, tenant_id: int) -> None:
    """Raise 404 if the tenant does not exist."""
    exists = db.query(Tenant.id).filter(Tenant.id == tenant_id).first()
    if not exists:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Tenant not found",
        )


def _parse_raw_metadata(raw_metadata: Optional[str]) -> Optional[dict]:
    """
    Safely parse the raw_metadata JSON text field.

    Returns the parsed dict, or None if the value is absent or malformed.
    """
    if not raw_metadata:
        return None
    try:
        data = json.loads(raw_metadata)
        if isinstance(data, dict):
            return data
    except (json.JSONDecodeError, TypeError):
        pass
    return None


def _extract_geo(metadata: dict) -> Optional[dict]:
    """
    Extract network geo data from parsed raw_metadata.

    Returns the network sub-dict only when both lat and lon are present
    and are valid numeric values.
    """
    network = metadata.get("network")
    if not isinstance(network, dict):
        return None

    lat = network.get("lat")
    lon = network.get("lon")

    # Validate that lat/lon are numeric (int or float)
    if lat is None or lon is None:
        return None
    if not isinstance(lat, (int, float)) or not isinstance(lon, (int, float)):
        return None

    return network


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/assets")
def get_geomap_assets(
    tenant_id: int,
    asset_type: Optional[str] = Query(
        None,
        description="Filter by asset type: domain, subdomain, ip",
    ),
    min_risk: int = Query(0, ge=0, le=100, description="Minimum risk score"),
    db: Session = Depends(get_db),
    membership=Depends(verify_tenant_access),
) -> dict[str, Any]:
    """
    Return geolocated assets as a GeoJSON FeatureCollection.

    Each Feature contains a Point geometry (lon, lat) and properties with
    asset metadata, network intelligence, and a per-severity finding count.

    Only active assets whose ``raw_metadata`` contains valid ``network.lat``
    and ``network.lon`` values are included.
    """
    _verify_tenant_exists(db, tenant_id)

    # Build base query for active assets in this tenant
    query = db.query(Asset).filter(
        Asset.tenant_id == tenant_id,
        Asset.is_active.is_(True),
    )

    if asset_type:
        query = query.filter(Asset.type == asset_type)

    if min_risk > 0:
        query = query.filter(Asset.risk_score >= min_risk)

    assets = query.all()

    # Collect asset IDs that have valid geo data so we can batch-query findings
    geo_assets: list[tuple[Asset, dict, dict]] = []  # (asset, metadata, network)
    geo_asset_ids: list[int] = []

    for asset in assets:
        metadata = _parse_raw_metadata(asset.raw_metadata)
        if metadata is None:
            continue
        network = _extract_geo(metadata)
        if network is None:
            continue
        geo_assets.append((asset, metadata, network))
        geo_asset_ids.append(asset.id)

    # Batch query: count findings per asset grouped by severity
    findings_map: dict[int, dict[str, int]] = defaultdict(
        lambda: {s.value: 0 for s in FindingSeverity}
    )

    if geo_asset_ids:
        severity_counts = (
            db.query(
                Finding.asset_id,
                Finding.severity,
                func.count(Finding.id),
            )
            .filter(
                Finding.asset_id.in_(geo_asset_ids),
                Finding.status == FindingStatus.OPEN,
            )
            .group_by(Finding.asset_id, Finding.severity)
            .all()
        )

        for asset_id, severity, count in severity_counts:
            findings_map[asset_id][severity.value] = count

    # Build GeoJSON features
    features: list[dict[str, Any]] = []

    for asset, metadata, network in geo_assets:
        finding_counts = findings_map.get(
            asset.id,
            {s.value: 0 for s in FindingSeverity},
        )
        total_findings = sum(finding_counts.values())

        feature: dict[str, Any] = {
            "type": "Feature",
            "geometry": {
                "type": "Point",
                "coordinates": [network["lon"], network["lat"]],
            },
            "properties": {
                "id": asset.id,
                "identifier": asset.identifier,
                "type": asset.type.value if hasattr(asset.type, "value") else str(asset.type),
                "risk_score": round(asset.risk_score or 0.0, 2),
                "ip": network.get("ip"),
                "country": network.get("country"),
                "country_code": network.get("country_code"),
                "city": network.get("city"),
                "region": network.get("region"),
                "asn": network.get("asn"),
                "asn_org": network.get("asn_org"),
                "isp": network.get("isp"),
                "cdn": metadata.get("cdn"),
                "waf": metadata.get("waf"),
                "cloud_provider": metadata.get("cloud_provider"),
                "findings": finding_counts,
                "total_findings": total_findings,
            },
        }
        features.append(feature)

    return {
        "type": "FeatureCollection",
        "features": features,
        "total": len(features),
    }


@router.get("/summary")
def get_geomap_summary(
    tenant_id: int,
    db: Session = Depends(get_db),
    membership=Depends(verify_tenant_access),
) -> dict[str, Any]:
    """
    Aggregated geographic and infrastructure summary for the tenant.

    Returns total geolocated vs total assets, country breakdown with
    average risk score, and cloud / CDN / WAF provider distributions.
    All lists are sorted by count descending.
    """
    _verify_tenant_exists(db, tenant_id)

    # Fetch all active assets for the tenant
    assets = (
        db.query(Asset)
        .filter(
            Asset.tenant_id == tenant_id,
            Asset.is_active.is_(True),
        )
        .all()
    )

    total_assets = len(assets)

    # Accumulators
    countries: dict[str, dict[str, Any]] = {}  # code -> {name, count, risk_sum}
    cloud_providers: dict[str, int] = defaultdict(int)
    cdn_providers: dict[str, int] = defaultdict(int)
    waf_providers: dict[str, int] = defaultdict(int)
    total_geolocated = 0

    for asset in assets:
        metadata = _parse_raw_metadata(asset.raw_metadata)
        if metadata is None:
            continue

        network = _extract_geo(metadata)
        if network is None:
            continue

        total_geolocated += 1
        risk = asset.risk_score or 0.0

        # Country aggregation
        country_code = network.get("country_code")
        country_name = network.get("country")
        if country_code:
            if country_code not in countries:
                countries[country_code] = {
                    "code": country_code,
                    "name": country_name or country_code,
                    "count": 0,
                    "risk_sum": 0.0,
                }
            countries[country_code]["count"] += 1
            countries[country_code]["risk_sum"] += risk

        # Infrastructure providers (top-level keys in raw_metadata)
        cloud = metadata.get("cloud_provider")
        if cloud:
            cloud_providers[cloud] += 1

        cdn = metadata.get("cdn")
        if cdn:
            cdn_providers[cdn] += 1

        waf = metadata.get("waf")
        if waf:
            waf_providers[waf] += 1

    # Build sorted country list with average risk
    country_list = sorted(
        [
            {
                "country_code": v["code"],
                "country": v["name"],
                "count": v["count"],
                "avg_risk": round(v["risk_sum"] / v["count"], 1) if v["count"] > 0 else 0.0,
            }
            for v in countries.values()
        ],
        key=lambda c: c["count"],
        reverse=True,
    )

    def _sorted_provider_list(mapping: dict[str, int]) -> list[dict[str, Any]]:
        return sorted(
            [{"name": name, "count": count} for name, count in mapping.items()],
            key=lambda p: p["count"],
            reverse=True,
        )

    return {
        "total_geolocated": total_geolocated,
        "total_assets": total_assets,
        "countries": country_list,
        "cloud_providers": _sorted_provider_list(cloud_providers),
        "cdn_providers": _sorted_provider_list(cdn_providers),
        "waf_providers": _sorted_provider_list(waf_providers),
    }
