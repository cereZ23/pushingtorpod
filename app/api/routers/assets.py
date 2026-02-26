"""
Assets Router

Handles asset management, discovery, and hierarchy
"""

from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session
from sqlalchemy import or_, and_, func, select
from typing import List, Optional
from datetime import datetime, timezone
import json
import logging

from app.api.dependencies import (
    get_db,
    verify_tenant_access,
    PaginationParams,
    escape_like,
)
from app.api.schemas.asset import (
    AssetResponse,
    AssetCreate,
    AssetUpdate,
    AssetListRequest,
    AssetDetailResponse,
    AssetTreeNode,
    SeedCreate,
    SeedResponse,
    BulkAssetCreate
)
from app.api.schemas.common import BulkOperationResult
from app.api.schemas.envelope import PaginatedEnvelope, PaginationMeta
from app.models.database import Asset, AssetType, Seed, Service, Finding
from app.models.enrichment import Certificate, Endpoint
from app.repositories.asset_repository import AssetRepository

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/tenants/{tenant_id}/assets", tags=["Assets"])


@router.get("", response_model=PaginatedEnvelope[AssetResponse])
def list_assets(
    tenant_id: int,
    asset_type: Optional[str] = Query(None, description="Filter by asset type"),
    priority: Optional[str] = Query(None, description="Filter by priority"),
    enrichment_status: Optional[str] = Query(None, description="Filter by enrichment status"),
    is_active: Optional[bool] = Query(None, description="Filter by active status"),
    search: Optional[str] = Query(None, description="Search in identifier"),
    min_risk_score: Optional[float] = Query(None, description="Minimum risk score"),
    max_risk_score: Optional[float] = Query(None, description="Maximum risk score"),
    changed_since: Optional[datetime] = Query(None, description="Changed since timestamp"),
    sort_by: str = Query("last_seen", description="Sort field"),
    sort_order: str = Query("desc", description="Sort order"),
    pagination: PaginationParams = Depends(),
    db: Session = Depends(get_db),
    membership = Depends(verify_tenant_access)
):
    """
    List assets with filtering, search, and pagination

    Supports:
    - Type filtering (domain, subdomain, ip, url)
    - Priority filtering (critical, high, normal, low)
    - Risk score range
    - Search by identifier
    - Changed since timestamp (for delta queries)
    - Sorting and pagination

    Returns:
        Paginated list of assets
    """
    # Build query
    query = db.query(Asset).filter(Asset.tenant_id == tenant_id)

    # Apply filters
    if asset_type:
        try:
            query = query.filter(Asset.type == AssetType(asset_type))
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid asset type: {asset_type}"
            )

    if priority:
        query = query.filter(Asset.priority == priority)

    if enrichment_status:
        query = query.filter(Asset.enrichment_status == enrichment_status)

    if is_active is not None:
        query = query.filter(Asset.is_active == is_active)

    if search:
        safe_search = escape_like(search)
        query = query.filter(Asset.identifier.ilike(f"%{safe_search}%", escape="\\"))

    if min_risk_score is not None:
        query = query.filter(Asset.risk_score >= min_risk_score)

    if max_risk_score is not None:
        query = query.filter(Asset.risk_score <= max_risk_score)

    if changed_since:
        query = query.filter(
            or_(
                Asset.last_seen >= changed_since,
                Asset.last_enriched_at >= changed_since
            )
        )

    # Get total count before pagination
    total = query.count()

    # Apply sorting
    ALLOWED_SORT_COLUMNS = {
        "identifier": Asset.identifier,
        "type": Asset.type,
        "first_seen": Asset.first_seen,
        "last_seen": Asset.last_seen,
        "risk_score": Asset.risk_score,
    }
    sort_column = ALLOWED_SORT_COLUMNS.get(sort_by, Asset.last_seen)
    if sort_order.lower() == "desc":
        query = query.order_by(sort_column.desc())
    else:
        query = query.order_by(sort_column.asc())

    # Apply pagination
    query = pagination.paginate_query(query)

    # Add correlated subquery counts (single query instead of N+1)
    service_count_sq = (
        select(func.count(Service.id))
        .where(Service.asset_id == Asset.id)
        .correlate(Asset)
        .scalar_subquery()
        .label('service_count')
    )
    certificate_count_sq = (
        select(func.count(Certificate.id))
        .where(Certificate.asset_id == Asset.id)
        .correlate(Asset)
        .scalar_subquery()
        .label('certificate_count')
    )
    endpoint_count_sq = (
        select(func.count(Endpoint.id))
        .where(Endpoint.asset_id == Asset.id)
        .correlate(Asset)
        .scalar_subquery()
        .label('endpoint_count')
    )
    finding_count_sq = (
        select(func.count(Finding.id))
        .where(Finding.asset_id == Asset.id)
        .correlate(Asset)
        .scalar_subquery()
        .label('finding_count')
    )

    # Execute query with counts in a single DB round-trip
    query = query.add_columns(
        service_count_sq,
        certificate_count_sq,
        endpoint_count_sq,
        finding_count_sq,
    )
    results = query.all()

    items = []
    for row in results:
        asset = row[0] if isinstance(row, tuple) else row.Asset if hasattr(row, 'Asset') else row
        asset_dict = AssetResponse.model_validate(asset).model_dump()
        asset_dict['service_count'] = row.service_count if hasattr(row, 'service_count') else 0
        asset_dict['certificate_count'] = row.certificate_count if hasattr(row, 'certificate_count') else 0
        asset_dict['endpoint_count'] = row.endpoint_count if hasattr(row, 'endpoint_count') else 0
        asset_dict['finding_count'] = row.finding_count if hasattr(row, 'finding_count') else 0
        items.append(asset_dict)

    return PaginatedEnvelope(
        data=items,
        meta=PaginationMeta(
            total=total,
            page=pagination.page,
            page_size=pagination.page_size,
            total_pages=(total + pagination.page_size - 1) // pagination.page_size,
        ),
    )


@router.get("/{asset_id}", response_model=AssetDetailResponse)
def get_asset(
    tenant_id: int,
    asset_id: int,
    db: Session = Depends(get_db),
    membership = Depends(verify_tenant_access)
):
    """
    Get asset by ID with comprehensive EASM detail

    Includes:
    - Asset metadata and enrichment status
    - Services with HTTP and TLS details
    - Certificates from TLSx (queried directly)
    - Endpoints from Katana crawler (limited to 100)
    - Findings with fingerprint and occurrence data
    - Events (last 50)
    - DNS/Network intelligence (IPs, rDNS, ASN, cloud provider)
    - Aggregated technology stack
    - Summary statistics with severity breakdown
    - HTTP response info per service

    Raises:
        - 404: Asset not found
        - 403: No access to tenant
    """
    asset = db.query(Asset).filter(
        Asset.id == asset_id,
        Asset.tenant_id == tenant_id
    ).first()

    if not asset:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Asset not found"
        )

    # Query certificates and endpoints directly (bypassing broken relationships)
    certificates = db.query(Certificate).filter(
        Certificate.asset_id == asset_id
    ).all()

    endpoints = db.query(Endpoint).filter(
        Endpoint.asset_id == asset_id
    ).order_by(Endpoint.last_seen.desc()).limit(100).all()

    # Build base response
    response_data = AssetResponse.model_validate(asset).model_dump()

    # ------------------------------------------------------------------ #
    # Services serialization
    # ------------------------------------------------------------------ #
    response_data['services'] = [
        {
            'id': s.id,
            'asset_id': s.asset_id,
            'port': s.port,
            'protocol': s.protocol,
            'product': s.product,
            'version': s.version,
            'tls_fingerprint': s.tls_fingerprint,
            'http_title': s.http_title,
            'http_status': s.http_status,
            'technologies': s.technologies,
            'web_server': s.web_server,
            'has_tls': s.has_tls,
            'tls_version': s.tls_version,
            'http_technologies': s.http_technologies,
            'response_time_ms': s.response_time_ms,
            'content_length': s.content_length,
            'redirect_url': s.redirect_url,
            'enrichment_source': s.enrichment_source,
            'enriched_at': s.enriched_at.isoformat() if s.enriched_at else None,
            'first_seen': s.first_seen.isoformat() if s.first_seen else None,
            'last_seen': s.last_seen.isoformat() if s.last_seen else None,
        }
        for s in asset.services
    ]

    # ------------------------------------------------------------------ #
    # Certificates serialization (queried directly)
    # ------------------------------------------------------------------ #
    response_data['certificates'] = [
        {
            'id': c.id,
            'subject_cn': c.subject_cn,
            'issuer': c.issuer,
            'serial_number': c.serial_number,
            'not_before': c.not_before.isoformat() if c.not_before else None,
            'not_after': c.not_after.isoformat() if c.not_after else None,
            'is_expired': c.is_expired,
            'days_until_expiry': c.days_until_expiry,
            'san_domains': c.san_domains,
            'signature_algorithm': c.signature_algorithm,
            'public_key_algorithm': c.public_key_algorithm,
            'public_key_bits': c.public_key_bits,
            'is_self_signed': c.is_self_signed,
            'is_wildcard': c.is_wildcard,
            'has_weak_signature': c.has_weak_signature,
            'first_seen': c.first_seen.isoformat() if c.first_seen else None,
            'last_seen': c.last_seen.isoformat() if c.last_seen else None,
        }
        for c in certificates
    ]

    # ------------------------------------------------------------------ #
    # Endpoints serialization (queried directly, max 100)
    # ------------------------------------------------------------------ #
    response_data['endpoints'] = [
        {
            'id': e.id,
            'url': e.url,
            'path': e.path,
            'method': e.method,
            'status_code': e.status_code,
            'content_type': e.content_type,
            'endpoint_type': e.endpoint_type,
            'is_api': e.is_api,
            'is_external': e.is_external,
            'depth': e.depth,
        }
        for e in endpoints
    ]

    # ------------------------------------------------------------------ #
    # Findings serialization (with fingerprint + occurrence_count)
    # ------------------------------------------------------------------ #
    response_data['findings'] = [
        {
            'id': f.id,
            'asset_id': f.asset_id,
            'source': f.source,
            'template_id': f.template_id,
            'name': f.name,
            'severity': f.severity.value if hasattr(f.severity, 'value') else str(f.severity),
            'cvss_score': f.cvss_score,
            'cve_id': f.cve_id,
            'status': f.status.value if hasattr(f.status, 'value') else str(f.status),
            'matched_at': f.matched_at,
            'host': f.host,
            'matcher_name': f.matcher_name,
            'fingerprint': f.fingerprint,
            'occurrence_count': f.occurrence_count,
            'first_seen': f.first_seen.isoformat() if f.first_seen else None,
            'last_seen': f.last_seen.isoformat() if f.last_seen else None,
        }
        for f in asset.findings
    ]

    # ------------------------------------------------------------------ #
    # Events serialization (last 50 by created_at desc)
    # ------------------------------------------------------------------ #
    response_data['events'] = [
        {
            'id': e.id,
            'asset_id': e.asset_id,
            'kind': e.kind.value if hasattr(e.kind, 'value') else str(e.kind),
            'payload': e.payload,
            'created_at': e.created_at.isoformat() if e.created_at else None,
        }
        for e in sorted(asset.events, key=lambda e: e.created_at, reverse=True)[:50]
    ]

    # ------------------------------------------------------------------ #
    # Technology stack aggregation
    # ------------------------------------------------------------------ #
    tech_stack: set[str] = set()
    for s in asset.services:
        # technologies is a Text column that may hold a JSON-encoded list
        if s.technologies:
            try:
                techs = json.loads(s.technologies) if isinstance(s.technologies, str) else s.technologies
                if isinstance(techs, list):
                    tech_stack.update(str(t) for t in techs)
            except (ValueError, TypeError):
                pass
        # http_technologies is a native JSON column (list)
        if s.http_technologies and isinstance(s.http_technologies, list):
            tech_stack.update(str(t) for t in s.http_technologies)
        if s.web_server:
            tech_stack.add(s.web_server)

    response_data['tech_stack'] = sorted(tech_stack)

    # ------------------------------------------------------------------ #
    # HTTP response info (only services with HTTP data)
    # ------------------------------------------------------------------ #
    http_info_list = []
    for s in asset.services:
        if s.http_status or s.http_title:
            # Parse per-service technologies
            svc_techs: list[str] = []
            if s.technologies:
                try:
                    parsed = json.loads(s.technologies) if isinstance(s.technologies, str) else s.technologies
                    if isinstance(parsed, list):
                        svc_techs = [str(t) for t in parsed]
                except (ValueError, TypeError):
                    pass
            if s.http_technologies and isinstance(s.http_technologies, list):
                svc_techs.extend(str(t) for t in s.http_technologies)

            http_info_list.append({
                'port': s.port,
                'title': s.http_title,
                'status_code': s.http_status,
                'web_server': s.web_server,
                'technologies': svc_techs,
                'response_time_ms': s.response_time_ms,
                'redirect_url': s.redirect_url,
                'has_tls': s.has_tls,
                'tls_version': s.tls_version,
            })
    response_data['http_info'] = http_info_list

    # ------------------------------------------------------------------ #
    # DNS / Network intelligence
    # ------------------------------------------------------------------ #
    dns_info = _build_dns_info(asset)
    response_data['dns_info'] = dns_info

    # ------------------------------------------------------------------ #
    # Summary statistics
    # ------------------------------------------------------------------ #
    severity_counts: dict[str, int] = {}
    for f in asset.findings:
        sev = f.severity.value if hasattr(f.severity, 'value') else str(f.severity)
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    open_findings = sum(
        1 for f in asset.findings
        if (f.status.value if hasattr(f.status, 'value') else str(f.status)) == 'open'
    )

    open_ports = sorted(set(
        s.port for s in asset.services if s.port is not None
    ))

    response_data['summary'] = {
        'total_services': len(asset.services),
        'total_findings': len(asset.findings),
        'total_certificates': len(certificates),
        'total_endpoints': len(endpoints),
        'open_ports': open_ports,
        'has_tls': any(s.has_tls for s in asset.services),
        'has_http': any(
            s.port in (80, 443, 8080, 8443)
            for s in asset.services if s.port is not None
        ),
        'severity_breakdown': severity_counts,
        'open_findings': open_findings,
    }

    # ------------------------------------------------------------------ #
    # SERVICE-type asset: resolve parent and inherit data
    # ------------------------------------------------------------------ #
    if asset.type and asset.type.value == 'service' and not response_data['services']:
        _enrich_service_asset(asset, db, response_data)

    return response_data


def _enrich_service_asset(asset: Asset, db: Session, response_data: dict) -> None:
    """
    For SERVICE-type assets (e.g. smtp.l.autistici.org:5269), find the parent
    subdomain/domain and pull the relevant service record + findings.

    Modifies response_data in place.
    """
    identifier = asset.identifier or ''

    # Parse hostname and port from identifier (e.g. "host.example.com:5269")
    if ':' in identifier:
        hostname = identifier.rsplit(':', 1)[0]
        try:
            target_port = int(identifier.rsplit(':', 1)[1])
        except ValueError:
            target_port = None
    else:
        hostname = identifier
        target_port = None

    # Find parent asset (subdomain, domain, or IP matching hostname)
    parent = db.query(Asset).filter(
        Asset.tenant_id == asset.tenant_id,
        Asset.identifier == hostname,
        Asset.type.in_([AssetType.SUBDOMAIN, AssetType.DOMAIN, AssetType.IP]),
    ).first()

    if not parent:
        return

    # Add parent_asset reference
    response_data['parent_asset'] = {
        'id': parent.id,
        'identifier': parent.identifier,
        'type': parent.type.value if hasattr(parent.type, 'value') else str(parent.type),
        'risk_score': parent.risk_score,
        'is_active': parent.is_active,
    }

    # Pull the matching service from the parent
    matching_service = None
    for s in parent.services:
        if target_port is not None and s.port == target_port:
            matching_service = s
            break

    if matching_service:
        response_data['services'] = [{
            'id': matching_service.id,
            'asset_id': matching_service.asset_id,
            'port': matching_service.port,
            'protocol': matching_service.protocol,
            'product': matching_service.product,
            'version': matching_service.version,
            'tls_fingerprint': matching_service.tls_fingerprint,
            'http_title': matching_service.http_title,
            'http_status': matching_service.http_status,
            'technologies': matching_service.technologies,
            'web_server': matching_service.web_server,
            'has_tls': matching_service.has_tls,
            'tls_version': matching_service.tls_version,
            'http_technologies': matching_service.http_technologies,
            'response_time_ms': matching_service.response_time_ms,
            'content_length': matching_service.content_length,
            'redirect_url': matching_service.redirect_url,
            'enrichment_source': matching_service.enrichment_source,
            'enriched_at': matching_service.enriched_at.isoformat() if matching_service.enriched_at else None,
            'first_seen': matching_service.first_seen.isoformat() if matching_service.first_seen else None,
            'last_seen': matching_service.last_seen.isoformat() if matching_service.last_seen else None,
        }]

    # Pull parent's certificates
    parent_certs = db.query(Certificate).filter(
        Certificate.asset_id == parent.id
    ).all()
    if parent_certs:
        response_data['certificates'] = [
            {
                'id': c.id,
                'subject_cn': c.subject_cn,
                'issuer': c.issuer,
                'serial_number': c.serial_number,
                'not_before': c.not_before.isoformat() if c.not_before else None,
                'not_after': c.not_after.isoformat() if c.not_after else None,
                'is_expired': c.is_expired,
                'days_until_expiry': c.days_until_expiry,
                'san_domains': c.san_domains,
                'is_self_signed': c.is_self_signed,
                'is_wildcard': c.is_wildcard,
                'has_weak_signature': c.has_weak_signature,
            }
            for c in parent_certs
        ]

    # Pull parent's findings
    parent_findings = list(parent.findings)
    if parent_findings:
        response_data['findings'] = [
            {
                'id': f.id,
                'asset_id': f.asset_id,
                'source': f.source,
                'template_id': f.template_id,
                'name': f.name,
                'severity': f.severity.value if hasattr(f.severity, 'value') else str(f.severity),
                'cvss_score': f.cvss_score,
                'cve_id': f.cve_id,
                'status': f.status.value if hasattr(f.status, 'value') else str(f.status),
                'matched_at': f.matched_at,
                'host': f.host,
                'matcher_name': f.matcher_name,
                'fingerprint': f.fingerprint,
                'occurrence_count': f.occurrence_count,
                'first_seen': f.first_seen.isoformat() if f.first_seen else None,
                'last_seen': f.last_seen.isoformat() if f.last_seen else None,
            }
            for f in parent_findings
        ]

    # Pull DNS info from parent
    response_data['dns_info'] = _build_dns_info(parent)

    # Pull tech stack from parent services
    parent_tech: set[str] = set()
    for s in parent.services:
        if s.technologies:
            try:
                techs = json.loads(s.technologies) if isinstance(s.technologies, str) else s.technologies
                if isinstance(techs, list):
                    parent_tech.update(str(t) for t in techs)
            except (ValueError, TypeError):
                pass
        if s.http_technologies and isinstance(s.http_technologies, list):
            parent_tech.update(str(t) for t in s.http_technologies)
        if s.web_server:
            parent_tech.add(s.web_server)
    response_data['tech_stack'] = sorted(parent_tech)

    # Recalculate summary with parent data
    svc_list = response_data.get('services', [])
    find_list = response_data.get('findings', [])
    cert_list = response_data.get('certificates', [])

    parent_open_ports = sorted(set(
        s.port for s in parent.services if s.port is not None
    ))

    parent_severity_counts: dict[str, int] = {}
    parent_open_findings = 0
    for f in parent_findings:
        sev = f.severity.value if hasattr(f.severity, 'value') else str(f.severity)
        parent_severity_counts[sev] = parent_severity_counts.get(sev, 0) + 1
        st = f.status.value if hasattr(f.status, 'value') else str(f.status)
        if st == 'open':
            parent_open_findings += 1

    response_data['summary'] = {
        'total_services': len(parent.services),
        'total_findings': len(parent_findings),
        'total_certificates': len(cert_list),
        'total_endpoints': 0,
        'open_ports': parent_open_ports,
        'has_tls': any(s.has_tls for s in parent.services),
        'has_http': any(
            s.port in (80, 443, 8080, 8443)
            for s in parent.services if s.port is not None
        ),
        'severity_breakdown': parent_severity_counts,
        'open_findings': parent_open_findings,
    }


def _build_dns_info(asset: Asset) -> dict:
    """
    Build DNS / network intelligence section from asset data.

    This function never makes external network calls. All data is derived
    from the asset's raw_metadata JSON field, its services, and simple
    heuristics like cloud provider detection by IP range patterns.
    """
    dns_info: dict = {
        'resolved_ips': [],
        'reverse_dns': None,
        'whois_summary': None,
        'asn_info': None,
        'cloud_provider': None,
    }

    # Parse raw_metadata safely
    raw_meta: dict = {}
    if asset.raw_metadata:
        try:
            raw_meta = json.loads(asset.raw_metadata) if isinstance(asset.raw_metadata, str) else {}
        except (ValueError, TypeError):
            raw_meta = {}

    # Resolved IPs: from raw_metadata or from asset identifier if type is IP
    resolved_ips = raw_meta.get('resolved_ips') or raw_meta.get('a_records') or []
    if not resolved_ips and asset.type and asset.type.value == 'ip':
        resolved_ips = [asset.identifier]
    # Also gather IPs from services with numeric identifiers or metadata
    if not resolved_ips:
        for s in asset.services:
            if s.product and s.product.startswith(('ip:', 'IP:')):
                resolved_ips.append(s.product.split(':', 1)[1].strip())
    dns_info['resolved_ips'] = list(set(resolved_ips))

    # Reverse DNS from raw_metadata
    dns_info['reverse_dns'] = raw_meta.get('rdns') or raw_meta.get('reverse_dns') or raw_meta.get('ptr')

    # WHOIS summary
    whois = raw_meta.get('whois') or raw_meta.get('whois_summary')
    if whois:
        dns_info['whois_summary'] = whois

    # ASN info
    asn = raw_meta.get('asn') or raw_meta.get('asn_info')
    if asn:
        dns_info['asn_info'] = asn

    # Cloud provider detection from raw_metadata or heuristic on IPs
    cloud = raw_meta.get('cloud_provider') or raw_meta.get('cdn')
    if not cloud:
        cloud = _detect_cloud_provider(dns_info['resolved_ips'], asset)
    dns_info['cloud_provider'] = cloud

    return dns_info


# Well-known cloud / CDN IP prefixes (first two octets) for heuristic detection.
# This is intentionally simplified; production systems would use MaxMind or
# cloud provider IP range JSON feeds.
_CLOUD_HINTS: dict[str, list[str]] = {
    'AWS': ['3.', '13.', '15.', '18.', '34.', '35.', '44.', '46.', '50.', '52.', '54.', '99.', '100.'],
    'GCP': ['34.', '35.', '104.', '108.', '142.'],
    'Azure': ['13.', '20.', '23.', '40.', '51.', '52.', '65.', '104.'],
    'Cloudflare': ['104.16.', '104.17.', '104.18.', '104.19.', '104.20.', '104.21.', '104.22.', '104.23.', '104.24.', '104.25.', '172.64.', '172.65.', '172.66.', '172.67.', '162.158.', '141.101.'],
    'Akamai': ['23.', '104.', '184.'],
}


def _detect_cloud_provider(ips: list[str], asset: Asset) -> Optional[str]:
    """
    Heuristic cloud provider detection based on IP prefix matching and
    service HTTP headers (Server, Via, X-Served-By).

    Returns the provider name or None.
    """
    # Check service headers first (most reliable signal)
    for s in asset.services:
        headers = s.http_headers if hasattr(s, 'http_headers') and s.http_headers else {}
        if isinstance(headers, dict):
            header_str = ' '.join(str(v) for v in headers.values()).lower()
            if 'cloudflare' in header_str:
                return 'Cloudflare'
            if 'akamai' in header_str or 'akamaighost' in header_str:
                return 'Akamai'
            if 'amazons3' in header_str or 'cloudfront' in header_str or 'awselb' in header_str:
                return 'AWS'
            if 'gws' in header_str or 'google' in header_str:
                return 'GCP'
            if 'microsoft' in header_str or 'azure' in header_str:
                return 'Azure'

        # Also check web_server field
        if s.web_server:
            ws = s.web_server.lower()
            if 'cloudflare' in ws:
                return 'Cloudflare'
            if 'akamai' in ws:
                return 'Akamai'

    # Fallback: match on IP prefixes (Cloudflare first because its prefixes
    # are more specific and overlap with generic cloud ranges)
    for ip in ips:
        if not ip:
            continue
        # Check Cloudflare first (more specific prefixes)
        for prefix in _CLOUD_HINTS.get('Cloudflare', []):
            if ip.startswith(prefix):
                return 'Cloudflare'
        for prefix in _CLOUD_HINTS.get('Akamai', []):
            if ip.startswith(prefix):
                # Akamai prefixes are broad; only match if not already matched
                pass
        for provider in ('AWS', 'GCP', 'Azure'):
            for prefix in _CLOUD_HINTS.get(provider, []):
                if ip.startswith(prefix):
                    return provider

    return None


@router.post("", response_model=AssetResponse, status_code=status.HTTP_201_CREATED)
def create_asset(
    tenant_id: int,
    asset_data: AssetCreate,
    db: Session = Depends(get_db),
    membership = Depends(verify_tenant_access)
):
    """
    Create new asset

    Validates asset type and identifier format

    Raises:
        - 400: Invalid asset data or duplicate
        - 403: No write access to tenant
    """
    # Verify write permission
    if not membership.has_permission("write"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Write permission required"
        )

    # Check if asset already exists
    existing = db.query(Asset).filter(
        Asset.tenant_id == tenant_id,
        Asset.identifier == asset_data.identifier,
        Asset.type == AssetType(asset_data.type)
    ).first()

    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Asset already exists"
        )

    # Create asset
    asset = Asset(
        tenant_id=tenant_id,
        type=AssetType(asset_data.type),
        identifier=asset_data.identifier,
        priority=asset_data.priority or "normal"
    )

    db.add(asset)
    db.commit()
    db.refresh(asset)

    logger.info(f"Created asset {asset.identifier} for tenant {tenant_id}")

    return AssetResponse.model_validate(asset)


@router.patch("/{asset_id}", response_model=AssetResponse)
def update_asset(
    tenant_id: int,
    asset_id: int,
    updates: AssetUpdate,
    db: Session = Depends(get_db),
    membership = Depends(verify_tenant_access)
):
    """
    Update asset

    Allows updating priority and active status

    Raises:
        - 404: Asset not found
        - 403: No write access
    """
    # Verify write permission
    if not membership.has_permission("write"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Write permission required"
        )

    asset = db.query(Asset).filter(
        Asset.id == asset_id,
        Asset.tenant_id == tenant_id
    ).first()

    if not asset:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Asset not found"
        )

    # Apply updates
    if updates.priority is not None:
        asset.priority = updates.priority
        asset.priority_updated_at = datetime.now(timezone.utc)
        asset.priority_auto_calculated = False

    if updates.is_active is not None:
        asset.is_active = updates.is_active

    db.commit()
    db.refresh(asset)

    logger.info(f"Updated asset {asset.identifier}")

    return AssetResponse.model_validate(asset)


@router.delete("/{asset_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_asset(
    tenant_id: int,
    asset_id: int,
    db: Session = Depends(get_db),
    membership = Depends(verify_tenant_access)
):
    """
    Delete asset (soft delete - mark as inactive)

    Raises:
        - 404: Asset not found
        - 403: No write access
    """
    # Verify write permission
    if not membership.has_permission("write"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Write permission required"
        )

    asset = db.query(Asset).filter(
        Asset.id == asset_id,
        Asset.tenant_id == tenant_id
    ).first()

    if not asset:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Asset not found"
        )

    # Soft delete
    asset.is_active = False
    db.commit()

    logger.info(f"Deleted asset {asset.identifier}")


@router.get("/tree", response_model=List[AssetTreeNode])
def get_asset_tree(
    tenant_id: int,
    db: Session = Depends(get_db),
    membership = Depends(verify_tenant_access)
):
    """
    Get hierarchical asset tree

    Returns:
        Tree structure: domains -> subdomains -> IPs/URLs

    Useful for visualization and navigation
    """
    # Get all domains
    domains = db.query(Asset).filter(
        Asset.tenant_id == tenant_id,
        Asset.type == AssetType.DOMAIN,
        Asset.is_active == True
    ).all()

    tree = []

    for domain in domains:
        domain_node = _build_asset_node(domain, db)

        # Get subdomains
        subdomains = db.query(Asset).filter(
            Asset.tenant_id == tenant_id,
            Asset.type == AssetType.SUBDOMAIN,
            Asset.identifier.like(f"%.{domain.identifier}"),
            Asset.is_active == True
        ).all()

        domain_node['children'] = [
            _build_asset_node(subdomain, db)
            for subdomain in subdomains
        ]

        tree.append(domain_node)

    return tree


@router.post("/bulk", response_model=BulkOperationResult)
def bulk_create_assets(
    tenant_id: int,
    bulk_data: BulkAssetCreate,
    db: Session = Depends(get_db),
    membership = Depends(verify_tenant_access)
):
    """
    Bulk create assets

    Creates multiple assets in one request
    Returns summary of successes and failures

    Raises:
        - 403: No write access
    """
    # Verify write permission
    if not membership.has_permission("write"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Write permission required"
        )

    success_count = 0
    failure_count = 0
    errors = []

    for asset_data in bulk_data.assets:
        try:
            # Check if exists
            existing = db.query(Asset).filter(
                Asset.tenant_id == tenant_id,
                Asset.identifier == asset_data.identifier,
                Asset.type == AssetType(asset_data.type)
            ).first()

            if existing:
                errors.append(f"Asset '{asset_data.identifier}' already exists")
                failure_count += 1
                continue

            # Create asset
            asset = Asset(
                tenant_id=tenant_id,
                type=AssetType(asset_data.type),
                identifier=asset_data.identifier,
                priority=asset_data.priority or "normal"
            )

            db.add(asset)
            success_count += 1

        except Exception as e:
            errors.append(f"Failed to create '{asset_data.identifier}': {str(e)}")
            failure_count += 1

    db.commit()

    logger.info(f"Bulk created {success_count} assets for tenant {tenant_id}")

    return BulkOperationResult(
        success_count=success_count,
        failure_count=failure_count,
        errors=errors
    )


# Seeds endpoints
@router.get("/seeds", response_model=List[SeedResponse])
def list_seeds(
    tenant_id: int,
    db: Session = Depends(get_db),
    membership = Depends(verify_tenant_access)
):
    """
    List all seeds for tenant

    Seeds are root domains, ASNs, IP ranges used for discovery

    Returns:
        List of seed objects
    """
    seeds = db.query(Seed).filter(
        Seed.tenant_id == tenant_id
    ).order_by(Seed.created_at.desc()).all()

    return [SeedResponse.model_validate(s) for s in seeds]


@router.post("/seeds", response_model=SeedResponse, status_code=status.HTTP_201_CREATED)
def create_seed(
    tenant_id: int,
    seed_data: SeedCreate,
    db: Session = Depends(get_db),
    membership = Depends(verify_tenant_access)
):
    """
    Create new seed

    Seeds trigger discovery pipeline

    Raises:
        - 403: No write access
        - 400: Invalid seed data
    """
    # Verify write permission
    if not membership.has_permission("write"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Write permission required"
        )

    # Create seed
    seed = Seed(
        tenant_id=tenant_id,
        type=seed_data.type,
        value=seed_data.value,
        enabled=seed_data.enabled
    )

    db.add(seed)
    db.commit()
    db.refresh(seed)

    logger.info(f"Created seed {seed.value} for tenant {tenant_id}")

    return SeedResponse.model_validate(seed)


@router.post("/{asset_id}/rescan", status_code=status.HTTP_202_ACCEPTED)
def rescan_asset(
    tenant_id: int,
    asset_id: int,
    db: Session = Depends(get_db),
    membership=Depends(verify_tenant_access),
):
    """
    Trigger re-enrichment scan for a single asset.

    Queues enrichment tasks (HTTPx, Naabu, TLSx) for the asset.
    """
    if not membership.has_permission("write"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Write permission required",
        )

    asset = db.query(Asset).filter(
        Asset.id == asset_id,
        Asset.tenant_id == tenant_id,
    ).first()

    if not asset:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Asset not found",
        )

    # Queue enrichment tasks
    task_ids = []
    try:
        from app.tasks.enrichment import run_httpx, run_naabu, run_tlsx
        from app.tasks.cert_harvest import harvest_certificates

        httpx_task = run_httpx.apply_async(
            kwargs={'tenant_id': tenant_id, 'asset_ids': [asset_id]}
        )
        task_ids.append(httpx_task.id)

        naabu_task = run_naabu.apply_async(
            kwargs={'tenant_id': tenant_id, 'asset_ids': [asset_id]}
        )
        task_ids.append(naabu_task.id)

    except Exception as e:
        logger.warning(f"Failed to queue enrichment for asset {asset_id}: {e}")

    # Update enrichment status
    asset.enrichment_status = "pending"
    db.commit()

    logger.info(f"Triggered rescan for asset {asset_id} (tenant {tenant_id})")

    return {
        'status': 'queued',
        'asset_id': asset_id,
        'task_ids': task_ids,
    }


@router.get("/{asset_id}/screenshots")
def get_asset_screenshots(
    tenant_id: int,
    asset_id: int,
    include_urls: bool = Query(False, description="Generate presigned MinIO URLs"),
    db: Session = Depends(get_db),
    membership=Depends(verify_tenant_access),
):
    """
    Get screenshot metadata for an asset.

    Returns the list of screenshots captured during Visual Recon (Phase 7).
    """
    asset = db.query(Asset).filter(
        Asset.id == asset_id,
        Asset.tenant_id == tenant_id,
    ).first()

    if not asset:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Asset not found",
        )

    try:
        meta = json.loads(asset.raw_metadata) if asset.raw_metadata else {}
    except (json.JSONDecodeError, TypeError):
        meta = {}

    screenshots = meta.get('screenshots', [])

    if include_urls and screenshots:
        from app.tasks.visual_recon import get_screenshot_url

        for entry in screenshots:
            if entry.get('full'):
                entry['full_url'] = get_screenshot_url(tenant_id, entry['full'])
            if entry.get('thumb'):
                entry['thumb_url'] = get_screenshot_url(tenant_id, entry['thumb'])

    return {
        'asset_id': asset_id,
        'total': len(screenshots),
        'screenshots': screenshots,
    }


@router.post("/{asset_id}/screenshots/capture", status_code=status.HTTP_202_ACCEPTED)
def trigger_asset_screenshot(
    tenant_id: int,
    asset_id: int,
    db: Session = Depends(get_db),
    membership=Depends(verify_tenant_access),
):
    """
    Trigger on-demand screenshot capture for a single asset.
    """
    if not membership.has_permission("write"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Write permission required",
        )

    asset = db.query(Asset).filter(
        Asset.id == asset_id,
        Asset.tenant_id == tenant_id,
    ).first()

    if not asset:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Asset not found",
        )

    from app.tasks.visual_recon import run_visual_recon

    task = run_visual_recon.apply_async(
        kwargs={
            'tenant_id': tenant_id,
            'asset_ids': [asset_id],
        }
    )

    logger.info(
        f"Triggered visual recon for asset {asset_id} (tenant {tenant_id}), "
        f"task_id={task.id}"
    )

    return {
        'task_id': task.id,
        'status': 'queued',
        'asset_id': asset_id,
    }


def _build_asset_node(asset: Asset, db: Session) -> dict:
    """Build asset tree node with counts"""
    return {
        "id": asset.id,
        "identifier": asset.identifier,
        "type": asset.type.value,
        "risk_score": asset.risk_score,
        "is_active": asset.is_active,
        "service_count": len(asset.services),
        "finding_count": len(asset.findings),
        "children": []
    }
