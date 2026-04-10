"""Enumeration phase implementations (Phases 2, 3, 4, 4b, 5, 5b, 5c).

Phase 2:  DNS Permutation & Bruteforce (alterx + puredns, Tier 2+)
Phase 3:  DNS Resolution + SPF/MX Pivot
Phase 4:  HTTP Probing (httpx)
Phase 4b: TLS Certificate Collection (tlsx)
Phase 5:  Port Scanning (naabu)
Phase 5b: CDN/WAF Detection (cdncheck, all tiers)
Phase 5c: Service Fingerprinting (fingerprintx, Tier 2+)
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from app.models.risk import Relationship
from app.tasks.pipeline_helpers import (
    _extract_parent_domain,
    _get_seed_domains,
    _is_hostname_in_scope,
    _upsert_relationship,
)

logger = logging.getLogger(__name__)


def _phase_2_dns_bruteforce(tenant_id, project_id, scan_run_id, db, tenant_logger, scan_tier=2):
    """Phase 2: DNS permutation & bruteforce with alterx + puredns.

    1. Reads known subdomains/domains from the DB
    2. Generates permutation candidates via alterx
    3. Validates candidates with puredns (wildcard filtering)
    4. Upserts validated subdomains as new assets
    """
    from app.tasks.dns_bruteforce import run_alterx, run_puredns
    from app.models.database import Asset, AssetType

    # Gather known subdomains
    subdomains = (
        db.query(Asset)
        .filter(
            Asset.tenant_id == tenant_id,
            Asset.type.in_([AssetType.DOMAIN, AssetType.SUBDOMAIN]),
            Asset.is_active == True,
        )
        .all()
    )

    if not subdomains:
        return {"assets_discovered": 0, "candidates_generated": 0}

    subdomain_list = [a.identifier for a in subdomains]

    # DNS rate limits per tier (queries/second -- distributed across resolvers)
    tier_rate = {2: 200, 3: 300}
    rate = tier_rate.get(scan_tier, 200)

    # Generate permutations
    candidates = run_alterx(subdomain_list, tenant_id)
    tenant_logger.info("alterx generated %d permutation candidates", len(candidates))

    # Validate via puredns
    validated = run_puredns(candidates, tenant_id, rate=rate)
    tenant_logger.info("puredns validated %d / %d candidates", len(validated), len(candidates))

    # Filter validated hostnames to only in-scope domains
    seed_domains = _get_seed_domains(tenant_id, project_id, db)
    in_scope = [h for h in validated if _is_hostname_in_scope(h.strip().lower(), seed_domains)]
    if len(in_scope) < len(validated):
        tenant_logger.info(
            f"Scope filter: {len(in_scope)} in-scope, {len(validated) - len(in_scope)} out-of-scope filtered"
        )
    validated = in_scope

    # Upsert validated subdomains
    assets_created = 0
    relationships_created = 0
    for hostname in validated:
        hostname = hostname.strip().lower()
        if not hostname:
            continue

        existing = (
            db.query(Asset)
            .filter(
                Asset.tenant_id == tenant_id,
                Asset.identifier == hostname,
                Asset.type == AssetType.SUBDOMAIN,
            )
            .first()
        )

        if not existing:
            asset = Asset(
                tenant_id=tenant_id,
                type=AssetType.SUBDOMAIN,
                identifier=hostname,
                is_active=True,
            )
            db.add(asset)
            db.flush()
            assets_created += 1

            # Create parent_domain relationship
            parent_domain = _extract_parent_domain(hostname)
            if parent_domain:
                parent_asset = (
                    db.query(Asset)
                    .filter(
                        Asset.tenant_id == tenant_id,
                        Asset.identifier == parent_domain,
                        Asset.type.in_([AssetType.DOMAIN, AssetType.SUBDOMAIN]),
                    )
                    .first()
                )
                if parent_asset:
                    if _upsert_relationship(
                        db,
                        tenant_id,
                        source_asset_id=asset.id,
                        target_asset_id=parent_asset.id,
                        rel_type="parent_domain",
                        metadata={"source": "dns_bruteforce"},
                    ):
                        relationships_created += 1
        else:
            existing.last_seen = datetime.now(timezone.utc)
            existing.is_active = True

    db.commit()

    return {
        "assets_discovered": assets_created,
        "candidates_generated": len(candidates),
        "candidates_validated": len(validated),
        "relationships_created": relationships_created,
    }


def _phase_3_dns_resolution(tenant_id, project_id, scan_run_id, db, tenant_logger):
    """Phase 3: DNS resolution with DNSX.

    After resolving DNS records this phase creates relationship edges:
    - resolves_to:   subdomain/domain -> IP  (A/AAAA records)
    - cname_to:      subdomain/domain -> CNAME target
    - parent_domain: subdomain -> parent domain hierarchy
    """
    from app.tasks.discovery import run_dnsx
    from app.models.database import Asset, AssetType

    # Get all subdomains to resolve
    subdomains = (
        db.query(Asset)
        .filter(
            Asset.tenant_id == tenant_id,
            Asset.type.in_([AssetType.DOMAIN, AssetType.SUBDOMAIN]),
            Asset.is_active == True,
        )
        .all()
    )

    if not subdomains:
        return {"records_resolved": 0, "relationships_created": 0}

    subdomain_list = [a.identifier for a in subdomains]

    # run_dnsx expects (subfinder_result: dict, tenant_id: int)
    subfinder_result = {"subdomains": subdomain_list}
    result = run_dnsx(subfinder_result, tenant_id)

    resolved = result.get("resolved", []) if isinstance(result, dict) else []

    # Collect unique IPs from all resolved records
    unique_ips = set()
    for record in resolved:
        for ip in record.get("a", []):
            unique_ips.add(ip)
        for ip in record.get("aaaa", []):
            unique_ips.add(ip)

    # Collect unique CNAME targets (they may be new subdomains)
    unique_cnames = set()
    for record in resolved:
        for cname in record.get("cname", []):
            cname = cname.strip().rstrip(".").lower()
            if cname:
                unique_cnames.add(cname)

    # Create IP assets (deduped, skip existing)
    ips_created = 0
    for ip in unique_ips:
        existing = db.query(Asset.id).filter(Asset.tenant_id == tenant_id, Asset.identifier == ip).first()
        if not existing:
            db.add(
                Asset(
                    tenant_id=tenant_id,
                    type=AssetType.IP,
                    identifier=ip,
                    is_active=True,
                )
            )
            ips_created += 1
    if ips_created:
        db.commit()

    # Ensure CNAME targets exist as assets (subdomains), but only if in scope.
    # CNAME chains often point to CDN/cloud infrastructure (b-cdn.net,
    # azureedge.net, etc.) that we must NOT scan.
    seed_domains = _get_seed_domains(tenant_id, project_id, db)
    cnames_created = 0
    cnames_skipped = 0
    for cname in unique_cnames:
        if not _is_hostname_in_scope(cname, seed_domains):
            cnames_skipped += 1
            continue
        existing = (
            db.query(Asset.id)
            .filter(
                Asset.tenant_id == tenant_id,
                Asset.identifier == cname,
            )
            .first()
        )
        if not existing:
            db.add(
                Asset(
                    tenant_id=tenant_id,
                    type=AssetType.SUBDOMAIN,
                    identifier=cname,
                    is_active=True,
                )
            )
            cnames_created += 1
    if cnames_created:
        db.commit()
    if cnames_skipped:
        tenant_logger.info(f"Skipped {cnames_skipped} out-of-scope CNAME targets (CDN/cloud infrastructure)")

    # ------------------------------------------------------------------
    # Build asset lookup for relationship creation
    # ------------------------------------------------------------------
    all_assets = (
        db.query(Asset)
        .filter(
            Asset.tenant_id == tenant_id,
            Asset.is_active == True,
        )
        .all()
    )
    asset_by_identifier = {a.identifier.lower(): a for a in all_assets}

    relationships_created = 0

    for record in resolved:
        host = record.get("host", "").lower()
        source_asset = asset_by_identifier.get(host)
        if not source_asset:
            continue

        # --- resolves_to: subdomain/domain -> IP (A records) ---
        for ip in record.get("a", []):
            target_asset = asset_by_identifier.get(ip)
            if target_asset:
                if _upsert_relationship(
                    db,
                    tenant_id,
                    source_asset_id=source_asset.id,
                    target_asset_id=target_asset.id,
                    rel_type="resolves_to",
                    metadata={"record_type": "A", "value": ip},
                ):
                    relationships_created += 1

        # --- resolves_to: subdomain/domain -> IP (AAAA records) ---
        for ip in record.get("aaaa", []):
            target_asset = asset_by_identifier.get(ip)
            if target_asset:
                if _upsert_relationship(
                    db,
                    tenant_id,
                    source_asset_id=source_asset.id,
                    target_asset_id=target_asset.id,
                    rel_type="resolves_to",
                    metadata={"record_type": "AAAA", "value": ip},
                ):
                    relationships_created += 1

        # --- cname_to: subdomain/domain -> CNAME target ---
        for cname in record.get("cname", []):
            cname_clean = cname.strip().rstrip(".").lower()
            target_asset = asset_by_identifier.get(cname_clean)
            if target_asset:
                if _upsert_relationship(
                    db,
                    tenant_id,
                    source_asset_id=source_asset.id,
                    target_asset_id=target_asset.id,
                    rel_type="cname_to",
                    metadata={"cname": cname_clean},
                ):
                    relationships_created += 1

        # --- parent_domain: subdomain -> parent domain ---
        parent_domain = _extract_parent_domain(host)
        if parent_domain:
            parent_asset = asset_by_identifier.get(parent_domain)
            if parent_asset:
                if _upsert_relationship(
                    db,
                    tenant_id,
                    source_asset_id=source_asset.id,
                    target_asset_id=parent_asset.id,
                    rel_type="parent_domain",
                    metadata={"source": "dns_resolution"},
                ):
                    relationships_created += 1

    if relationships_created:
        db.commit()

    tenant_logger.info(
        f"Phase 3 relationships: {relationships_created} edges created (resolves_to, cname_to, parent_domain)"
    )

    return {
        "records_resolved": len(resolved),
        "ips_created": ips_created,
        "cnames_created": cnames_created,
        "hosts_resolved": len(subdomain_list),
        "relationships_created": relationships_created,
    }


def _phase_4_http_probing(tenant_id, project_id, scan_run_id, db, tenant_logger):
    """Phase 4: HTTP probing with HTTPx.

    Probes all active domain, subdomain, and IP assets for HTTP/HTTPS
    services. Results are stored as Service records linked to assets.

    After probing, creates ``hosts`` relationship edges from each asset
    to every Service-type asset discovered on it (one edge per distinct
    port).
    """
    from app.tasks.enrichment import run_httpx
    from app.models.database import Asset, AssetType, Service

    assets = (
        db.query(Asset)
        .filter(
            Asset.tenant_id == tenant_id,
            Asset.type.in_([AssetType.DOMAIN, AssetType.SUBDOMAIN, AssetType.IP]),
            Asset.is_active == True,
        )
        .all()
    )

    if not assets:
        tenant_logger.warning("No active assets for HTTP probing")
        return {"services_discovered": 0, "hosts_probed": 0, "relationships_created": 0}

    asset_ids = [a.id for a in assets]
    tenant_logger.info(f"HTTPx: probing {len(asset_ids)} assets")
    result = run_httpx(tenant_id, asset_ids)

    services_created = result.get("services_created", 0) if isinstance(result, dict) else 0
    services_updated = result.get("services_updated", 0) if isinstance(result, dict) else 0

    # ------------------------------------------------------------------
    # Create 'hosts' edges: asset -> service asset
    #
    # The Service table links services to assets, but the Relationship
    # table needs asset-to-asset edges. We model each (asset, port)
    # pair as a logical "hosts" edge from the asset to itself. If
    # dedicated SERVICE-type assets existed we would link to those;
    # for now we create an asset of type SERVICE for each unique
    # (identifier:port) so the graph can visualize them.
    # ------------------------------------------------------------------
    relationships_created = 0

    # Refresh the session to pick up services written by run_httpx
    db.expire_all()

    for asset in assets:
        services = (
            db.query(Service)
            .filter(
                Service.asset_id == asset.id,
            )
            .all()
        )

        for svc in services:
            if svc.port is None:
                continue

            # Upsert a SERVICE-type asset for the (host, port) combo
            svc_identifier = f"{asset.identifier}:{svc.port}"
            svc_asset = (
                db.query(Asset)
                .filter(
                    Asset.tenant_id == tenant_id,
                    Asset.identifier == svc_identifier,
                    Asset.type == AssetType.SERVICE,
                )
                .first()
            )

            if not svc_asset:
                svc_asset = Asset(
                    tenant_id=tenant_id,
                    type=AssetType.SERVICE,
                    identifier=svc_identifier,
                    is_active=True,
                )
                db.add(svc_asset)
                db.flush()  # Get the id for the relationship

            # Create the hosts relationship: domain/IP -> service
            if _upsert_relationship(
                db,
                tenant_id,
                source_asset_id=asset.id,
                target_asset_id=svc_asset.id,
                rel_type="hosts",
                metadata={
                    "port": svc.port,
                    "protocol": svc.protocol,
                    "http_status": svc.http_status,
                    "web_server": svc.web_server,
                },
            ):
                relationships_created += 1

    if relationships_created:
        db.commit()

    tenant_logger.info(f"Phase 4 relationships: {relationships_created} 'hosts' edges created")

    return {
        "services_discovered": services_created + services_updated,
        "services_created": services_created,
        "services_updated": services_updated,
        "hosts_probed": len(asset_ids),
        "relationships_created": relationships_created,
    }


def _phase_4b_tls_collection(tenant_id, project_id, scan_run_id, db, tenant_logger):
    """Phase 4b: TLS certificate collection with tlsx.

    Runs tlsx against all active DOMAIN and SUBDOMAIN assets to collect
    TLS/SSL certificate metadata (validity, SANs, cipher suites, TLS
    versions, certificate chain). Results are stored as Certificate
    records and linked Service records via the enrichment task.
    """
    from app.tasks.enrichment import run_tlsx
    from app.models.database import Asset, AssetType

    assets = (
        db.query(Asset)
        .filter(
            Asset.tenant_id == tenant_id,
            Asset.type.in_([AssetType.DOMAIN, AssetType.SUBDOMAIN]),
            Asset.is_active == True,
        )
        .all()
    )

    if not assets:
        tenant_logger.warning("No active domain/subdomain assets for TLS collection")
        return {"certificates_collected": 0, "hosts_analyzed": 0}

    asset_ids = [a.id for a in assets]
    tenant_logger.info(f"TLSx: collecting certificates from {len(asset_ids)} assets")
    result = run_tlsx(tenant_id, asset_ids)

    certificates_collected = result.get("certificates_discovered", 0) if isinstance(result, dict) else 0
    certificates_created = result.get("certificates_created", 0) if isinstance(result, dict) else 0
    certificates_updated = result.get("certificates_updated", 0) if isinstance(result, dict) else 0
    hosts_analyzed = result.get("hosts_analyzed", 0) if isinstance(result, dict) else 0

    return {
        "certificates_collected": certificates_collected,
        "certificates_created": certificates_created,
        "certificates_updated": certificates_updated,
        "hosts_analyzed": hosts_analyzed,
    }


def _phase_5_port_scanning(tenant_id, project_id, scan_run_id, db, tenant_logger, scan_tier=1):
    """Phase 5: Port scanning with Naabu. Ports/rate/policy depend on scan tier.

    The scan_tier controls port range, rate, timeout AND the sensitive-port
    blocklist:

    - Tier 1 (Safe):       top-100 ports, full_scan=False, full blocklist
                           (SSH, SMB, RDP, MySQL, Postgres are skipped —
                           safe defaults for unauthorized discovery).
    - Tier 2 (Moderate):   top-1000 ports, full_scan=False, reduced blocklist
                           (only SSH 22 + RDP 3389 skipped for legal safety;
                           DB/SMB ports allowed so EASM can actually find
                           exposed databases, which is the main value prop).
    - Tier 3 (Aggressive): all 65535 ports, full_scan=True, NO blocklist
                           (operator has explicit authorization for the
                           target: scan everything, no exceptions).
    """
    from app.tasks.enrichment import run_naabu
    from app.models.database import Asset, AssetType

    # CPU/RAM-aware port configuration
    from app.services.resource_scaler import get_scan_params

    params = get_scan_params(scan_tier)
    tier_ports = {1: "100", 2: "1000", 3: "full"}
    tier_full = {1: False, 2: False, 3: True}
    # Tier-aware sensitive-port blocklist.
    #   T1: full blocklist (SSH, SMB, RDP, MySQL, Postgres)
    #   T2: reduced — keep only login-oriented services (legal risk) blocked
    #   T3: empty  — operator has authorization, scan everything
    tier_blocklist = {
        1: [22, 445, 3389, 3306, 5432],
        2: [22, 3389],
        3: [],
    }
    blocked_ports = tier_blocklist.get(scan_tier, [22, 445, 3389, 3306, 5432])
    config = {
        "top_ports": tier_ports.get(scan_tier, "1000"),
        "rate": params.naabu_rate,
        "full_scan": tier_full.get(scan_tier, False),
        "timeout": params.naabu_timeout,
        "blocked_ports": blocked_ports,
    }

    # Apply adaptive throttle if active
    from app.services.adaptive_throttle import get_throttle

    throttle = get_throttle(tenant_id, scan_run_id)
    effective_rate = throttle.get_rate(config["rate"])

    # Get domains/subdomains -- naabu resolves hostnames to IPs internally,
    # so scanning both a subdomain AND its resolved IP is redundant.
    # Only include standalone IPs (not the target of any resolves_to relationship).
    hostname_assets = (
        db.query(Asset)
        .filter(
            Asset.tenant_id == tenant_id,
            Asset.type.in_([AssetType.DOMAIN, AssetType.SUBDOMAIN]),
            Asset.is_active == True,
        )
        .all()
    )

    # Find IPs that are NOT covered by any hostname (standalone IPs from
    # seeds/uncover/ASN). Use a single LEFT JOIN ... IS NULL query so the
    # "covered" check and the Asset filter read the same transactional
    # snapshot — the previous two-query approach (set of IDs + NOT IN)
    # suffered from a race with parallel phases (3/4) that were still
    # writing resolves_to relationships, causing covered IPs to slip
    # through as "standalone" and get scanned twice by naabu.
    from sqlalchemy.orm import aliased
    from sqlalchemy import and_

    _R = aliased(Relationship)
    standalone_ips = (
        db.query(Asset)
        .outerjoin(
            _R,
            and_(
                _R.target_asset_id == Asset.id,
                _R.tenant_id == tenant_id,
                _R.rel_type == "resolves_to",
            ),
        )
        .filter(
            Asset.tenant_id == tenant_id,
            Asset.type == AssetType.IP,
            Asset.is_active == True,
            _R.id.is_(None),
        )
        .all()
    )

    # For logging: count covered IPs (total active IPs minus standalone).
    # Cheap indexed COUNT(*) — runs in the same session as the join above.
    total_ip_count = (
        db.query(Asset)
        .filter(
            Asset.tenant_id == tenant_id,
            Asset.type == AssetType.IP,
            Asset.is_active == True,
        )
        .count()
    )
    covered_ip_count = total_ip_count - len(standalone_ips)

    assets = hostname_assets + standalone_ips

    if not assets:
        return {"ports_discovered": 0, "scan_tier": scan_tier}

    # Dedup hostnames that resolve to the same IP — scanning the same
    # server 6 times via different hostnames wastes time and duplicates findings.
    from app.services.ip_dedup import dedup_by_resolved_ip

    assets, ip_dedup_skipped = dedup_by_resolved_ip(assets, tenant_id, db)

    asset_ids = [a.id for a in assets]
    blocked_str = ",".join(map(str, config["blocked_ports"])) if config["blocked_ports"] else "none"
    tenant_logger.info(
        f"Naabu: top_ports={config['top_ports']}, rate={effective_rate} pkt/s "
        f"{'(throttled) ' if throttle.is_throttled else ''}"
        f"full_scan={config['full_scan']} (tier {scan_tier}), "
        f"blocked_ports={blocked_str}, "
        f"targets={len(asset_ids)} ({len(hostname_assets)} hostnames, "
        f"{covered_ip_count} covered IPs skipped, {ip_dedup_skipped} same-IP hostnames deduped)"
    )
    result = run_naabu(
        tenant_id,
        asset_ids,
        full_scan=config["full_scan"],
        rate=effective_rate,
        timeout=config.get("timeout"),
        blocked_ports=config["blocked_ports"],
    )

    return {
        "ports_discovered": result.get("ports_discovered", 0) if isinstance(result, dict) else 0,
        "services_created": result.get("services_created", 0) if isinstance(result, dict) else 0,
        "hosts_scanned": result.get("hosts_scanned", 0) if isinstance(result, dict) else 0,
        "scan_tier": scan_tier,
        "top_ports": config["top_ports"],
        "rate": config["rate"],
    }


def _phase_5b_cdn_detection(tenant_id, project_id, scan_run_id, db, tenant_logger):
    """Phase 5b: CDN/WAF detection with cdncheck.

    Runs on all tiers (read-only DNS lookup). Updates cdn_name, waf_name,
    and cloud_provider columns on the Asset model.
    """
    from app.tasks.service_fingerprint import run_cdncheck
    from app.models.database import Asset, AssetType

    assets = (
        db.query(Asset)
        .filter(
            Asset.tenant_id == tenant_id,
            Asset.type.in_([AssetType.DOMAIN, AssetType.SUBDOMAIN, AssetType.IP]),
            Asset.is_active == True,
        )
        .all()
    )

    if not assets:
        return {"hosts_checked": 0, "cdn_detected": 0, "waf_detected": 0}

    hosts = [a.identifier for a in assets]
    results = run_cdncheck(hosts, tenant_id)

    cdn_count = 0
    waf_count = 0
    updated = 0

    for asset in assets:
        info = results.get(asset.identifier)
        if not info:
            continue

        changed = False
        if info.get("cdn") and info.get("cdn_name"):
            asset.cdn_name = info["cdn_name"]
            cdn_count += 1
            changed = True
        if info.get("waf") and info.get("waf_name"):
            asset.waf_name = info["waf_name"]
            waf_count += 1
            changed = True
        if info.get("cloud"):
            asset.cloud_provider = info["cloud"]
            changed = True

        if changed:
            updated += 1

    db.commit()

    return {
        "hosts_checked": len(results),
        "cdn_detected": cdn_count,
        "waf_detected": waf_count,
        "assets_updated": updated,
    }


def _phase_5c_service_fingerprint(tenant_id, project_id, scan_run_id, db, tenant_logger, scan_tier=1):
    """Phase 5c: Service fingerprinting with fingerprintx.

    Runs on open ports discovered by naabu (Phase 5). Updates service
    product/version with more accurate protocol-level identification.

    IP dedup: when multiple hostnames resolve to the same IP, fingerprintx
    only probes one representative hostname per unique (IP, port) pair.
    Results are propagated to all sibling services sharing that IP+port.
    """
    from app.tasks.service_fingerprint import run_fingerprintx
    from app.models.database import Asset, AssetType, Service
    from app.services.resource_scaler import get_scan_params
    from app.config import settings

    # Apply CPU-aware timeout (default 300s is too long for small scans)
    params = get_scan_params(scan_tier)
    settings.fingerprintx_timeout = params.fingerprintx_timeout
    tenant_logger.info(f"fingerprintx timeout set to {params.fingerprintx_timeout}s (tier {scan_tier})")

    # Build host:port targets from services table
    services = (
        db.query(Service)
        .join(Asset)
        .filter(
            Asset.tenant_id == tenant_id,
            Asset.is_active == True,
            Service.port.isnot(None),
        )
        .all()
    )

    if not services:
        return {"services_fingerprinted": 0, "protocols_identified": 0}

    # ---------------------------------------------------------------
    # IP dedup: build a map of hostname -> resolved IPs so we can
    # skip fingerprinting the same (IP, port) pair multiple times.
    # ---------------------------------------------------------------
    # Collect all assets referenced by these services
    asset_ids_in_scope = list({svc.asset_id for svc in services})
    assets_in_scope = db.query(Asset).filter(Asset.id.in_(asset_ids_in_scope)).all()
    asset_by_id = {a.id: a for a in assets_in_scope}

    # Build hostname -> primary resolved IP map via relationships
    hostname_asset_ids = [a.id for a in assets_in_scope if a.type in (AssetType.DOMAIN, AssetType.SUBDOMAIN)]

    asset_to_primary_ip: dict[int, str] = {}
    if hostname_asset_ids:
        rels = (
            db.query(Relationship)
            .filter(
                Relationship.tenant_id == tenant_id,
                Relationship.rel_type == "resolves_to",
                Relationship.source_asset_id.in_(hostname_asset_ids),
            )
            .all()
        )
        # Batch-load target IP assets to avoid N+1 queries
        target_ip_ids = list({r.target_asset_id for r in rels})
        if target_ip_ids:
            ip_assets = db.query(Asset).filter(Asset.id.in_(target_ip_ids)).all()
            ip_by_id = {a.id: a.identifier for a in ip_assets}
            for rel in rels:
                ip_str = ip_by_id.get(rel.target_asset_id)
                if ip_str:
                    # Keep only first (deterministic) IP per hostname
                    if rel.source_asset_id not in asset_to_primary_ip:
                        asset_to_primary_ip[rel.source_asset_id] = ip_str

    # Deduplicate targets: for each unique (resolved_ip, port), keep only
    # one representative target.  Map skipped services to the representative
    # so we can propagate results.
    seen_ip_port: dict[tuple[str, int], str] = {}  # (ip, port) -> representative target key
    targets = []
    service_map: dict[str, Service] = {}  # target_key -> service
    sibling_services: dict[str, list[Service]] = {}  # representative target -> list of sibling services
    ip_dedup_skipped = 0

    for svc in services:
        asset = asset_by_id.get(svc.asset_id)
        if not asset or not svc.port:
            continue

        target = f"{asset.identifier}:{svc.port}"
        resolved_ip = asset_to_primary_ip.get(asset.id)

        if resolved_ip:
            dedup_key = (resolved_ip, svc.port)
            if dedup_key in seen_ip_port:
                # This (IP, port) is already being fingerprinted via another hostname.
                # Record as sibling for result propagation.
                representative = seen_ip_port[dedup_key]
                sibling_services.setdefault(representative, []).append(svc)
                ip_dedup_skipped += 1
                continue
            seen_ip_port[dedup_key] = target

        targets.append(target)
        service_map[target] = svc

    if not targets:
        return {"services_fingerprinted": 0, "protocols_identified": 0}

    tenant_logger.info(
        f"fingerprintx: {len(targets)} targets to scan "
        f"({ip_dedup_skipped} same-IP duplicates skipped, "
        f"{len(sibling_services)} groups will inherit results)"
    )

    results = run_fingerprintx(targets, tenant_id)

    protocols_identified = 0
    services_updated = 0

    def _apply_fingerprint(svc: Service, entry: dict) -> tuple[int, int]:
        """Apply fingerprint data to a service. Returns (updated, protocols)."""
        _updated = 0
        _protocols = 0
        if entry.get("service"):
            svc.product = entry["service"]
            _updated = 1
        if entry.get("version"):
            svc.version = entry["version"]
        if entry.get("protocol"):
            svc.protocol = entry["protocol"]
            _protocols = 1
        if entry.get("tls"):
            svc.has_tls = True
        svc.enrichment_source = "fingerprintx"
        return _updated, _protocols

    for entry in results:
        host = entry.get("host", "")
        port = entry.get("port", 0)
        target_key = f"{host}:{port}"

        svc = service_map.get(target_key)
        if not svc:
            continue

        # Apply to the representative service
        u, p = _apply_fingerprint(svc, entry)
        services_updated += u
        protocols_identified += p

        # Propagate to all sibling services sharing the same (IP, port)
        for sibling_svc in sibling_services.get(target_key, []):
            su, sp = _apply_fingerprint(sibling_svc, entry)
            services_updated += su
            protocols_identified += sp

    db.commit()

    return {
        "services_fingerprinted": services_updated,
        "protocols_identified": protocols_identified,
        "targets_scanned": len(targets),
        "ip_dedup_skipped": ip_dedup_skipped,
    }
