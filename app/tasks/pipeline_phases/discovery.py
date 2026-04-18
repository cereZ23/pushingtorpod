"""Discovery phase implementations (Phases 0, 1, 1b, 1c, 1d, 1e).

Phase 0:  Seed Ingestion & Scope Validation
Phase 1:  Passive Discovery (subfinder, crt.sh Certificate Transparency)
Phase 1b: GitHub Dorking (optional, requires GITHUB_TOKEN)
Phase 1c: WHOIS/RDAP + Reverse WHOIS
Phase 1d: Cloud Bucket/Storage Discovery (S3, GCS, Azure Blob, DO Spaces)
Phase 1e: Cloud Asset Enumeration (cloudlist, Tier 2+)
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from app.tasks.pipeline_helpers import (
    _extract_parent_domain,
    _get_seed_domains,
    _is_hostname_in_scope,
    _is_in_scope,
    _is_ip,
    _query_crtsh,
    _upsert_relationship,
)

logger = logging.getLogger(__name__)


def _phase_0_seed_ingestion(tenant_id, project_id, scan_run_id, db, tenant_logger):
    """Phase 0: Parse seeds from project, validate scope, create initial assets.

    After upserting seed assets, counts total active assets available for
    subsequent pipeline phases. This ensures the stats reflect the real
    scanning surface rather than just newly-created rows.
    """
    from app.models.scanning import Project, Scope, Observation
    from app.models.database import Asset, AssetType, Seed

    project = db.query(Project).filter(Project.id == project_id).first()
    seeds = project.seeds or []

    if not seeds:
        # Fall back to tenant seeds
        tenant_seeds = db.query(Seed).filter(Seed.tenant_id == tenant_id, Seed.enabled == True).all()
        seeds = [{"type": s.type, "value": s.value} for s in tenant_seeds]

    if not seeds:
        raise ValueError("No seeds configured for project or tenant")

    # Load scope rules
    scopes = db.query(Scope).filter(Scope.project_id == project_id).all()

    assets_created = 0
    assets_updated = 0
    for seed in seeds:
        seed_type = seed.get("type", "domain")
        seed_value = seed.get("value", "").strip()

        if not seed_value:
            continue

        # Determine asset type
        if seed_type in ("domain", "subdomain"):
            asset_type = AssetType.DOMAIN
        elif seed_type == "ip":
            asset_type = AssetType.IP
        else:
            # For ASN, IP range - store as observation for later expansion
            obs = Observation(
                tenant_id=tenant_id,
                scan_run_id=scan_run_id,
                source="seed",
                observation_type=f"seed_{seed_type}",
                raw_data=seed,
            )
            db.add(obs)
            continue

        # Check scope rules
        if not _is_in_scope(seed_value, scopes):
            tenant_logger.warning(f"Seed {seed_value} out of scope, skipping")
            continue

        # Upsert asset
        existing = (
            db.query(Asset)
            .filter(Asset.tenant_id == tenant_id, Asset.identifier == seed_value, Asset.type == asset_type)
            .first()
        )

        if not existing:
            asset = Asset(
                tenant_id=tenant_id,
                type=asset_type,
                identifier=seed_value,
                is_active=True,
            )
            db.add(asset)
            assets_created += 1
        else:
            existing.last_seen = datetime.now(timezone.utc)
            existing.is_active = True
            assets_updated += 1

    db.commit()

    # --- Create parent_domain relationships for seeded subdomains ---
    relationships_created = 0
    seed_assets = (
        db.query(Asset)
        .filter(
            Asset.tenant_id == tenant_id,
            Asset.type.in_([AssetType.DOMAIN, AssetType.SUBDOMAIN]),
            Asset.is_active == True,
        )
        .all()
    )

    # Build a lookup by identifier so we can find parent assets
    asset_by_identifier = {a.identifier.lower(): a for a in seed_assets}

    for asset in seed_assets:
        parent_domain = _extract_parent_domain(asset.identifier)
        if parent_domain and parent_domain in asset_by_identifier:
            parent_asset = asset_by_identifier[parent_domain]
            if _upsert_relationship(
                db,
                tenant_id,
                source_asset_id=asset.id,
                target_asset_id=parent_asset.id,
                rel_type="parent_domain",
                metadata={"source": "seed_ingestion"},
            ):
                relationships_created += 1

    if relationships_created:
        db.commit()

    # Count total active assets available for subsequent phases
    total_active = db.query(Asset).filter(Asset.tenant_id == tenant_id, Asset.is_active == True).count()

    return {
        "seeds_processed": len(seeds),
        "assets_discovered": assets_created,
        "assets_updated": assets_updated,
        "relationships_created": relationships_created,
        "total_active_assets": total_active,
    }


def _phase_1_passive_discovery(tenant_id, project_id, scan_run_id, db, tenant_logger):
    """Phase 1: Run subfinder + crt.sh for passive subdomain discovery."""
    from app.tasks.discovery import run_subfinder
    from app.models.database import Asset, AssetType

    # Get root domains from assets
    domains = (
        db.query(Asset.identifier)
        .filter(Asset.tenant_id == tenant_id, Asset.type == AssetType.DOMAIN, Asset.is_active == True)
        .all()
    )
    domain_list = [d[0] for d in domains]

    if not domain_list:
        return {"assets_discovered": 0, "domains_checked": 0}

    # run_subfinder expects (seed_data: dict, tenant_id: int)
    seed_data = {"domains": domain_list}
    result = run_subfinder(seed_data, tenant_id)

    # Count subdomains found, filter to in-scope only
    subdomains = result.get("subdomains", []) if isinstance(result, dict) else []
    seed_domains = _get_seed_domains(tenant_id, project_id, db)
    subdomains = [s for s in subdomains if _is_hostname_in_scope(s.strip().lower(), seed_domains)]
    assets_discovered = len(subdomains)

    # Upsert discovered subdomains as assets
    for sub in subdomains:
        sub = sub.strip().lower()
        if not sub:
            continue
        existing = db.query(Asset.id).filter(Asset.tenant_id == tenant_id, Asset.identifier == sub).first()
        if not existing:
            db.add(
                Asset(
                    tenant_id=tenant_id,
                    type=AssetType.SUBDOMAIN,
                    identifier=sub,
                    is_active=True,
                )
            )
    if subdomains:
        db.commit()

    # Run crt.sh Certificate Transparency log search
    crtsh_total = 0
    crtsh_new = 0
    for domain in domain_list:
        try:
            total, new = _query_crtsh(domain, tenant_id, db, tenant_logger)
            crtsh_total += total
            crtsh_new += new
        except Exception as e:
            tenant_logger.warning(f"crt.sh query failed for {domain} (non-fatal): {e}")

    assets_discovered += crtsh_new

    return {
        "assets_discovered": assets_discovered,
        "crtsh_found": crtsh_total,
        "crtsh_new": crtsh_new,
        "domains_checked": len(domain_list),
    }


def _phase_1b_github_dorking(tenant_id, project_id, scan_run_id, db, tenant_logger):
    """Phase 1b: GitHub code search for leaked secrets."""
    # Will be implemented in Phase 3 of the plan
    return {"findings_created": 0, "status": "stub"}


def _phase_1c_whois_discovery(tenant_id, project_id, scan_run_id, db, tenant_logger):
    """Phase 1c: WHOIS/RDAP + reverse WHOIS + GeoIP + CDN/WAF discovery.

    Enriches all active domain, subdomain, and IP assets with:
    - WHOIS registration data (registrar, org, dates, nameservers)
    - Reverse DNS (PTR records)
    - ASN / BGP information
    - GeoIP geolocation (country, city, lat/lon)
    - CDN detection (Cloudflare, Akamai, Fastly, etc.)
    - WAF detection (Cloudflare, AWS WAF, Imperva, etc.)
    - Cloud provider detection (AWS, GCP, Azure, etc.)

    Results are stored in asset.raw_metadata under structured keys.
    """
    from app.tasks.network_enrichment import phase_1c_network_enrichment
    from app.models.database import Asset, AssetType

    # Only enrich root DOMAIN + IP assets with full WHOIS/GeoIP.
    # Subdomains share the same WHOIS as their parent domain, so running
    # WHOIS on each one is redundant and slow (~0.5-2s per lookup x hundreds).
    # CDN/WAF detection for subdomains is handled in Phase 5b (cdncheck).
    assets = (
        db.query(Asset)
        .filter(
            Asset.tenant_id == tenant_id,
            Asset.type.in_([AssetType.DOMAIN, AssetType.IP]),
            Asset.is_active == True,  # noqa: E712
        )
        .all()
    )

    if not assets:
        return {"assets_discovered": 0, "assets_enriched": 0}

    asset_ids = [a.id for a in assets]
    tenant_logger.info(
        f"Phase 1c: {len(asset_ids)} assets for network enrichment "
        f"(domains + IPs only, subdomains inherit WHOIS from parent)"
    )

    enrichment_result = phase_1c_network_enrichment(tenant_id, asset_ids, db, tenant_logger)

    # --- IP Range Discovery from WHOIS org name ---
    # After enrichment, extract org names from WHOIS data on root domains
    # and discover IP ranges via BGPView/RIPE.
    import ipaddress
    from app.services.network_intel import discover_org_ip_ranges, whois_lookup

    org_names_seen: set[str] = set()
    new_ips_created = 0

    for asset in assets:
        if asset.type != AssetType.DOMAIN:
            continue
        # Get org from raw_metadata (populated by enrichment above)
        metadata = asset.raw_metadata if isinstance(asset.raw_metadata, dict) else {}
        whois_data = metadata.get("whois") if isinstance(metadata.get("whois"), dict) else {}
        org = whois_data.get("org") if isinstance(whois_data, dict) else None
        if not org or org.lower() in org_names_seen:
            continue
        org_names_seen.add(org.lower())

        tenant_logger.info("Phase 1c: discovering IP ranges for org '%s'", org)
        ip_ranges = discover_org_ip_ranges(org)

        for range_info in ip_ranges:
            prefix = range_info.get("prefix")
            if not prefix:
                continue
            try:
                network = ipaddress.ip_network(prefix, strict=False)
            except ValueError:
                continue

            # Only scan ranges up to /22 (1024 IPs) to avoid scanning huge ISP blocks
            if network.prefixlen < 22:
                tenant_logger.info(
                    "Skipping large prefix %s (/%d) — too broad",
                    prefix,
                    network.prefixlen,
                )
                continue

            # Create IP assets for each address in the range
            for ip_addr in network.hosts():
                ip_str = str(ip_addr)
                existing = (
                    db.query(Asset.id)
                    .filter(
                        Asset.tenant_id == tenant_id,
                        Asset.identifier == ip_str,
                    )
                    .first()
                )
                if not existing:
                    new_asset = Asset(
                        tenant_id=tenant_id,
                        type=AssetType.IP,
                        identifier=ip_str,
                        is_active=True,
                        source="ip_range_discovery",
                    )
                    db.add(new_asset)
                    new_ips_created += 1

            if new_ips_created > 0:
                db.commit()
                tenant_logger.info(
                    "Phase 1c: created %d new IP assets from range %s",
                    new_ips_created,
                    prefix,
                )

    enrichment_result["ip_ranges_discovered"] = len(org_names_seen)
    enrichment_result["new_ips_from_ranges"] = new_ips_created
    return enrichment_result


def _phase_1d_cloud_buckets(tenant_id, project_id, scan_run_id, db, tenant_logger):
    """Phase 1d: Cloud Bucket/Storage Discovery.

    Generates bucket name permutations from root domains and subdomains,
    then probes AWS S3, Google Cloud Storage, Azure Blob Storage, and
    DigitalOcean Spaces for publicly accessible buckets.

    Runs after seed ingestion and passive discovery so that both root domains
    and discovered subdomains are available as inputs for name generation.
    """
    from app.tasks.cloud_scan import run_cloud_bucket_scan
    from app.models.database import Asset, AssetType

    # Only use ROOT domains for bucket name generation (not subdomains).
    # Subdomains like mail.example.com generate too many useless permutations.
    assets = (
        db.query(Asset)
        .filter(
            Asset.tenant_id == tenant_id,
            Asset.type == AssetType.DOMAIN,
            Asset.is_active == True,  # noqa: E712
        )
        .all()
    )

    if not assets:
        return {"findings_created": 0, "domains_processed": 0}

    asset_ids = [a.id for a in assets]
    tenant_logger.info(f"Cloud bucket scan: {len(asset_ids)} domain assets")

    result = run_cloud_bucket_scan(tenant_id, asset_ids, db=db, scan_run_id=scan_run_id)

    return {
        "findings_created": result.get("findings_created", 0) if isinstance(result, dict) else 0,
        "findings_updated": result.get("findings_updated", 0) if isinstance(result, dict) else 0,
        "domains_processed": result.get("domains_processed", 0) if isinstance(result, dict) else 0,
        "bucket_names_generated": result.get("bucket_names_generated", 0) if isinstance(result, dict) else 0,
        "targets_probed": result.get("targets_probed", 0) if isinstance(result, dict) else 0,
        "buckets_found": result.get("buckets_found", 0) if isinstance(result, dict) else 0,
    }


def _phase_1e_cloud_enum(tenant_id, project_id, scan_run_id, db, tenant_logger):
    """Phase 1e: Cloud asset enumeration with cloudlist.

    Reads cloud provider credentials from project.settings['cloud_providers'],
    runs cloudlist, and upserts discovered IPs/hostnames as assets.
    """
    from app.tasks.cloud_enum import run_cloudlist
    from app.models.database import Asset, AssetType
    from app.models.scanning import Project

    project = db.query(Project).filter(Project.id == project_id).first()
    provider_config = (project.settings or {}).get("cloud_providers", [])

    if not provider_config:
        return {"assets_discovered": 0, "providers_scanned": 0}

    cloud_assets = run_cloudlist(tenant_id, provider_config)

    assets_created = 0
    for ca in cloud_assets:
        identifier = ca.get("hostname") or ca.get("ip", "")
        if not identifier:
            continue

        asset_type = AssetType.IP if _is_ip(identifier) else AssetType.SUBDOMAIN

        existing = (
            db.query(Asset)
            .filter(
                Asset.tenant_id == tenant_id,
                Asset.identifier == identifier,
                Asset.type == asset_type,
            )
            .first()
        )

        if not existing:
            asset = Asset(
                tenant_id=tenant_id,
                type=asset_type,
                identifier=identifier,
                is_active=True,
                cloud_provider=ca.get("provider", ""),
            )
            db.add(asset)
            assets_created += 1
        else:
            existing.last_seen = datetime.now(timezone.utc)
            existing.is_active = True
            if ca.get("provider"):
                existing.cloud_provider = ca["provider"]

    db.commit()

    return {
        "assets_discovered": assets_created,
        "providers_scanned": len(provider_config),
        "total_cloud_assets": len(cloud_assets),
    }
