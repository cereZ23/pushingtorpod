"""
Vulnerability scanning tasks with Nuclei integration

Sprint 3: Implements comprehensive Nuclei vulnerability scanning:
- URL-based scanning from HTTPx enrichment results
- Template management and customization
- Severity-based filtering
- Finding deduplication and storage
- False positive suppression
- Risk score calculation
- Integration with enrichment pipeline
"""

import logging
import asyncio
from typing import List, Optional, Dict
from datetime import datetime, timezone

from app.celery_app import celery
from app.models.database import Asset, AssetType, FindingSeverity
from app.services.scanning.nuclei_service import NucleiService, calculate_risk_score_from_findings
from app.services.scanning.suppression_service import SuppressionService
from app.repositories.finding_repository import FindingRepository
from app.repositories.service_repository import ServiceRepository
from app.utils.logger import TenantLoggerAdapter

logger = logging.getLogger(__name__)


@celery.task(name="app.tasks.scanning.run_nuclei_scan")
def run_nuclei_scan(
    tenant_id: int,
    asset_ids: Optional[List[int]] = None,
    severity: Optional[List[str]] = None,
    templates: Optional[List[str]] = None,
    rate_limit: int = 300,
    concurrency: int = 50,
    timeout: int = 1800,
    interactsh_server: Optional[str] = None,
    exclude_tags: Optional[str] = None,
):
    """
    Execute Nuclei vulnerability scan on assets

    Workflow:
    1. Get URLs from assets (from HTTPx enrichment results)
    2. Execute Nuclei scan with specified templates/severity
    3. Parse JSON output
    4. Apply suppression rules (filter false positives)
    5. Store findings with deduplication (bulk upsert)
    6. Update asset risk scores based on findings
    7. Log results and stats

    Args:
        tenant_id: Tenant ID
        asset_ids: Optional list of specific asset IDs to scan
        severity: Severity filter (critical, high, medium, low, info)
        templates: Optional template paths/categories
        rate_limit: Requests per second (default: 300)

    Returns:
        Dict with scan results and statistics
    """
    from app.database import SessionLocal

    db = SessionLocal()
    tenant_logger = TenantLoggerAdapter(logger, {"tenant_id": tenant_id})

    try:
        tenant_logger.info(
            f"Starting Nuclei scan (assets: {len(asset_ids) if asset_ids else 'all'}, "
            f"severity: {severity}, templates: {templates})"
        )

        # Get assets to scan
        query = db.query(Asset).filter(Asset.tenant_id == tenant_id, Asset.is_active == True)

        if asset_ids:
            query = query.filter(Asset.id.in_(asset_ids))

        assets = query.all()

        if not assets:
            tenant_logger.warning("No assets found for Nuclei scan")
            return {"assets_scanned": 0, "findings_created": 0, "findings_updated": 0, "status": "no_assets"}

        # Get URLs from services (HTTPx enrichment results)
        service_repo = ServiceRepository(db)
        urls_by_asset = {}

        for asset in assets:
            # Get web services for this asset (prefer live, fallback to any HTTP service)
            web_services = service_repo.get_web_services(asset.id, only_live=True)
            if not web_services:
                web_services = service_repo.get_web_services(asset.id, only_live=False)

            for service in web_services:
                # Build URL from service. The protocol field often stores
                # the transport ("tcp") not the application scheme ("https").
                # Derive scheme from TLS flag and port, not from protocol.
                port = service.port
                if service.has_tls or port in (443, 8443):
                    scheme = "https"
                elif port in (80, 8080):
                    scheme = "http"
                elif service.protocol in ("http", "https"):
                    scheme = service.protocol
                else:
                    scheme = "https" if port == 443 else "http"

                # Construct URL
                if port in [80, 443]:
                    url = f"{scheme}://{asset.identifier}"
                else:
                    url = f"{scheme}://{asset.identifier}:{port}"

                if asset.id not in urls_by_asset:
                    urls_by_asset[asset.id] = []

                urls_by_asset[asset.id].append(url)

            # Fallback: if no services at all, scan the hostname directly
            # Nuclei resolves hostnames and handles port 80/443 automatically
            if asset.id not in urls_by_asset and asset.type in (AssetType.DOMAIN, AssetType.SUBDOMAIN):
                urls_by_asset[asset.id] = [
                    f"https://{asset.identifier}",
                    f"http://{asset.identifier}",
                ]

        if not urls_by_asset:
            tenant_logger.warning("No scannable targets found for Nuclei")
            return {"assets_scanned": len(assets), "findings_created": 0, "findings_updated": 0, "status": "no_urls"}

        # Flatten URLs for scanning
        all_urls = []
        url_to_asset = {}
        # Also build a hostname→asset_id map for robust fallback matching.
        # Keys are lowercased so that a Nuclei finding whose host was
        # normalised (urlparse always lowercases) still matches even when
        # the DB identifier uses a different casing.
        host_to_asset = {}
        from urllib.parse import urlparse

        for asset_id, urls in urls_by_asset.items():
            for url in urls:
                all_urls.append(url)
                url_to_asset[url] = asset_id
                # Also store a lowercased version so that the base-URL
                # rebuilding step (which goes through urlparse and therefore
                # lowercases the host part) can still match.
                url_lower = url.lower()
                if url_lower != url:
                    url_to_asset[url_lower] = asset_id
                try:
                    parsed = urlparse(url)
                    if parsed.hostname:
                        host_to_asset[parsed.hostname.lower()] = asset_id
                        # Store both scheme variants so that a scheme
                        # switch (http↔https redirect) during the scan
                        # still resolves to the correct asset.
                        for alt_scheme in ("http", "https"):
                            port = parsed.port
                            if port and port not in (80, 443):
                                alt_url = f"{alt_scheme}://{parsed.hostname}:{port}"
                            else:
                                alt_url = f"{alt_scheme}://{parsed.hostname}"
                            if alt_url not in url_to_asset:
                                url_to_asset[alt_url] = asset_id
                except Exception:
                    pass

        tenant_logger.info(f"Scanning {len(all_urls)} URLs across {len(assets)} assets")

        # NOTE: Katana crawling is already done in Phase 6b of the pipeline.
        # Running it again here per-URL was causing O(N*300s) timeouts that
        # stalled the entire pipeline.  We scan the base URLs directly.
        scan_targets = list(all_urls)

        # Enrich scan targets with high-value endpoints discovered by Katana
        # (Phase 6b). Only include endpoints that are likely to have vulns:
        # admin panels, login pages, APIs, forms, and URLs with parameters.
        # Exclude static assets (css/js/images/fonts) that waste scan time.
        try:
            from app.models.enrichment import Endpoint

            STATIC_EXTENSIONS = {
                ".css",
                ".js",
                ".png",
                ".jpg",
                ".jpeg",
                ".gif",
                ".svg",
                ".ico",
                ".woff",
                ".woff2",
                ".ttf",
                ".eot",
                ".map",
                ".mp4",
                ".mp3",
                ".pdf",
                ".zip",
            }
            INTERESTING_PATHS = {
                "/admin",
                "/login",
                "/signin",
                "/api/",
                "/graphql",
                "/upload",
                "/config",
                "/dashboard",
                "/manager",
                "/console",
                "/debug",
                "/actuator",
                "/swagger",
                "/openapi",
                "/wp-admin",
                "/wp-login",
                "/phpmyadmin",
                "/xmlrpc",
            }

            endpoint_urls = set()
            endpoints = (
                db.query(Endpoint.url, Endpoint.endpoint_type)
                .join(Asset, Asset.id == Endpoint.asset_id)
                .filter(
                    Asset.tenant_id == tenant_id,
                    Asset.is_active == True,
                    Asset.id.in_(list(urls_by_asset.keys())),
                )
                .all()
            )

            for ep_url, ep_type in endpoints:
                if not ep_url:
                    continue
                url_lower = ep_url.lower()

                # Skip static assets
                if any(url_lower.endswith(ext) for ext in STATIC_EXTENSIONS):
                    continue

                # Include if: api/form type, interesting path, or has query params
                include = ep_type in ("api", "form") or any(p in url_lower for p in INTERESTING_PATHS) or "?" in ep_url
                if include and ep_url not in url_to_asset:
                    endpoint_urls.add(ep_url)

            if endpoint_urls:
                scan_targets.extend(endpoint_urls)
                # Register Katana endpoint hostnames in host_to_asset so
                # that findings matched on these URLs can still be mapped
                # back to the correct asset via the hostname fallback.
                for ep_url in endpoint_urls:
                    try:
                        ep_parsed = urlparse(ep_url)
                        if ep_parsed.hostname:
                            ep_host = ep_parsed.hostname.lower()
                            if ep_host not in host_to_asset:
                                # Look up by identifier in the current asset set
                                for a in assets:
                                    if a.identifier.lower() == ep_host:
                                        host_to_asset[ep_host] = a.id
                                        break
                    except Exception:
                        pass
                tenant_logger.info(
                    f"Added {len(endpoint_urls)} high-value Katana endpoints to Nuclei targets "
                    f"(from {len(endpoints)} total endpoints, filtered by type/path/params)"
                )
        except Exception as exc:
            tenant_logger.warning(f"Failed to load Katana endpoints for Nuclei: {exc}")

        # Execute Nuclei scan
        nuclei_service = NucleiService(tenant_id)

        # Use asyncio to run async method
        scan_result = asyncio.run(
            nuclei_service.scan_urls(
                urls=scan_targets,
                templates=templates,
                severity=severity or ["critical", "high", "medium"],
                rate_limit=rate_limit,
                concurrency=concurrency,
                timeout=timeout,
                interactsh_server=interactsh_server,
                exclude_tags=exclude_tags,
            )
        )

        findings = scan_result["findings"]
        stats = scan_result["stats"]
        errors = scan_result.get("errors", [])

        tenant_logger.info(f"Nuclei scan complete: {stats['findings_count']} findings discovered")

        if errors:
            tenant_logger.warning(f"Scan had {len(errors)} validation errors")

        # Map findings to assets using multi-level matching:
        # 1. Exact URL match (case-sensitive, then lowercased)
        # 2. Base URL match (strip path/query/fragment, both scheme variants)
        # 3. Hostname match against host_to_asset map
        # 4. DB lookup by hostname (case-insensitive via func.lower)
        from sqlalchemy import func as sa_func

        for finding in findings:
            matched_url = finding.get("matched_at")

            # 1. Exact URL match
            if matched_url and matched_url in url_to_asset:
                finding["asset_id"] = url_to_asset[matched_url]
                continue
            # Try lowercased URL (covers case mismatches between asset
            # identifier casing and Nuclei output normalisation)
            if matched_url and matched_url.lower() in url_to_asset:
                finding["asset_id"] = url_to_asset[matched_url.lower()]
                continue

            # 2-4. Parse hostname from matched_at and try various matches
            finding_host = finding.get("host")
            if finding_host:
                finding_host = finding_host.lower()
            if matched_url:
                try:
                    # SSL/network templates output "hostname:port" without scheme.
                    # urlparse treats that as scheme:path, giving hostname=None.
                    if "://" not in matched_url:
                        finding_host = (matched_url.split(":")[0] or finding_host or "").lower() or None
                    else:
                        parsed = urlparse(matched_url)
                        finding_host = (parsed.hostname or finding_host or "").lower() or None

                        # 2. Rebuild base URL and try match (both schemes)
                        if parsed.hostname:
                            hostname_lc = parsed.hostname.lower()
                            port = parsed.port
                            for try_scheme in (parsed.scheme or "https", "http", "https"):
                                if port and port not in (80, 443):
                                    base_url = f"{try_scheme}://{hostname_lc}:{port}"
                                else:
                                    base_url = f"{try_scheme}://{hostname_lc}"
                                if base_url in url_to_asset:
                                    finding["asset_id"] = url_to_asset[base_url]
                                    break
                            if "asset_id" in finding:
                                continue
                except Exception:
                    pass

            # 3. Hostname match against host_to_asset map
            if finding_host and finding_host in host_to_asset:
                finding["asset_id"] = host_to_asset[finding_host]
                continue

            # 4. DB lookup by hostname (catches assets not in current scan)
            if finding_host:
                asset = (
                    db.query(Asset)
                    .filter(
                        Asset.tenant_id == tenant_id,
                        sa_func.lower(Asset.identifier) == finding_host,
                    )
                    .first()
                )
                if asset:
                    finding["asset_id"] = asset.id
                    host_to_asset[finding_host] = asset.id  # cache for next lookup
                    continue

            # Could not map — log details for debugging
            tenant_logger.warning(
                f"Unmapped finding: matched_at={matched_url!r}, host={finding_host!r}, name={finding.get('name')!r}"
            )

        # Filter out findings without asset mapping
        findings_with_assets = [f for f in findings if "asset_id" in f]

        if len(findings_with_assets) < len(findings):
            unmapped = len(findings) - len(findings_with_assets)
            tenant_logger.warning(f"Could not map {unmapped} findings to assets")

        # Separate discovery findings from vulnerability findings.
        # Discovery findings (CAA, NS, MX, AAAA, SPF detect, etc.) are
        # stored as asset enrichment metadata, not as finding records.
        _DISCOVERY_TEMPLATES = {
            "caa-fingerprint",
            "ns-record-detect",
            "mx-record-detect",
            "soa-record-detect",
            "aaaa-record-detect",
            "txt-record-detect",
            "spf-record-detect",
            "dkim-record-detect",
            "ptr-record-detect",
            "srv-record-detect",
            "dns-saas-service-detection",
            "bimi-record-detect",
            "email-service-detect",
            "tlsa-record-detect",
            "dnssec-detect",
            "dns-wildcard-detect",
        }
        vuln_findings = []
        discovery_count = 0
        for f in findings_with_assets:
            tid = (f.get("template_id") or "").lower().replace(" ", "-")
            if any(dt in tid for dt in _DISCOVERY_TEMPLATES):
                # Store as enrichment on the asset
                asset_id = f["asset_id"]
                discovery_key = f.get("template_id", "unknown")
                try:
                    import json as _json

                    asset = db.query(Asset).filter(Asset.id == asset_id).first()
                    if asset:
                        meta = {}
                        if asset.raw_metadata:
                            try:
                                meta = (
                                    _json.loads(asset.raw_metadata)
                                    if isinstance(asset.raw_metadata, str)
                                    else (asset.raw_metadata or {})
                                )
                            except (ValueError, TypeError):
                                pass
                        dns_discovery = meta.get("dns_discovery", {})
                        dns_discovery[discovery_key] = {
                            "name": f.get("name"),
                            "matched_at": f.get("matched_at"),
                            "severity": f.get("severity"),
                        }
                        meta["dns_discovery"] = dns_discovery
                        asset.raw_metadata = _json.dumps(meta)
                        discovery_count += 1
                except Exception:
                    pass
            else:
                vuln_findings.append(f)

        if discovery_count:
            db.commit()
            tenant_logger.info(
                f"Stored {discovery_count} discovery findings as asset enrichment (not in findings table)"
            )

        findings_with_assets = vuln_findings

        # Apply suppression rules (filter false positives)
        suppression_service = SuppressionService(db, tenant_id)
        unsuppressed, suppressed = suppression_service.filter_findings(findings_with_assets)

        tenant_logger.info(f"Suppression filtering: {len(unsuppressed)} unsuppressed, {len(suppressed)} suppressed")

        # Store findings in database
        finding_repo = FindingRepository(db)
        upsert_result = finding_repo.bulk_upsert_findings(unsuppressed, tenant_id)

        tenant_logger.info(f"Stored findings: {upsert_result['created']} created, {upsert_result['updated']} updated")

        # Update asset risk scores
        assets_updated = update_asset_risk_scores(tenant_id, list(urls_by_asset.keys()), db)

        tenant_logger.info(f"Updated risk scores for {assets_updated} assets")

        # Trigger threat intel enrichment for newly discovered CVEs
        try:
            from app.tasks.threat_intel_sync import enrich_findings_threat_intel

            enrich_findings_threat_intel.delay(tenant_id)
            tenant_logger.info("Queued threat intel enrichment for new findings")
        except Exception as exc:
            tenant_logger.warning(f"Failed to queue threat intel enrichment: {exc}")

        return {
            "tenant_id": tenant_id,
            "assets_scanned": len(assets),
            "urls_scanned": len(all_urls),
            "findings_discovered": stats["findings_count"],
            "findings_suppressed": len(suppressed),
            "findings_created": upsert_result["created"],
            "findings_updated": upsert_result["updated"],
            "assets_risk_updated": assets_updated,
            "stats": stats,
            "status": "success",
        }

    except Exception as e:
        tenant_logger.error(f"Nuclei scan failed: {e}", exc_info=True)
        return {"tenant_id": tenant_id, "error": str(e), "status": "failed"}
    finally:
        db.close()


@celery.task(name="app.tasks.scanning.scan_single_asset")
def scan_single_asset(
    tenant_id: int, asset_id: int, severity: Optional[List[str]] = None, templates: Optional[List[str]] = None
):
    """
    Scan a single asset (convenience wrapper)

    Args:
        tenant_id: Tenant ID
        asset_id: Asset ID to scan
        severity: Severity filter
        templates: Template paths

    Returns:
        Dict with scan results
    """
    return run_nuclei_scan(tenant_id=tenant_id, asset_ids=[asset_id], severity=severity, templates=templates)


@celery.task(name="app.tasks.scanning.scan_critical_assets")
def scan_critical_assets(tenant_id: int):
    """
    Scan assets with critical priority

    Triggered automatically for high-priority assets.

    Args:
        tenant_id: Tenant ID

    Returns:
        Dict with scan results
    """
    from app.database import SessionLocal

    db = SessionLocal()

    try:
        # Get critical priority assets
        assets = (
            db.query(Asset)
            .filter(Asset.tenant_id == tenant_id, Asset.priority == "critical", Asset.is_active == True)
            .all()
        )

        if not assets:
            return {"assets_scanned": 0, "status": "no_critical_assets"}

        asset_ids = [asset.id for asset in assets]

        # Scan with critical/high severity only
        return run_nuclei_scan(tenant_id=tenant_id, asset_ids=asset_ids, severity=["critical", "high"])

    finally:
        db.close()


def update_asset_risk_scores(tenant_id: int, asset_ids: List[int], db) -> int:
    """
    Update risk scores for assets based on their findings

    Risk scoring algorithm:
    - Base score from existing risk_score
    - Add points for findings by severity:
        - Critical: +3.0
        - High: +2.0
        - Medium: +1.0
        - Low: +0.5
        - Info: +0.1
    - Cap at 10.0

    Args:
        tenant_id: Tenant ID
        asset_ids: List of asset IDs to update
        db: Database session

    Returns:
        Number of assets updated
    """
    finding_repo = FindingRepository(db)
    updated_count = 0

    for asset_id in asset_ids:
        # Get asset
        asset = db.query(Asset).filter_by(id=asset_id, tenant_id=tenant_id).first()
        if not asset:
            continue

        # Get open findings for asset
        findings = finding_repo.get_findings(tenant_id=tenant_id, asset_id=asset_id, status=["open"])

        # Convert to dicts for scoring function
        findings_dicts = [{"severity": f.severity.value} for f in findings]

        # Calculate risk score from findings
        findings_score = calculate_risk_score_from_findings(findings_dicts)

        # Update asset risk score
        # Note: We could also factor in other risk signals here
        # (e.g., exposed services, weak TLS, etc.)
        asset.risk_score = min(findings_score, 10.0)

        # Update priority based on risk score if auto-calculated
        if asset.priority_auto_calculated:
            if asset.risk_score >= 7.0:
                asset.priority = "critical"
            elif asset.risk_score >= 5.0:
                asset.priority = "high"
            elif asset.risk_score >= 2.0:
                asset.priority = "normal"
            else:
                asset.priority = "low"

            asset.priority_updated_at = datetime.now(timezone.utc)

        updated_count += 1

    db.commit()

    return updated_count


@celery.task(name="app.tasks.scanning.update_nuclei_templates")
def update_nuclei_templates():
    """
    Update Nuclei templates from ProjectDiscovery repository

    Should be run periodically (e.g., daily) to get latest templates.

    Returns:
        Dict with update results
    """
    from app.services.scanning.template_manager import template_manager

    logger.info("Updating Nuclei templates...")

    try:
        result = template_manager.update_templates()

        if result["success"]:
            logger.info("Nuclei templates updated successfully")
        else:
            logger.error(f"Template update failed: {result.get('error')}")

        return result

    except Exception as e:
        logger.error(f"Failed to update templates: {e}", exc_info=True)
        return {"success": False, "error": str(e), "timestamp": datetime.now(timezone.utc).isoformat()}


@celery.task(name="app.tasks.scanning.calculate_comprehensive_risk_scores")
def calculate_comprehensive_risk_scores(tenant_id: int):
    """
    Calculate comprehensive risk scores for all tenant assets

    Sprint 5: Comprehensive risk scoring engine considering:
    - Vulnerability findings (Nuclei)
    - Certificate/TLS issues (expiry, mismatches)
    - Exposed high-risk ports (SSH, RDP, databases)
    - Service security (login pages, HTTP vs HTTPS)
    - Asset age (new assets get monitoring bonus)

    This task should be run after enrichment pipelines complete.

    Args:
        tenant_id: Tenant ID to calculate scores for

    Returns:
        Dict with calculation results and statistics
    """
    from app.database import SessionLocal
    from app.services.risk_scoring import batch_calculate_risk_scores

    db = SessionLocal()
    tenant_logger = TenantLoggerAdapter(logger, {"tenant_id": tenant_id})

    try:
        tenant_logger.info("Starting comprehensive risk score calculation")

        # Calculate risk scores for all assets
        result = batch_calculate_risk_scores(db, tenant_id, batch_size=100)

        tenant_logger.info(f"Risk scoring complete: {result['updated']}/{result['total_assets']} assets updated")

        return {"tenant_id": tenant_id, "success": True, **result, "timestamp": datetime.now(timezone.utc).isoformat()}

    except Exception as e:
        tenant_logger.error(f"Risk scoring failed: {e}", exc_info=True)
        return {
            "tenant_id": tenant_id,
            "success": False,
            "error": str(e),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    finally:
        db.close()


@celery.task(name="app.tasks.scanning.calculate_all_tenant_risk_scores")
def calculate_all_tenant_risk_scores():
    """
    Calculate comprehensive risk scores for all tenants

    This is a scheduled task that runs periodically to update
    risk scores across all tenants.

    Should be run after enrichment and scanning pipelines.

    Returns:
        Dict with overall statistics
    """
    from celery import group as celery_group
    from app.database import SessionLocal
    from app.models.database import Tenant

    db = SessionLocal()

    try:
        tenants = db.query(Tenant).all()
        tenant_ids = [t.id for t in tenants]
    finally:
        db.close()

    if not tenant_ids:
        return {
            "total_tenants": 0,
            "status": "no_tenants",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    logger.info(f"Queuing risk score calculation for {len(tenant_ids)} tenants")

    # Use group() to run in parallel without blocking the worker
    job = celery_group(calculate_comprehensive_risk_scores.s(tid) for tid in tenant_ids)
    result = job.apply_async()

    return {
        "total_tenants": len(tenant_ids),
        "status": "queued",
        "group_id": result.id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
