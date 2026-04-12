"""
Threat Intelligence synchronization tasks.

Celery tasks for periodic refresh of EPSS scores and CISA KEV catalog data.
Designed to run via Celery Beat on a daily schedule (2:15 AM UTC) and can also
be triggered manually through the threat-intel API endpoints.

Tasks:
    refresh_threat_intel:
        Full refresh of KEV catalog + bulk EPSS lookup for all CVEs in findings.

    enrich_findings_threat_intel:
        Per-tenant enrichment that attaches EPSS/KEV data to findings and
        feeds updated scores into the risk scoring engine.
"""

import json
import logging
from datetime import datetime, timezone

from app.celery_app import celery
from app.utils.logger import TenantLoggerAdapter

logger = logging.getLogger(__name__)


@celery.task(
    name="app.tasks.threat_intel_sync.refresh_threat_intel",
    bind=True,
    max_retries=3,
    default_retry_delay=300,
)
def refresh_threat_intel(self) -> dict:
    """Periodic task to refresh EPSS and KEV data platform-wide.

    Workflow:
        1. Refresh the full CISA KEV catalog into Redis.
        2. Query all unique CVE IDs from the findings table.
        3. Bulk-fetch EPSS scores for all discovered CVEs.
        4. Cache everything in Redis with 24h TTL.

    This task is idempotent and safe to run multiple times. It is scheduled
    daily via Celery Beat but can also be triggered manually.

    Returns:
        Statistics dict with kev_count, epss_fetched, and timing information.
    """
    from app.database import SessionLocal
    from app.models.database import Finding
    from app.services.threat_intel import ThreatIntelService

    logger.info("Starting threat intelligence refresh")
    start_time = datetime.now(timezone.utc)

    stats = {
        "kev_count": 0,
        "unique_cves": 0,
        "epss_fetched": 0,
        "errors": [],
        "started_at": start_time.isoformat(),
        "status": "running",
    }

    service = ThreatIntelService()

    # Step 1: Refresh KEV catalog
    try:
        kev_count = service.refresh_kev_catalog()
        stats["kev_count"] = kev_count
        logger.info("KEV catalog refreshed: %d entries", kev_count)
    except Exception as exc:
        error_msg = f"KEV refresh failed: {exc}"
        logger.error(error_msg, exc_info=True)
        stats["errors"].append(error_msg)
        # Retry on transient errors
        try:
            self.retry(exc=exc)
        except self.MaxRetriesExceededError:
            logger.error("KEV refresh max retries exceeded")

    # Step 2: Get all unique CVE IDs from findings
    db = SessionLocal()
    try:
        cve_rows = db.query(Finding.cve_id).filter(Finding.cve_id.isnot(None), Finding.cve_id != "").distinct().all()
        cve_ids = [row[0] for row in cve_rows if row[0]]
        stats["unique_cves"] = len(cve_ids)
        logger.info("Found %d unique CVEs in findings table", len(cve_ids))
    except Exception as exc:
        error_msg = f"Failed to query CVE IDs: {exc}"
        logger.error(error_msg, exc_info=True)
        stats["errors"].append(error_msg)
        cve_ids = []
    finally:
        db.close()

    # Step 3: Bulk fetch EPSS scores
    if cve_ids:
        try:
            epss_results = service.get_epss_scores_bulk(cve_ids)
            stats["epss_fetched"] = len(epss_results)
            # Log CVEs with high EPSS for operational awareness
            high_epss = {cve: score for cve, score in epss_results.items() if score >= 0.5}
            if high_epss:
                logger.warning(
                    "High EPSS scores detected (%d CVEs >= 0.5): %s",
                    len(high_epss),
                    ", ".join(
                        f"{cve}={score:.3f}"
                        for cve, score in sorted(high_epss.items(), key=lambda x: x[1], reverse=True)[:10]
                    ),
                )
        except Exception as exc:
            error_msg = f"EPSS bulk fetch failed: {exc}"
            logger.error(error_msg, exc_info=True)
            stats["errors"].append(error_msg)

    end_time = datetime.now(timezone.utc)
    stats["completed_at"] = end_time.isoformat()
    stats["duration_seconds"] = (end_time - start_time).total_seconds()
    stats["status"] = "completed" if not stats["errors"] else "completed_with_errors"

    logger.info(
        "Threat intel refresh completed in %.1fs: KEV=%d, EPSS=%d, errors=%d",
        stats["duration_seconds"],
        stats["kev_count"],
        stats["epss_fetched"],
        len(stats["errors"]),
    )

    return stats


@celery.task(
    name="app.tasks.threat_intel_sync.enrich_findings_threat_intel",
    bind=True,
    max_retries=2,
    default_retry_delay=60,
)
def enrich_findings_threat_intel(self, tenant_id: int) -> dict:
    """Enrich a tenant's findings with EPSS/KEV data and update risk scores.

    For each open finding with a cve_id:
        1. Looks up EPSS score (from Redis cache or API).
        2. Checks KEV catalog membership.
        3. Stores enrichment data in the finding's evidence JSON field
           under the "threat_intel" key.
        4. Triggers comprehensive risk score recalculation for affected assets.

    This feeds directly into the RiskScoringEngine which already uses
    EPSS and KEV signals in its scoring formula via the _score_findings method.

    Args:
        tenant_id: Tenant ID whose findings should be enriched.

    Returns:
        Statistics dict with enrichment counts and affected assets.
    """
    from app.database import SessionLocal
    from app.models.database import Asset, Finding, FindingStatus
    from app.services.threat_intel import ThreatIntelService

    tenant_logger = TenantLoggerAdapter(logger, {"tenant_id": tenant_id})
    tenant_logger.info("Starting threat intel enrichment for tenant findings")

    db = SessionLocal()
    start_time = datetime.now(timezone.utc)

    stats = {
        "tenant_id": tenant_id,
        "findings_processed": 0,
        "findings_with_cve": 0,
        "kev_matches": 0,
        "high_epss_count": 0,
        "assets_affected": 0,
        "status": "running",
    }

    try:
        service = ThreatIntelService()

        # Get all open findings with CVE IDs for this tenant
        findings = (
            db.query(Finding)
            .join(Asset)
            .filter(
                Asset.tenant_id == tenant_id,
                Finding.status == FindingStatus.OPEN,
                Finding.cve_id.isnot(None),
                Finding.cve_id != "",
            )
            .all()
        )

        stats["findings_with_cve"] = len(findings)

        if not findings:
            tenant_logger.info("No open findings with CVE IDs found")
            stats["status"] = "completed"
            return stats

        # Bulk enrich
        enrichments = service.enrich_findings(findings)

        # Build lookup by finding_id for efficient update
        enrichment_map = {e["finding_id"]: e for e in enrichments}

        affected_asset_ids: set[int] = set()

        for finding in findings:
            enrichment = enrichment_map.get(finding.id)
            if not enrichment:
                continue

            # Update finding evidence with threat intel data.
            # evidence may be a dict, a JSON string, or None.
            raw_evidence = finding.evidence
            if isinstance(raw_evidence, str):
                try:
                    evidence = json.loads(raw_evidence)
                except (json.JSONDecodeError, TypeError):
                    evidence = {}
            else:
                evidence = raw_evidence or {}
            evidence["threat_intel"] = {
                "epss_score": enrichment["epss_score"],
                "is_kev": enrichment["is_kev"],
                "kev_details": enrichment.get("kev_details"),
                "enriched_at": datetime.now(timezone.utc).isoformat(),
            }
            finding.evidence = evidence

            stats["findings_processed"] += 1

            if enrichment["is_kev"]:
                stats["kev_matches"] += 1

            if enrichment["epss_score"] >= 0.5:
                stats["high_epss_count"] += 1

            affected_asset_ids.add(finding.asset_id)

        stats["assets_affected"] = len(affected_asset_ids)

        db.commit()

        tenant_logger.info(
            "Threat intel enrichment complete: %d findings processed, %d KEV matches, %d high-EPSS, %d assets affected",
            stats["findings_processed"],
            stats["kev_matches"],
            stats["high_epss_count"],
            stats["assets_affected"],
        )

        # Trigger risk score recalculation for affected assets
        if affected_asset_ids:
            try:
                from app.tasks.scanning import (
                    calculate_comprehensive_risk_scores,
                )

                calculate_comprehensive_risk_scores.delay(tenant_id)
                tenant_logger.info(
                    "Triggered risk score recalculation for tenant %d",
                    tenant_id,
                )
            except Exception as exc:
                tenant_logger.warning("Failed to trigger risk recalculation: %s", exc)

        stats["status"] = "completed"

    except Exception as exc:
        tenant_logger.error("Threat intel enrichment failed: %s", exc, exc_info=True)
        db.rollback()
        stats["status"] = "failed"
        stats["error"] = str(exc)
        try:
            self.retry(exc=exc)
        except self.MaxRetriesExceededError:
            tenant_logger.error("Threat intel enrichment max retries exceeded")

    finally:
        end_time = datetime.now(timezone.utc)
        stats["duration_seconds"] = (end_time - start_time).total_seconds()
        db.close()

    return stats
