"""Detection phase implementations (Phases 8, 9, 10, 11, 12).

Phase 8:  Misconfiguration Detection
Phase 9:  Vulnerability Scanning (nuclei, + interactsh on Tier 3)
Phase 10: Correlation & Dedup
Phase 11: Risk Scoring
Phase 12: Diff, Alerting & Reporting
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from app.models.risk import Relationship

logger = logging.getLogger(__name__)


def _phase_8_misconfig_detection(tenant_id, project_id, scan_run_id, db, tenant_logger):
    """Phase 8: Misconfiguration detection (50 controls)."""
    from app.tasks.misconfig import run_misconfig_detection

    result = run_misconfig_detection(tenant_id, scan_run_id=scan_run_id)

    if isinstance(result, dict):
        return {
            "findings_created": result.get("findings_created", 0),
            "findings_updated": result.get("findings_updated", 0),
            "assets_checked": result.get("assets_checked", 0),
            "controls_executed": result.get("controls_executed", 0),
            "status": result.get("status", "unknown"),
        }
    return {"findings_created": 0, "status": "unknown"}


def _phase_9_vuln_scanning(tenant_id, project_id, scan_run_id, db, tenant_logger, scan_tier=1):
    """Phase 9: Vulnerability scanning with Nuclei. Templates/severity depend on scan tier.

    Tier 1 (Safe):       critical + high only (~1700 templates)
    Tier 2 (Moderate):   critical + high + medium (~4700 templates)
    Tier 3 (Aggressive): critical + high + medium + low (~6000 templates)

    Nuclei internally resolves asset IDs to URLs via their HTTPx-enriched
    services, so we include IP assets alongside domains and subdomains to
    scan all hosts that have live web services.
    """
    from app.tasks.scanning import run_nuclei_scan
    from app.models.database import Asset, AssetType

    # Tier-based Nuclei severity configuration
    # Tier 3 excludes 'info' -- those are mostly tech-detection templates
    # (4000+) that duplicate Phase 6 and add 20+ min to scan time.
    tier_severity = {
        1: ["critical", "high"],
        2: ["critical", "high", "medium"],
        3: ["critical", "high", "medium", "low"],
    }
    severity = tier_severity.get(scan_tier, tier_severity[1])

    # Only scan hostnames -- Nuclei resolves them internally via services.
    # Skip IP assets that are already covered by a hostname's DNS resolution.
    hostname_assets = (
        db.query(Asset)
        .filter(
            Asset.tenant_id == tenant_id,
            Asset.type.in_([AssetType.DOMAIN, AssetType.SUBDOMAIN]),
            Asset.is_active == True,
        )
        .all()
    )

    covered_ip_ids = {
        r.target_asset_id
        for r in db.query(Relationship.target_asset_id)
        .filter(
            Relationship.tenant_id == tenant_id,
            Relationship.rel_type == "resolves_to",
        )
        .all()
    }
    standalone_ips = (
        db.query(Asset)
        .filter(
            Asset.tenant_id == tenant_id,
            Asset.type == AssetType.IP,
            Asset.is_active == True,
            ~Asset.id.in_(covered_ip_ids) if covered_ip_ids else True,
        )
        .all()
    )

    # Dedup hostnames resolving to the same IP before scanning
    from app.services.ip_dedup import dedup_by_resolved_ip

    all_assets = hostname_assets + standalone_ips
    all_assets, ip_dedup_skipped = dedup_by_resolved_ip(all_assets, tenant_id, db)

    # Split assets: CDN-fronted hosts only get takeover/ssl checks (CVE scans
    # would hit the CDN edge, not the origin, producing false positives).
    direct_assets = [a for a in all_assets if not a.cdn_name]
    cdn_assets = [a for a in all_assets if a.cdn_name]

    if not all_assets:
        return {"findings_created": 0, "scan_tier": scan_tier}

    asset_ids = [a.id for a in direct_assets]
    cdn_asset_ids = [a.id for a in cdn_assets]
    tenant_logger.info(
        f"Nuclei targets: {len(all_assets)} total ({len(direct_assets)} direct + "
        f"{len(cdn_assets)} CDN-fronted, {len(covered_ip_ids)} covered IPs skipped, "
        f"{ip_dedup_skipped} same-IP hostnames deduped)"
    )

    # Interactsh OOB callback support (Tier 3 only)
    from app.config import settings as app_settings

    use_interactsh = scan_tier >= 3 and getattr(app_settings, "interactsh_enabled", False)
    interactsh_server = ""
    if use_interactsh:
        interactsh_server = app_settings.interactsh_server or "oast.pro"
        tenant_logger.info("Nuclei: interactsh enabled (server=%s)", interactsh_server)

    # CPU/RAM-aware concurrency, rate limit, and timeout
    from app.services.resource_scaler import get_scan_params

    params = get_scan_params(scan_tier)
    concurrency = params.nuclei_concurrency
    rate_limit = params.nuclei_rate_limit
    timeout = params.nuclei_timeout

    # Apply adaptive throttle if active
    from app.services.adaptive_throttle import get_throttle

    throttle = get_throttle(tenant_id, scan_run_id)
    concurrency = throttle.get_rate(concurrency)

    tenant_logger.info(
        f"Nuclei: severity={severity}, rate={rate_limit}rps, concurrency={concurrency} "
        f"(tier {scan_tier}), timeout={timeout}s"
        f"{' [THROTTLED]' if throttle.is_throttled else ''}, targets={len(asset_ids)}"
    )

    total_created = 0
    total_updated = 0
    total_scanned = 0
    total_urls = 0

    # Tier 1 "fast" scan: only the highest-value template dirs (~2k templates).
    # dns/ and network/ are slow (many socket-based checks) and low-yield for EASM.
    # http/misconfiguration/ overlaps with Phase 8 misconfig.py (50 controls).
    # Tier 2+ gets the full set for deeper analysis.
    tier_templates = {
        1: ["http/cves/", "http/exposed-panels/", "http/takeovers/", "http/default-logins/", "http/exposures/", "ssl/"],
        # Tier 2/3: None = use nuclei_service default (all dirs including cloud/)
    }
    templates_for_scan = tier_templates.get(scan_tier)

    # Pass 1: Full scan on direct (non-CDN) assets
    if asset_ids:
        result = run_nuclei_scan(
            tenant_id,
            asset_ids,
            severity=severity,
            templates=templates_for_scan,
            rate_limit=rate_limit,
            concurrency=concurrency,
            timeout=timeout,
            interactsh_server=interactsh_server if use_interactsh else None,
        )
        if isinstance(result, dict):
            total_created += result.get("findings_created", 0)
            total_updated += result.get("findings_updated", 0)
            total_scanned += result.get("assets_scanned", 0)
            total_urls += result.get("urls_scanned", 0)

    # Pass 2: CDN-fronted assets -- only takeover + SSL checks (fast, ~2 min)
    if cdn_asset_ids:
        tenant_logger.info(f"Nuclei CDN pass: {len(cdn_asset_ids)} CDN-fronted assets (takeovers + ssl only)")
        cdn_result = run_nuclei_scan(
            tenant_id,
            cdn_asset_ids,
            severity=["critical", "high", "medium"],
            templates=["http/takeovers/", "ssl/"],
            rate_limit=rate_limit,
            concurrency=concurrency,
            timeout=300,  # CDN pass is fast -- 5 min max
        )
        if isinstance(cdn_result, dict):
            total_created += cdn_result.get("findings_created", 0)
            total_updated += cdn_result.get("findings_updated", 0)
            total_scanned += cdn_result.get("assets_scanned", 0)
            total_urls += cdn_result.get("urls_scanned", 0)

    # Pass 3: DNS & Network protocol checks (SPF/DKIM/DMARC, zone transfer,
    # SSH, FTP, SNMP, exposed databases). These templates use info/low severity
    # which is excluded from the main HTTP scan to avoid 4000+ noise templates.
    #
    # Tier 1: dns/ only (SPF, DKIM, DMARC, DNSSEC, zone transfer) — fast, ~1 min
    # Tier 2: dns/ + network/ basics (SSH, FTP, SNMP, Redis, MySQL, MongoDB)
    # Tier 3: dns/ + network/ full (all protocol checks)
    dns_network_templates = {
        1: ["dns/"],
        2: ["dns/", "network/"],
        3: ["dns/", "network/"],
    }
    dns_net_tpls = dns_network_templates.get(scan_tier, ["dns/"])

    # All domain/subdomain assets need DNS checks; standalone IPs need network checks
    dns_net_asset_ids = [a.id for a in all_assets]
    if dns_net_asset_ids:
        tenant_logger.info(
            f"Nuclei DNS/network pass: {len(dns_net_asset_ids)} assets, templates={dns_net_tpls} (tier {scan_tier})"
        )
        dns_result = run_nuclei_scan(
            tenant_id,
            dns_net_asset_ids,
            severity=["critical", "high", "medium", "low", "info"],
            templates=dns_net_tpls,
            rate_limit=rate_limit,
            concurrency=concurrency,
            timeout=300,  # DNS/network checks are fast
        )
        if isinstance(dns_result, dict):
            total_created += dns_result.get("findings_created", 0)
            total_updated += dns_result.get("findings_updated", 0)

    return {
        "findings_created": total_created,
        "findings_updated": total_updated,
        "assets_scanned": total_scanned,
        "urls_scanned": total_urls,
        "scan_tier": scan_tier,
        "severity_filter": severity,
        "interactsh_enabled": use_interactsh,
        "cdn_assets_scanned": len(cdn_asset_ids),
        "dns_network_templates": dns_net_tpls,
    }


def _phase_10_correlation(tenant_id, project_id, scan_run_id, db, tenant_logger):
    """Phase 10: Correlation & deduplication."""
    from app.tasks.correlation import run_correlation

    result = run_correlation(tenant_id, scan_run_id=scan_run_id)

    if isinstance(result, dict):
        return {
            "issues_created": result.get("issues_created", 0),
            "issues_updated": result.get("issues_updated", 0),
            "findings_processed": result.get("findings_processed", 0),
        }
    return {"issues_created": 0}


def _phase_11_risk_scoring(tenant_id, project_id, scan_run_id, db, tenant_logger):
    """Phase 11: Risk scoring (issue -> asset -> org).

    Three-pass scoring:
    1. Issues: risk_engine.compute_issue_score with real EPSS/KEV data from
       the highest-severity linked finding.
    2. Assets: risk_scoring.recalculate_asset_risk (CVSS + EPSS + KEV base,
       internet-exposure / expired-cert / new-asset modifiers, capped at 100).
    3. Org: risk_engine.compute_org_score (top-weighted aggregation with
       dampening, persisted as a RiskScore snapshot).
    """
    from app.services.risk_engine import (
        compute_issue_score,
        compute_org_score,
        IssueScoreInput,
    )
    from app.services.risk_scoring import recalculate_asset_risk
    from app.models.database import Asset, Finding
    from app.models.issues import Issue, IssueFinding, IssueStatus
    from app.models.risk import RiskScore

    scores_computed = 0

    # ------------------------------------------------------------------
    # 1. Score each open issue with real threat intel from linked findings
    # ------------------------------------------------------------------
    issues = (
        db.query(Issue)
        .filter(
            Issue.tenant_id == tenant_id,
            Issue.status.in_(
                [
                    IssueStatus.OPEN,
                    IssueStatus.TRIAGED,
                    IssueStatus.IN_PROGRESS,
                ]
            ),
        )
        .all()
    )

    # Build a lightweight threat intel helper (may be None if Redis is down)
    threat_intel_svc = None
    try:
        from app.services.threat_intel import ThreatIntelService

        threat_intel_svc = ThreatIntelService()
    except Exception as exc:
        tenant_logger.warning(
            "ThreatIntelService unavailable for issue scoring: %s",
            exc,
        )

    for issue in issues:
        mitigation = 0.5 if issue.status == IssueStatus.MITIGATED else 0.0
        severity_str = issue.severity if isinstance(issue.severity, str) else str(issue.severity)

        # Derive EPSS/KEV from the highest-severity linked finding
        issue_epss = 0.0
        issue_is_kev = False

        issue_is_cdn = False

        linked_finding_ids = [
            row.finding_id for row in db.query(IssueFinding.finding_id).filter_by(issue_id=issue.id).all()
        ]
        if linked_finding_ids:
            linked_findings = db.query(Finding).filter(Finding.id.in_(linked_finding_ids)).all()

            # Check CDN status from linked assets
            linked_asset_ids = list({f.asset_id for f in linked_findings})
            if linked_asset_ids:
                cdn_assets = (
                    db.query(Asset.id)
                    .filter(
                        Asset.id.in_(linked_asset_ids),
                        Asset.cdn_name.isnot(None),
                    )
                    .count()
                )
                if cdn_assets > 0:
                    issue_is_cdn = True

            if threat_intel_svc is not None:
                for finding in linked_findings:
                    if not finding.cve_id:
                        continue
                    evidence = finding.evidence or {}
                    cached = evidence.get("threat_intel", {})
                    if cached:
                        epss = float(cached.get("epss_score", 0.0))
                        kev = bool(cached.get("is_kev", False))
                    else:
                        try:
                            epss = threat_intel_svc.get_epss_score(finding.cve_id)
                            kev = threat_intel_svc.is_in_kev(finding.cve_id)
                        except (KeyError, ValueError, OSError) as _ti_exc:
                            tenant_logger.debug(
                                "Threat intel lookup failed for %s: %s",
                                finding.cve_id,
                                _ti_exc,
                            )
                            epss, kev = 0.0, False
                    if epss > issue_epss:
                        issue_epss = epss
                    if kev:
                        issue_is_kev = True

        inp = IssueScoreInput(
            severity=severity_str,
            confidence=issue.confidence or 1.0,
            exposure_factor=1.0,
            is_kev=issue_is_kev,
            epss_score=issue_epss,
            is_cdn_fronted=issue_is_cdn,
            mitigation_factor=mitigation,
        )
        result = compute_issue_score(inp)
        issue.risk_score = result.score
        scores_computed += 1

    db.flush()

    # ------------------------------------------------------------------
    # 2. Score each active asset via the new two-tier algorithm
    # ------------------------------------------------------------------
    assets = (
        db.query(Asset)
        .filter(
            Asset.tenant_id == tenant_id,
            Asset.is_active == True,
        )
        .all()
    )

    asset_scores = []
    for asset in assets:
        try:
            result = recalculate_asset_risk(asset.id, db)
            score = result.get("risk_score", 0.0)
            if "error" not in result:
                asset_scores.append(score)
                scores_computed += 1
        except Exception as exc:
            tenant_logger.error(
                "Risk scoring failed for asset %d: %s",
                asset.id,
                exc,
            )

    db.flush()

    # ------------------------------------------------------------------
    # 3. Org score (top-weighted aggregation with dampening)
    # ------------------------------------------------------------------
    if asset_scores:
        # Fetch previous org score for dampening
        prev_row = (
            db.query(RiskScore.score)
            .filter_by(tenant_id=tenant_id, scope_type="organization")
            .order_by(RiskScore.scored_at.desc())
            .first()
        )
        previous_score = prev_row.score if prev_row else None

        org_result = compute_org_score(
            sorted(asset_scores, reverse=True),
            previous_score=previous_score,
        )

        risk_score_row = RiskScore(
            tenant_id=tenant_id,
            scope_type="organization",
            scope_id=None,
            scan_run_id=scan_run_id,
            score=org_result.score,
            grade=org_result.grade,
            previous_score=previous_score,
            delta=org_result.delta,
            components={
                "top_contribution": round(org_result.score, 2),
                "asset_count": len(asset_scores),
            },
            explanation={
                "total_assets_scored": len(asset_scores),
                "average_asset_score": round(
                    sum(asset_scores) / len(asset_scores),
                    2,
                ),
                "max_asset_score": round(max(asset_scores), 2),
            },
        )
        db.add(risk_score_row)
        scores_computed += 1

    db.commit()

    return {"scores_computed": scores_computed}


def _phase_12_diff_alerting(tenant_id, project_id, scan_run_id, db, tenant_logger):
    """Phase 12: Diff computation and alerting.

    Runs two steps:
    1. Synchronous diff computation (snapshot comparison, event-based alerts).
    2. Asynchronous alert policy evaluation against actual DB findings
       dispatched as a Celery task so it does not block the pipeline.
    """
    from app.tasks.diff_alert import run_diff_and_alert

    result = run_diff_and_alert(tenant_id, scan_run_id)

    # Fire the policy-based alert evaluation asynchronously.
    # This queries real Finding rows and matches against tenant alert
    # policies, complementing the lightweight event-based alerting
    # performed inside run_diff_and_alert.
    try:
        from app.tasks.alert_evaluation import evaluate_alert_policies

        evaluate_alert_policies.delay(tenant_id, scan_run_id)
        tenant_logger.info(
            "Dispatched alert policy evaluation for tenant %d (scan_run %d)",
            tenant_id,
            scan_run_id,
        )
    except Exception as exc:
        # Non-fatal: policy evaluation failure should not break the pipeline
        tenant_logger.error(
            "Failed to dispatch alert policy evaluation: %s",
            exc,
        )

    if isinstance(result, dict):
        return {
            "new_assets": result.get("new_assets", 0),
            "new_findings": result.get("new_findings", 0),
            "alerts_sent": result.get("alerts_sent", 0),
            "is_suspicious": result.get("is_suspicious", False),
        }
    return {"alerts_sent": 0}
