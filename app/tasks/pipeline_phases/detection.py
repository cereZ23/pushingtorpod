"""Detection phase implementations (Phases 8, 9, 10, 11, 12).

Phase 8:  Misconfiguration Detection
Phase 9:  Vulnerability Scanning (nuclei, + interactsh on Tier 3)
Phase 10: Correlation & Dedup
Phase 11: Risk Scoring
Phase 12: Diff, Alerting & Reporting
"""

from __future__ import annotations

import json
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
    # Include medium for all tiers — many real exposure findings
    # (Dockerfile, docker-compose, .htaccess, .env) are rated medium.
    # Excluding medium from T1 caused false negatives on known vulns.
    tier_severity = {
        1: ["critical", "high", "medium"],
        2: ["critical", "high", "medium"],
        3: ["critical", "high", "medium", "low"],
    }
    severity = tier_severity.get(scan_tier, tier_severity[1])

    # Only scan assets that have at least one live HTTP service (discovered
    # by phase 4 HTTPx). Sending ghost subdomains to Nuclei causes 80%+
    # error rates and wastes scan time on unreachable hosts.
    from app.models.database import Service
    from sqlalchemy.orm import aliased
    from sqlalchemy import and_, exists

    live_asset_ids = {
        row[0]
        for row in db.query(Asset.id)
        .filter(
            Asset.tenant_id == tenant_id,
            Asset.type.in_([AssetType.DOMAIN, AssetType.SUBDOMAIN, AssetType.IP]),
            Asset.is_active == True,
            exists().where(
                and_(
                    Service.asset_id == Asset.id,
                    Service.http_status.isnot(None),
                )
            ),
        )
        .all()
    }

    hostname_assets = (
        db.query(Asset)
        .filter(
            Asset.tenant_id == tenant_id,
            Asset.type.in_([AssetType.DOMAIN, AssetType.SUBDOMAIN]),
            Asset.is_active == True,
            Asset.id.in_(live_asset_ids),
        )
        .all()
    )

    # Standalone IPs not covered by any hostname (atomic LEFT JOIN, see phase 5)
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
            Asset.id.in_(live_asset_ids),
            _R.id.is_(None),
        )
        .all()
    )

    # NOTE: do NOT dedup hostnames by resolved IP for Nuclei. Unlike naabu
    # (port scanning, where same IP = same ports), Nuclei uses the Host
    # header and each virtual host can serve different content. Deduping
    # by IP caused www.ifo.it to be dropped (same Azure IP as cdn.ifo.it)
    # and its docker-compose.yml + .htaccess findings were never found.
    all_assets = hostname_assets + standalone_ips

    # Soft-404 detection: probe each host with a random URL to find hosts
    # that return 200 for non-existent paths. These produce false positives
    # in Nuclei (every path looks "found"). Filter them from scan targets
    # but still run DNS/SSL checks on them.
    from app.utils.soft404 import detect_soft404_hosts

    probe_urls = {}
    for a in all_assets:
        url = f"https://{a.identifier}"
        probe_urls[url] = a.id
        # Also try http for non-TLS hosts
        http_url = f"http://{a.identifier}"
        probe_urls[http_url] = a.id

    soft404_urls = detect_soft404_hosts(list(probe_urls.keys()), timeout=5.0, max_workers=30)
    soft404_asset_ids = {probe_urls[u] for u in soft404_urls}

    if soft404_asset_ids:
        before_count = len(all_assets)
        all_assets = [a for a in all_assets if a.id not in soft404_asset_ids]
        tenant_logger.info(
            f"Soft-404: filtered {before_count - len(all_assets)} hosts "
            f"(custom error pages), {len(all_assets)} remain for Nuclei HTTP scan"
        )

    tenant_logger.info(
        f"Nuclei: {len(live_asset_ids)} assets with live HTTP, "
        f"{len(all_assets)} targets ({len(hostname_assets)} hostnames + {len(standalone_ips)} standalone IPs)"
    )

    # Split assets: CDN-fronted hosts only get takeover/ssl checks (CVE scans
    # would hit the CDN edge, not the origin, producing false positives).
    direct_assets = [a for a in all_assets if not getattr(a, "cdn_name", None)]
    cdn_assets = [a for a in all_assets if getattr(a, "cdn_name", None)]

    if not all_assets:
        return {"findings_created": 0, "scan_tier": scan_tier}

    asset_ids = [a.id for a in direct_assets]
    cdn_asset_ids = [a.id for a in cdn_assets]

    # DNS/network pass targets: ALL active domains (not just HTTP-live),
    # because DNS checks (SPF, DKIM, DMARC, zone transfer, DNSSEC) don't
    # need a web server.
    all_active_domains = (
        db.query(Asset)
        .filter(
            Asset.tenant_id == tenant_id,
            Asset.type.in_([AssetType.DOMAIN, AssetType.SUBDOMAIN]),
            Asset.is_active == True,
        )
        .all()
    )

    tenant_logger.info(
        f"Nuclei targets: {len(all_assets)} HTTP-live ({len(direct_assets)} direct + "
        f"{len(cdn_assets)} CDN-fronted, no IP dedup — virtual hosts need distinct scans), "
        f"{len(all_active_domains)} domains for DNS/network pass"
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

    # Tier-aware exclude-tags: T1 is very conservative (no active payloads),
    # T2/T3 allow detection-based checks but still exclude intrusive templates.
    # NOTE: we tried fully opening T3 (removing intrusive,sqli,xss,ssrf) but
    # those templates send attack payloads that cause i/o timeouts on Azure
    # hosts, which triggers nuclei's "permanently unresponsive" blacklist and
    # prevents ALL subsequent templates (including simple detection checks
    # like docker-compose, htaccess) from running on that host. Keeping
    # intrusive excluded is essential for detection quality.
    # Exclude noisy tags. `discovery` templates (CAA, NS, MX, SOA, SPF, AAAA
    # etc.) only report that something EXISTS, not that it's vulnerable. They
    # produce 80+ INFO findings per scan that drown actionable results.
    tier_exclude_tags = {
        1: "dos,headless,fuzz,osint,token-spray,intrusive,sqli,xss,ssrf,ssti,rce,upload,bruteforce,credential-stuffing,discovery",
        2: "dos,headless,fuzz,osint,token-spray,intrusive,credential-stuffing,bruteforce,upload,discovery",
        3: "dos,headless,fuzz,osint,intrusive,credential-stuffing,discovery",
    }
    exclude_tags = tier_exclude_tags.get(scan_tier, tier_exclude_tags[1])

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

    # Tier-aware template selection.
    # See security-engineer agent analysis for full rationale per directory.
    # Excluded everywhere: http/technologies/ (Phase 6 does it), http/osint/
    # (Phase 1 does it), dast/ (payload injection risk), credential-stuffing/
    # (legal), headless/ (Phase 7 does it), file/code/workflows/ (not HTTP).
    tier_templates = {
        1: [
            "http/cves/",
            "http/exposed-panels/",
            "http/takeovers/",
            "http/default-logins/",
            "http/exposures/",
            "http/honeypot/",
            "http/cnvd/",
            "ssl/",
            "custom/",
        ],
        2: [
            "http/cves/",
            "http/exposed-panels/",
            "http/misconfiguration/",
            "http/default-logins/",
            "http/takeovers/",
            "http/exposures/",
            "http/vulnerabilities/",
            "http/iot/",
            "http/cnvd/",
            "http/miscellaneous/",
            "http/honeypot/",
            "cloud/",
            "ssl/",
            "javascript/",
            "custom/",
        ],
        # T3: same dirs as T2 but with broader severity + fewer exclude-tags
    }
    templates_for_scan = tier_templates.get(scan_tier, tier_templates[2])

    # DNS/network template config (Pass 3)
    # Tier 1: dns/ only (SPF, DKIM, DMARC, DNSSEC, zone transfer) -- fast, ~1 min
    # Tier 2: dns/ + network/ basics (SSH, FTP, SNMP, Redis, MySQL, MongoDB)
    # Tier 3: dns/ + network/ full (all protocol checks)
    dns_network_templates = {
        1: ["dns/"],
        2: ["dns/", "network/"],
        3: ["dns/", "network/"],
    }
    dns_net_tpls = dns_network_templates.get(scan_tier, ["dns/"])
    dns_net_asset_ids = [a.id for a in all_active_domains]

    # Memory profiling: log RSS before/after Nuclei passes
    import psutil

    proc = psutil.Process()
    mem_before = proc.memory_info().rss / (1024 * 1024)
    tenant_logger.info(f"Nuclei memory: {mem_before:.0f} MB RSS before scan")

    # ---------------------------------------------------------------
    # Run all Nuclei passes concurrently using threads.
    # Each pass targets different assets/templates so they don't
    # interfere with each other.  This eliminates sequential startup
    # overhead (~20s per Nuclei process) and overlaps I/O-bound work.
    # ---------------------------------------------------------------
    from concurrent.futures import ThreadPoolExecutor, as_completed

    def _run_pass_1():
        """Pass 1: HTTP + SSL templates on direct (non-CDN) assets."""
        if not asset_ids:
            return None
        return run_nuclei_scan(
            tenant_id,
            asset_ids,
            severity=severity,
            templates=templates_for_scan,
            rate_limit=rate_limit,
            concurrency=concurrency,
            timeout=timeout,
            interactsh_server=interactsh_server if use_interactsh else None,
            exclude_tags=exclude_tags,
        )

    def _run_pass_2():
        """Pass 2: CDN-fronted assets -- takeover + SSL checks only."""
        if not cdn_asset_ids:
            return None
        tenant_logger.info(f"Nuclei CDN pass: {len(cdn_asset_ids)} CDN-fronted assets (takeovers + ssl only)")
        return run_nuclei_scan(
            tenant_id,
            cdn_asset_ids,
            severity=["critical", "high", "medium"],
            templates=["http/takeovers/", "ssl/"],
            rate_limit=rate_limit,
            concurrency=concurrency,
            timeout=300,
            exclude_tags=tier_exclude_tags[1],  # CDN pass always uses T1 (conservative)
        )

    def _run_pass_3():
        """Pass 3: DNS & network protocol checks on all assets."""
        if not dns_net_asset_ids:
            return None
        tenant_logger.info(
            f"Nuclei DNS/network pass: {len(dns_net_asset_ids)} assets, templates={dns_net_tpls} (tier {scan_tier})"
        )
        return run_nuclei_scan(
            tenant_id,
            dns_net_asset_ids,
            severity=["critical", "high", "medium", "low", "info"],
            templates=dns_net_tpls,
            rate_limit=rate_limit,
            concurrency=concurrency,
            timeout=300,
            exclude_tags=exclude_tags,
        )

    # Pass 0: custom templates FIRST (sequential, fast ~10s).
    # Custom templates get buried in the 5000+ stock template queue and
    # never execute before timeout. Running them as a dedicated pass
    # guarantees they always run on every host.
    if asset_ids:
        tenant_logger.info(
            f"Nuclei custom pass: {len(asset_ids)} direct assets, templates=['/app/custom-nuclei-templates/']"
        )
        try:
            custom_result = run_nuclei_scan(
                tenant_id,
                asset_ids,
                severity=["critical", "high", "medium", "low"],
                templates=["/app/custom-nuclei-templates/"],
                rate_limit=rate_limit,
                concurrency=concurrency,
                timeout=120,  # 2 min max — only 3 templates
                exclude_tags="",  # empty string = no exclusions for our own templates
            )
            if isinstance(custom_result, dict):
                total_created += custom_result.get("findings_created", 0)
                total_updated += custom_result.get("findings_updated", 0)
                total_scanned += custom_result.get("assets_scanned", 0)
                total_urls += custom_result.get("urls_scanned", 0)
                tenant_logger.info(
                    f"Nuclei custom pass complete: {custom_result.get('findings_created', 0)} new findings"
                )
        except Exception as exc:
            tenant_logger.error(f"Nuclei custom pass failed: {exc}")

    # Run stock passes in PARALLEL — pass 1 (HTTP) and pass 3 (DNS/network) target
    # different protocols so they don't compete for bandwidth. The HTTP-live
    # filter on pass 1 eliminated the 88% error rate that made parallel
    # execution problematic before.
    from concurrent.futures import ThreadPoolExecutor, as_completed

    passes = {"pass_1": _run_pass_1, "pass_2": _run_pass_2, "pass_3": _run_pass_3}
    active_passes = {
        k: fn
        for k, fn in passes.items()
        if ((k == "pass_1" and asset_ids) or (k == "pass_2" and cdn_asset_ids) or (k == "pass_3" and dns_net_asset_ids))
    }

    tenant_logger.info(f"Nuclei: running {len(active_passes)} passes concurrently: {', '.join(active_passes.keys())}")

    with ThreadPoolExecutor(max_workers=len(active_passes) or 1) as executor:
        futures = {executor.submit(fn): name for name, fn in active_passes.items()}
        for future in as_completed(futures):
            pass_name = futures[future]
            try:
                result = future.result()
                if isinstance(result, dict):
                    total_created += result.get("findings_created", 0)
                    total_updated += result.get("findings_updated", 0)
                    total_scanned += result.get("assets_scanned", 0)
                    total_urls += result.get("urls_scanned", 0)
                    tenant_logger.info(f"Nuclei {pass_name} complete: {result.get('findings_created', 0)} findings")
            except Exception as exc:
                tenant_logger.error(f"Nuclei {pass_name} failed: {exc}")

    mem_after = proc.memory_info().rss / (1024 * 1024)
    tenant_logger.info(f"Nuclei memory: {mem_after:.0f} MB RSS after scan (delta: +{mem_after - mem_before:.0f} MB)")

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
        "memory_before_mb": round(mem_before),
        "memory_after_mb": round(mem_after),
        "memory_delta_mb": round(mem_after - mem_before),
    }


def _phase_10_correlation(tenant_id, project_id, scan_run_id, db, tenant_logger):
    """Phase 10: Correlation & deduplication.

    Also auto-closes stale nuclei findings not seen in the last 2 scans.
    """
    from app.tasks.correlation import run_correlation
    from app.models.database import Finding, FindingStatus, Asset
    from datetime import timedelta

    # Auto-close stale nuclei findings: open findings whose last_seen is
    # older than the current scan's started_at are no longer detected.
    # Grace period: 2 scan cycles (findings must be absent for 2 consecutive scans).
    from app.models.scanning import ScanRun

    current_run = db.query(ScanRun).filter(ScanRun.id == scan_run_id).first()
    if current_run and current_run.started_at:
        grace = timedelta(hours=48)
        cutoff = current_run.started_at - grace
        stale_nuclei = (
            db.query(Finding)
            .join(Asset)
            .filter(
                Asset.tenant_id == tenant_id,
                Finding.source == "nuclei",
                Finding.status == FindingStatus.OPEN,
                Finding.last_seen < cutoff,
            )
            .all()
        )
        auto_closed = 0
        for f in stale_nuclei:
            f.status = FindingStatus.FIXED
            auto_closed += 1
        if auto_closed:
            db.commit()
            tenant_logger.info(f"Auto-closed {auto_closed} stale nuclei findings (not seen since {cutoff})")

    result = run_correlation(tenant_id, scan_run_id=scan_run_id)

    if isinstance(result, dict):
        return {
            "issues_created": result.get("issues_created", 0),
            "issues_updated": result.get("issues_updated", 0),
            "findings_processed": result.get("findings_processed", 0),
            "nuclei_auto_closed": auto_closed if current_run else 0,
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
    from app.models.enrichment import Certificate  # noqa: F401 — register with mapper before any Asset query
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
                    raw_evidence = finding.evidence or {}
                    if isinstance(raw_evidence, str):
                        try:
                            parsed = json.loads(raw_evidence)
                            evidence = parsed if isinstance(parsed, dict) else {}
                        except (json.JSONDecodeError, TypeError):
                            evidence = {}
                    elif isinstance(raw_evidence, dict):
                        evidence = raw_evidence
                    else:
                        evidence = {}
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
            if not isinstance(result, dict):
                tenant_logger.warning(
                    "Risk scoring returned non-dict for asset %d: %s",
                    asset.id,
                    type(result).__name__,
                )
                continue
            score = result.get("risk_score", 0.0)
            if "error" not in result:
                asset_scores.append(score)
                scores_computed += 1
        except Exception as exc:
            tenant_logger.error(
                "Risk scoring failed for asset %d: %s",
                asset.id,
                exc,
                exc_info=True,
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
