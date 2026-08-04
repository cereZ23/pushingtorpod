"""Detection phase implementations (Phases 8, 9, 9b, 10, 11, 12).

Phase 8:  Misconfiguration Detection
Phase 9:  Vulnerability Scanning (nuclei, + interactsh on Tier 3)
Phase 9b: DNSTwist Typosquatting Detection (Tier 3 only)
Phase 10: Correlation & Dedup
Phase 11: Risk Scoring
Phase 12: Diff, Alerting & Reporting
"""

from __future__ import annotations

import json
import logging
import time
from datetime import datetime, timezone

from app.models.risk import Relationship

logger = logging.getLogger(__name__)


def _phase_8_misconfig_detection(tenant_id, project_id, scan_run_id, db, tenant_logger):
    """Phase 8: Misconfiguration detection (50 controls)."""
    from app.tasks.misconfig import run_misconfig_detection

    result = run_misconfig_detection(tenant_id, scan_run_id=scan_run_id)

    if isinstance(result, dict):
        checked = result.get("assets_checked", 0)
        errors = result.get("errors", 0)
        return {
            "findings_created": result.get("findings_created", 0),
            "findings_updated": result.get("findings_updated", 0),
            "assets_checked": checked,
            "controls_executed": result.get("controls_executed", 0),
            "status": result.get("status", "unknown"),
            # Standard phase counters (errors are per-asset → real partial signal).
            "items_total": checked + errors,
            "items_succeeded": checked,
            "items_failed": errors,
            "items_skipped": 0,
        }
    return {"findings_created": 0, "status": "unknown"}


def _phase_8c_origin_discovery(tenant_id, project_id, scan_run_id, db, tenant_logger):
    """Phase 8c: Discover origin servers exposed behind a WAF/CDN."""
    from app.services.origin_discovery import run_origin_discovery

    result = run_origin_discovery(tenant_id, scan_run_id=scan_run_id)

    if isinstance(result, dict):
        return {
            "findings_created": result.get("findings_created", 0),
            "findings_updated": result.get("findings_updated", 0),
            "assets_checked": result.get("assets_checked", 0),
            "candidates_probed": result.get("candidates_probed", 0),
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
    from app.services.scan_tiers import tier_severity as _tier_severity

    severity = _tier_severity(scan_tier)

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

    # Dead-host pruning: soft-404 only catches hosts that return 200 on a random
    # path. Hosts that are 5xx-on-everything or timing out still pass and cost
    # nuclei up to `-mhe × -timeout` (~500s) of hanging sockets each, collapsing
    # throughput and eating the phase budget. Probe the survivors once (reusing the
    # concurrent probe machinery) and route the genuinely dead ones OUT of the heavy
    # CVE loop and INTO the light SSL/takeover pass below (so cert/takeover findings
    # are kept). Conservative: dropped only if EVERY probe URL fails. Reversible flag.
    from app.config import settings as _settings

    dead_asset_ids: set = set()
    if getattr(_settings, "nuclei_prune_dead_hosts", True) and all_assets:
        from app.utils.soft404 import detect_dead_hosts
        from collections import Counter

        survivor_ids = {a.id for a in all_assets}
        survivor_urls = {u: aid for u, aid in probe_urls.items() if aid in survivor_ids}
        dead_urls = detect_dead_hosts(
            list(survivor_urls.keys()),
            timeout=6.0,
            max_workers=30,
            min_status=getattr(_settings, "nuclei_dead_host_min_status", 500),
        )
        # A host is dead only when ALL its probe URLs (https + http) are dead.
        probes_per_asset = Counter(survivor_urls.values())
        dead_probes_per_asset = Counter(survivor_urls[u] for u in dead_urls)
        dead_asset_ids = {aid for aid, n in dead_probes_per_asset.items() if n == probes_per_asset[aid]}
        if dead_asset_ids:
            tenant_logger.info(
                f"Dead-host prune: {len(dead_asset_ids)} unresponsive/5xx hosts routed to the "
                f"light SSL/takeover pass (out of the heavy CVE loop) to protect the scan budget"
            )

    tenant_logger.info(
        f"Nuclei: {len(live_asset_ids)} assets with live HTTP, "
        f"{len(all_assets)} targets ({len(hostname_assets)} hostnames + {len(standalone_ips)} standalone IPs)"
    )

    # Split assets: CDN-fronted AND dead hosts get takeover/ssl checks only (a full
    # CVE scan would hit the CDN edge / a dead host, wasting the budget). Direct,
    # live, non-CDN hosts get the full CVE passes.
    direct_assets = [a for a in all_assets if not getattr(a, "cdn_name", None) and a.id not in dead_asset_ids]
    cdn_assets = [a for a in all_assets if getattr(a, "cdn_name", None) or a.id in dead_asset_ids]

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
    # Overall budget for a pass's target-batching, matched to the phase-9 group
    # wall-clock ({1:1800, 2:3600, 3:10800}s) with margin, so a batched pass
    # self-terminates before the phase timeout would mark it failed.
    _group_timeout = {1: 1800, 2: 3600, 3: 10800}.get(scan_tier, 3600)
    nuclei_group_budget = int(_group_timeout * 0.9)
    _phase9_start = time.monotonic()  # #3: recompute the budget from REMAINING wall-clock below

    # Tier-aware knobs that keep the T1 pass inside its budget WITHOUT dropping host/template
    # coverage: a tighter Katana endpoint cap (endpoints are ranked → only the low-value tail
    # is cut) and a shorter per-request timeout (i/o-timeout requests stop pinning a slot).
    endpoint_cap = (
        app_settings.nuclei_max_endpoints_per_host_t1 if scan_tier == 1 else app_settings.nuclei_max_endpoints_per_host
    )
    req_timeout = app_settings.nuclei_request_timeout_t1 if scan_tier == 1 else 10
    mhe_cap = app_settings.nuclei_max_host_errors_t1 if scan_tier == 1 else 50

    # Tier-aware exclude-tags (config-driven, per-env overridable).
    # KEY INSIGHT: what gets a host blacklisted by nuclei as "permanently
    # unresponsive" (i/o timeouts starving every later template) is the
    # PAYLOAD-SENDING families — intrusive, fuzz, dos, bruteforce, upload —
    # NOT the version/path-based CVE matchers that merely happen to carry a
    # class tag like `rce`/`sqli`. So T1 keeps the payload-senders excluded
    # (Azure-timeout safeguard, unchanged) but now ALLOWS the benign CVE
    # detection templates — that's the fix for "0 CVE on the default tier".
    # Discovery templates (SPF/DKIM/DMARC/CAA/DNSSEC/NS-takeover/wildcard) are
    # kept in the scan but post-processed into asset enrichment metadata, not
    # findings — see _store_discovery_as_enrichment().
    tier_exclude_tags = {
        1: app_settings.nuclei_exclude_tags_t1,
        2: app_settings.nuclei_exclude_tags_t2,
        3: app_settings.nuclei_exclude_tags_t3,
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
    # NOTE: custom/ removed — custom templates are now at /app/custom-nuclei-templates/
    # and appended automatically by nuclei_service.py (survives nuclei auto-update).
    from app.services.scan_tiers import http_stock_roots

    templates_for_scan = http_stock_roots(scan_tier)

    # DNS/network template config (Pass 3)
    # All tiers get network/ — exposed SSH, RDP, Redis, MongoDB etc. are
    # critical findings that an EASM must detect regardless of scan tier.
    dns_network_templates = {
        1: ["dns/", "network/"],
        2: ["dns/", "network/"],
        3: ["dns/", "network/"],
    }
    dns_net_tpls = dns_network_templates.get(scan_tier, ["dns/", "network/"])

    # Targets for DNS/network pass: domains + IPs/subdomains with non-HTTP services
    # (SSH, RDP, FTP, Redis, MySQL, etc.) that the HTTP pass wouldn't scan.
    non_http_ports = {
        22,
        21,
        23,
        25,
        110,
        143,
        389,
        445,
        993,
        995,
        1099,
        1433,
        1521,
        3306,
        3389,
        5432,
        5900,
        5984,
        6379,
        6380,
        8089,
        9200,
        11211,
        27017,
        50000,
    }
    ip_with_network_services = (
        db.query(Asset)
        .filter(
            Asset.tenant_id == tenant_id,
            Asset.type.in_([AssetType.IP, AssetType.SUBDOMAIN, AssetType.DOMAIN]),
            Asset.is_active == True,  # noqa: E712
            Asset.id.in_(
                db.query(Service.asset_id).filter(
                    Service.port.in_(non_http_ports),
                )
            ),
        )
        .all()
    )
    dns_net_asset_ids = list({a.id for a in all_active_domains} | {a.id for a in ip_with_network_services})

    if ip_with_network_services:
        tenant_logger.info(
            "Nuclei network pass: %d assets with non-HTTP services (SSH, RDP, DB, etc.)",
            len(ip_with_network_services),
        )

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
    from concurrent.futures import as_completed

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
            batch_deadline_seconds=nuclei_group_budget,
            scan_run_id=scan_run_id,
            max_endpoints_per_host=endpoint_cap,
            request_timeout=req_timeout,
            max_host_errors=mhe_cap,
            # PERF/quick-win: the full HTTP-stock set (~4347 templates) × Katana endpoints was the
            # phase-9 blowup (118k requests/batch → 27min truncation). Run stock on BASE assets
            # only; the cheap custom pass still scans endpoints. Endpoint CVE coverage returns with
            # the dedicated reduced endpoint pass (Traccia B). SAFETY: endpoint-derived findings are
            # excluded from the auto-close streak until then (see coverage_autoclose).
            include_katana_endpoints=False,
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
            batch_deadline_seconds=nuclei_group_budget,
            scan_run_id=scan_run_id,
            max_endpoints_per_host=endpoint_cap,
            request_timeout=req_timeout,
            max_host_errors=mhe_cap,
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
            batch_deadline_seconds=nuclei_group_budget,
            scan_run_id=scan_run_id,
            max_endpoints_per_host=endpoint_cap,
            request_timeout=req_timeout,
            max_host_errors=mhe_cap,
            # DNS/network templates never target HTTP paths — feeding Katana endpoints here is pure
            # waste (and was inflating this pass toward the per-batch timeout). Base assets only.
            include_katana_endpoints=False,
        )

    # Pass 0: custom templates FIRST (sequential, fast ~10s).
    # Custom templates get buried in the 5000+ stock template queue and
    # never execute before timeout. Running them as a dedicated pass
    # guarantees they always run on every host.
    # Coverage-ledger wiring: each pass records a conservative per-asset verdict so the
    # coverage-aware auto-close can prove a detector actually ran on an asset. Import
    # here (local, like the rest of this phase) and keep every call fail-open.
    from app.services.coverage_emit import emit_nuclei_pass_coverage, nuclei_result_outcome
    from app.services.scan_policy import (
        PASS_CDN_SSL_TAKEOVER,
        PASS_CUSTOM_HTTP,
        PASS_DNS_NETWORK,
        PASS_HTTP_STOCK,
    )

    if asset_ids:
        tenant_logger.info(
            f"Nuclei custom pass: {len(asset_ids)} direct assets, templates=['/app/custom-nuclei-templates/']"
        )
        custom_errored = False
        custom_result = None
        try:
            custom_result = run_nuclei_scan(
                tenant_id,
                asset_ids,
                severity=["critical", "high", "medium", "low"],
                templates=["/app/custom-nuclei-templates/"],
                rate_limit=rate_limit,
                concurrency=concurrency,
                timeout=600,  # 10 min — 12 custom templates × ~130 targets + katana endpoints
                exclude_tags="",  # empty string = no exclusions for our own templates
                scan_run_id=scan_run_id,
                max_endpoints_per_host=endpoint_cap,
                request_timeout=req_timeout,
                max_host_errors=mhe_cap,
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
            custom_errored = True
            tenant_logger.error(f"Nuclei custom pass failed: {exc}")
        # A dict-reported failure ({"status":"failed"}) never raises — derive the outcome
        # from the result contract, not just the except path, or it becomes a false COVERED.
        custom_failed, custom_truncated = nuclei_result_outcome(custom_result, exception_occurred=custom_errored)
        emit_nuclei_pass_coverage(
            db,
            tenant_id=tenant_id,
            scan_run_id=scan_run_id,
            pass_name=PASS_CUSTOM_HTTP,
            tier=scan_tier,
            asset_ids=asset_ids,
            severity=["critical", "high", "medium", "low"],
            templates=["/app/custom-nuclei-templates/"],
            exclude_tags="",
            ran=True,
            errored=custom_failed,
            truncated=custom_truncated,
        )

    # #3: the parallel passes' batching budget must come from the wall-clock REMAINING after
    # the (sequential) custom pass — not the full group_timeout — or custom_time + budget +
    # a batch overshoot exceeds the phase wall-clock and the phase HARD-FAILS instead of
    # truncating. Recompute here, after the custom pass, before the parallel passes read it.
    _elapsed = time.monotonic() - _phase9_start
    nuclei_group_budget = max(120, int((_group_timeout - _elapsed) * 0.9))
    tenant_logger.info(
        f"Nuclei parallel-pass budget: {nuclei_group_budget}s "
        f"({int(_elapsed)}s of {_group_timeout}s phase budget already spent by the custom pass)"
    )

    # Run stock passes in PARALLEL — pass 1 (HTTP) and pass 3 (DNS/network) target
    # different protocols so they don't compete for bandwidth. The HTTP-live
    # filter on pass 1 eliminated the 88% error rate that made parallel
    # execution problematic before.
    from app.core.concurrency import ContextThreadPoolExecutor

    passes = {"pass_1": _run_pass_1, "pass_2": _run_pass_2, "pass_3": _run_pass_3}
    active_passes = {
        k: fn
        for k, fn in passes.items()
        if ((k == "pass_1" and asset_ids) or (k == "pass_2" and cdn_asset_ids) or (k == "pass_3" and dns_net_asset_ids))
    }

    tenant_logger.info(f"Nuclei: running {len(active_passes)} passes concurrently: {', '.join(active_passes.keys())}")

    # Per-pass coverage metadata (policy identity inputs), keyed by the internal pass id.
    coverage_meta = {
        "pass_1": (PASS_HTTP_STOCK, asset_ids, severity, templates_for_scan, exclude_tags),
        "pass_2": (
            PASS_CDN_SSL_TAKEOVER,
            cdn_asset_ids,
            ["critical", "high", "medium"],
            ["http/takeovers/", "ssl/"],
            tier_exclude_tags[1],
        ),
        "pass_3": (
            PASS_DNS_NETWORK,
            dns_net_asset_ids,
            ["critical", "high", "medium", "low", "info"],
            dns_net_tpls,
            exclude_tags,
        ),
    }

    truncated_passes: list[str] = []
    with ContextThreadPoolExecutor(max_workers=len(active_passes) or 1) as executor:
        futures = {executor.submit(fn): name for name, fn in active_passes.items()}
        for future in as_completed(futures):
            pass_name = futures[future]
            pass_errored = False
            result = None
            try:
                result = future.result()
                if isinstance(result, dict):
                    total_created += result.get("findings_created", 0)
                    total_updated += result.get("findings_updated", 0)
                    total_scanned += result.get("assets_scanned", 0)
                    total_urls += result.get("urls_scanned", 0)
                    tenant_logger.info(f"Nuclei {pass_name} complete: {result.get('findings_created', 0)} findings")
            except Exception as exc:
                pass_errored = True
                tenant_logger.error(f"Nuclei {pass_name} failed: {exc}")
            # A dict-reported failure ({"status":"failed"}) never raises — derive the outcome
            # from the result contract, not just the except path, or it becomes a false COVERED.
            pass_failed, pass_truncated = nuclei_result_outcome(result, exception_occurred=pass_errored)
            if pass_truncated:
                truncated_passes.append(pass_name)
            meta = coverage_meta.get(pass_name)
            if meta:
                policy_pass, pass_assets, pass_sev, pass_tpls, pass_excl = meta
                emit_nuclei_pass_coverage(
                    db,
                    tenant_id=tenant_id,
                    scan_run_id=scan_run_id,
                    pass_name=policy_pass,
                    tier=scan_tier,
                    asset_ids=pass_assets,
                    severity=pass_sev,
                    templates=pass_tpls,
                    exclude_tags=pass_excl,
                    ran=True,
                    errored=pass_failed,
                    truncated=pass_truncated,
                )

    if truncated_passes:
        tenant_logger.warning(
            f"Nuclei coverage INCOMPLETE: passes {truncated_passes} hit their timeout; "
            "some templates did not run (partial findings were salvaged)"
        )

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
        # Incomplete coverage is recorded on the phase result so a truncated scan
        # is visible (never silently treated as a full run).
        "coverage_complete": not truncated_passes,
        "truncated_passes": truncated_passes,
    }


def _phase_9b_dnstwist(tenant_id, project_id, scan_run_id, db, tenant_logger):
    """Phase 9b: DNSTwist typosquatting / domain permutation detection.

    Only runs on Tier 3 (Aggressive) scans. Generates domain permutations
    for all root domains belonging to the tenant and checks DNS registration
    to detect potential phishing / brand abuse domains.
    """
    from app.tasks.dnstwist_scan import run_dnstwist

    tenant_logger.info("Starting DNSTwist typosquatting scan")

    # run_dnstwist is a Celery task, but we call the underlying function
    # directly (synchronously) within the pipeline to keep orchestration
    # in one place and avoid double-queuing.
    result = run_dnstwist(tenant_id=tenant_id, domain_list=None)

    if isinstance(result, dict):
        return {
            "findings_created": result.get("findings_created", 0),
            "domains_scanned": result.get("domains_scanned", 0),
        }
    return {"findings_created": 0, "domains_scanned": 0}


def _phase_10_correlation(tenant_id, project_id, scan_run_id, db, tenant_logger):
    """Phase 10: Correlation & deduplication.

    Runs the coverage-aware auto-close in SHADOW only — the legacy tenant-wide nuclei/misconfig
    closers are DISABLED (no real status changes) until the consumer leaves shadow. See below.
    """
    from app.tasks.correlation import run_correlation

    # Discovery health is still evaluated + persisted here (idempotent) for dashboards and the
    # shadow consumer; it no longer gates a real close (the legacy closers are disabled below).
    from app.services.discovery_health import evaluate_and_persist_discovery_health

    health = evaluate_and_persist_discovery_health(db, tenant_id, project_id, scan_run_id)

    # Coverage-aware auto-close SHADOW (P-C): runs BEFORE the old closers so it observes the
    # FULL open set. Persists each finding's miss-streak + run attribution; it NEVER changes
    # finding status (no real close). Fail-open WITH rollback so a shadow error can't leave a
    # partially-written transaction to corrupt the rest of the phase.
    try:
        from app.services.coverage_autoclose import shadow_auto_close

        shadow = shadow_auto_close(db, tenant_id=tenant_id, project_id=project_id, scan_run_id=scan_run_id)
        tenant_logger.info(
            f"Coverage auto-close shadow: {shadow.get('decisions')} would_close={len(shadow.get('would_close_ids', []))}"
        )
    except Exception:
        db.rollback()
        tenant_logger.warning("Coverage auto-close shadow failed (non-fatal)", exc_info=True)

    # Legacy tenant-wide auto-close DISABLED (2026-08-03). Both old closers FIXED any
    # nuclei/misconfig finding merely absent for 48h / 5min — tenant-wide, NOT coverage- or
    # endpoint-aware. Now that HTTP-stock scans base URLs only (endpoint CVE coverage deferred to
    # the dedicated endpoint pass — Traccia B), an endpoint finding is no longer re-detected and the
    # old closer would false-FIX it after the grace period. Until the coverage-aware consumer
    # (shadow, above) leaves shadow we auto-close NOTHING — a false-open is strictly safer than a
    # false-fixed. Counters kept at 0 for the phase-10 stats/response contract.
    auto_closed = 0
    misconfig_closed = 0
    tenant_logger.info(
        "Legacy tenant-wide auto-close disabled; coverage-aware consumer running in shadow "
        "(discovery auto_close_allowed=%s)",
        health.auto_close_allowed,
    )

    # Collapse network/service findings (FTP/SSH/...) detected on multiple
    # hostnames that resolve to the same IP into one — they're one real service.
    # Runs before correlation so issues form from the deduped set.
    from app.tasks.correlation import dedup_network_findings_by_ip

    dedup_network_findings_by_ip(tenant_id, db, tenant_logger)

    result = run_correlation(tenant_id, scan_run_id=scan_run_id)

    if isinstance(result, dict):
        return {
            "issues_created": result.get("issues_created", 0),
            "issues_updated": result.get("issues_updated", 0),
            "findings_processed": result.get("findings_processed", 0),
            # Legacy closers disabled → always 0 (kept for the response contract).
            "nuclei_auto_closed": auto_closed,
            "misconfig_auto_closed": misconfig_closed,
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
    # 2b. Score each active service (persisted for global sort/filter + UI).
    # ------------------------------------------------------------------
    try:
        from app.services.risk_scoring import RiskScoringEngine
        from app.models.database import Service, FindingStatus

        engine = RiskScoringEngine(db)
        asset_ids = [a.id for a in assets]
        identifier_by_asset = {a.id: a.identifier for a in assets}
        services = db.query(Service).filter(Service.asset_id.in_(asset_ids)).all() if asset_ids else []

        # Batch the assets' OPEN findings once (N+1-free).
        svc_findings_by_asset: dict = {}
        if asset_ids:
            for f in (
                db.query(Finding).filter(Finding.asset_id.in_(asset_ids), Finding.status == FindingStatus.OPEN).all()
            ):
                svc_findings_by_asset.setdefault(f.asset_id, []).append(f)

        for svc in services:
            try:
                r = engine.calculate_service_risk(
                    svc,
                    asset_findings=svc_findings_by_asset.get(svc.asset_id, []),
                    asset_identifier=identifier_by_asset.get(svc.asset_id, ""),
                )
                svc.risk_score = r["risk_score"]
                svc.risk_level = r["risk_level"]
                svc.risk_components = r["components"]
            except Exception as exc:
                tenant_logger.warning("Service risk scoring failed for service %d: %s", svc.id, exc)
        db.flush()
        tenant_logger.info("Service risk scored for %d services", len(services))
    except Exception as exc:
        tenant_logger.error("Service risk scoring pass failed: %s", exc, exc_info=True)

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
