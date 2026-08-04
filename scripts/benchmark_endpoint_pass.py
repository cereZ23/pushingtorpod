#!/usr/bin/env python3
"""Versioned, reviewable tooling for the proposed endpoint nuclei pass.

Modes (default = the safe one):
  --dry-run    (default) print the PLAN only, with REDACTED targets (host + endpoint-shape, no
               query values). Runs NO nuclei and sends NO traffic.
  --reconcile  run ``nuclei -tl`` (list templates ONLY — no scan, no traffic) with ABSOLUTE template
               paths, and diff vs the reconciled applicable set to EXPLAIN nuclei's "Templates
               loaded" delta.

The ACTIVE benchmark is intentionally NOT implemented here yet. To be representative it must reuse
the pipeline's EXACT endpoint selection (in-scope + static-filter + priority + shape-dedup + per-host
cap, per --project) and the exact prod nuclei flags — i.e. the ``select_endpoint_targets`` extraction
that is the first task of Sprint 3. Reimplementing that selection here would diverge from the pass
and mis-predict its cost, so it is deliberately deferred (see Sprint-3 plan). --dry-run/--reconcile
send no traffic and are safe to run now.

Run inside the worker:  docker compose exec -T worker python scripts/benchmark_endpoint_pass.py --dry-run
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from datetime import datetime, timezone

DEFAULT_CAP = 200


def _reconciled_ruleset(tier: int):
    """(base_dir, roots, severity, exclude, snapshot, ruleset) via the exact pipeline machinery."""
    import yaml

    from app.config import settings
    from app.services.coverage_emit import _split_roots
    from app.services.rule_catalog import enumerate_nuclei_from_snapshot
    from app.services.rule_revision import resolve_nuclei_rule_snapshot
    from app.services.scan_policy import build_nuclei_policy_manifest
    from app.services.scan_tiers import http_stock_roots, tier_severity

    roots = http_stock_roots(tier)
    severity = tier_severity(tier)
    exclude = [t.strip() for t in str(getattr(settings, f"nuclei_exclude_tags_t{tier}", "")).split(",") if t.strip()]
    base_dir, split_roots = _split_roots(list(roots))
    snapshot = resolve_nuclei_rule_snapshot(base_dir, split_roots)
    manifest = build_nuclei_policy_manifest(
        nuclei_version="bench-tool",
        template_revision=snapshot.revision.digest,
        pass_name="http_stock",
        tier=tier,
        severity=list(severity),
        template_roots=split_roots,
        exclude_tags=exclude,
    )
    ruleset = enumerate_nuclei_from_snapshot(manifest, snapshot, parse_yaml=yaml.safe_load)
    return base_dir, split_roots, severity, exclude, snapshot, ruleset


def _endpoint_ids(tier: int):
    """(base_dir, ruleset, [endpoint_sensitive ids]) — classified via the app classifier."""
    import yaml

    from app.services.endpoint_template_classifier import ENDPOINT_SENSITIVE, classify_nuclei_template

    base_dir, _roots, _sev, _excl, snapshot, ruleset = _reconciled_ruleset(tier)
    docs = {}
    for f in snapshot.files:
        try:
            docs[f.relative_path] = yaml.safe_load(f.content)
        except Exception:
            docs[f.relative_path] = None
    ids = [
        r.detector_id
        for r in ruleset.rules
        if isinstance(docs.get(r.relative_path), dict)
        and classify_nuclei_template(docs[r.relative_path]).category == ENDPOINT_SENSITIVE
    ]
    return base_dir, ruleset, ids


def _scan_in_progress(db, tenant: int):
    """Fail-closed 'is anything scanning?' — ANY running scan_run (all tenants) OR a Celery
    run_scan_pipeline task. Celery unreachable → treated as busy (-1). Used to gate an active run."""
    from app.models.scanning import ScanRun

    db_running = db.query(ScanRun).filter(ScanRun.status.in_(("running", "RUNNING"))).count()
    celery_running: int
    try:
        from app.celery_app import celery

        active = celery.control.inspect(timeout=4).active() or {}
        celery_running = sum(
            1 for tasks in active.values() for t in tasks if "run_scan_pipeline" in (t.get("name") or "")
        )
    except Exception:
        celery_running = -1  # unknown → fail-closed (treat as busy)
    return db_running, celery_running


def _in_scope_endpoints(db, tenant: int, project: int | None, cap: int):
    """In-scope endpoint URLs (host_in_scope, same boundary as the pass), scoped to a project when
    given. NOTE: this does NOT reproduce the pass's static-filter/priority/shape-dedup/cap — that
    needs the Sprint-3 select_endpoint_targets extraction; used here only for the redacted preview."""
    from app.models.database import Asset
    from app.models.enrichment import Endpoint
    from app.services.scope_authorization import _active_authorizations
    from app.tasks.scanning import endpoint_shape_key, host_in_scope, normalize_host

    q = db.query(Asset).filter(Asset.tenant_id == tenant, Asset.is_active == True)
    if project is not None:
        q = q.filter(Asset.project_id == project)
    assets = q.all()
    authorised_hosts = {normalize_host(a.identifier) for a in assets}
    authorised_hosts.discard("")
    scope_entries = [
        e for auth in _active_authorizations(db, tenant, datetime.now(timezone.utc)) for e in (auth.scope_entries or [])
    ]
    asset_ids = [a.id for a in assets]
    urls, seen_shapes = [], set()
    eq = db.query(Endpoint.url).join(Asset, Asset.id == Endpoint.asset_id).filter(Asset.tenant_id == tenant)
    if asset_ids:
        eq = eq.filter(Endpoint.asset_id.in_(asset_ids))
    for (u,) in eq.all():
        if not u:
            continue
        from urllib.parse import urlparse

        host = urlparse(u).hostname or ""
        if not host_in_scope(host, authorised_hosts, scope_entries):
            continue
        shape = endpoint_shape_key(u)  # shared shape fn → redaction + rough dedup
        if shape in seen_shapes:
            continue
        seen_shapes.add(shape)
        urls.append(u)
    return urls[:cap]


def cmd_reconcile(tier: int):
    base_dir, roots, severity, exclude, _snap, ruleset = _reconciled_ruleset(tier)
    catalog_rel = {r.relative_path for r in ruleset.rules}
    abs_roots = [os.path.join(base_dir, r) for r in roots]  # fix 1: absolute paths, like the pipeline
    args = ["nuclei", "-tl", "-duc", "-silent"]
    for ar in abs_roots:
        args += ["-t", ar]
    args += ["-severity", ",".join(severity), "-etags", ",".join(exclude)]
    print("=== RECONCILE (nuclei -tl: LIST ONLY, no scan/traffic) ===")
    print("  " + " ".join(args) + "\n")
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=300)
    except subprocess.TimeoutExpired:
        print("nuclei -tl timed out (300s)")
        return 1
    listed = set()
    for ln in p.stdout.splitlines():
        ln = ln.strip()
        if ln:
            listed.add(ln.replace(base_dir.rstrip("/") + "/", ""))
    print(f"catalog applicable: {len(catalog_rel)}   nuclei -tl listed: {len(listed)}   exit={p.returncode}")
    only_catalog = sorted(catalog_rel - listed)
    print(f"\nin catalog but NOT loaded by nuclei ({len(only_catalog)})  <-- the delta to explain:")
    for rel in only_catalog[:60]:
        print("  " + rel)
    only_nuclei = sorted(listed - catalog_rel)
    print(f"\nloaded by nuclei but NOT in catalog ({len(only_nuclei)}):")
    for rel in only_nuclei[:20]:
        print("  " + rel)
    if p.stderr.strip():
        print("\n[stderr tail]")
        for ln in p.stderr.splitlines()[-6:]:
            print("  " + ln)
    return 0


def cmd_dry_run(tier: int, tenant: int, project: int | None, cap: int):
    from app.database import SessionLocal
    from app.tasks.scanning import endpoint_shape_key

    base_dir, ruleset, ep_ids = _endpoint_ids(tier)
    db = SessionLocal()
    try:
        targets = _in_scope_endpoints(db, tenant, project, cap)
        db_running, celery_running = _scan_in_progress(db, tenant)
    finally:
        db.close()
    busy = db_running > 0 or celery_running != 0
    print("=== DRY RUN (no nuclei, no traffic) ===")
    print(f"tier={tier} tenant={tenant} project={project}")
    print(f"applicable set (reconciled): {len(ruleset.rules)}")
    print(f"endpoint_sensitive templates: {len(ep_ids)}")
    print(f"in-scope endpoints (preview, shape-deduped): {len(targets)} (cap {cap})")
    print(
        f"scan-in-progress gate: db_running={db_running} celery_run_scan_pipeline={celery_running} -> active would {'REFUSE' if busy else 'proceed'}"
    )
    print("NOTE: preview targets are NOT the pass's exact selection (static-filter/priority/cap need")
    print("      the Sprint-3 select_endpoint_targets extraction). Values below are REDACTED.\n")
    print("first 8 REDACTED target shapes (host | id-collapsed path | param-names):")
    for u in targets[:8]:
        host, path, params = endpoint_shape_key(u)
        print(f"  {host} | {path} | params={list(params)}")
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--tier", type=int, default=1)
    ap.add_argument("--tenant", type=int, required=True, help="tenant id (required; no default)")
    ap.add_argument("--project", type=int, default=None)
    ap.add_argument("--cap", type=int, default=DEFAULT_CAP)
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--dry-run", action="store_true")
    g.add_argument("--reconcile", action="store_true")
    g.add_argument("--run", action="store_true")
    a = ap.parse_args()
    if a.reconcile:
        return cmd_reconcile(a.tier)
    if a.run:
        print(
            "ACTIVE benchmark is deferred to Sprint 3: it must reuse the pipeline's exact endpoint\n"
            "selection (select_endpoint_targets) + prod nuclei flags to be representative. Run\n"
            "--dry-run / --reconcile now (no traffic)."
        )
        return 2
    return cmd_dry_run(a.tier, a.tenant, a.project, a.cap)  # default


if __name__ == "__main__":
    sys.exit(main() or 0)
