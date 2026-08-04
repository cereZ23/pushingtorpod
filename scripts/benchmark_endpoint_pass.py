#!/usr/bin/env python3
"""Versioned, reviewable benchmark/reconcile tool for the proposed endpoint nuclei pass.

Modes (default = the safe one):
  --dry-run    (default) print the PLAN only — endpoint templates, authorised targets, timeout,
               rate, concurrency. Runs NO nuclei and sends NO traffic.
  --reconcile  run ``nuclei -tl`` (list templates ONLY — no scan, no traffic) for the T1 policy and
               diff it against the reconciled applicable set to EXPLAIN why the catalog count and
               nuclei's "Templates loaded" differ.
  --run        ACTIVE benchmark: run the endpoint_sensitive templates against AUTHORISED endpoints
               and time nuclei. Refuses to start if a scan is active. Secure temp dir. No DB writes.

Safety: targets are the tenant's IN-SCOPE endpoints only (host is a pass asset OR under an ACTIVE
ScanAuthorization — the SAME boundary as the real pass, via host_in_scope). Read-only: never writes
findings/coverage. Run inside the worker container:
    docker compose exec -T worker python scripts/benchmark_endpoint_pass.py --dry-run
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from urllib.parse import urlparse

DEFAULT_TENANT = 3  # curci
TEMPLATES_DIR = "/home/appuser/nuclei-templates"
DEFAULT_CAP = 200
TIMEOUT = 6
RATE = 300
CONCURRENCY = 25


def _reconciled_ruleset(tier: int):
    """Return (roots, severity, exclude, snapshot, ruleset) via the exact pipeline machinery."""
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


def _endpoint_templates(tier: int):
    """(base_dir, roots, severity, exclude, [abs template paths], [ids], total_applicable)."""
    import yaml

    from app.services.endpoint_template_classifier import ENDPOINT_SENSITIVE, classify_nuclei_template

    base_dir, roots, severity, exclude, snapshot, ruleset = _reconciled_ruleset(tier)
    docs = {}
    for f in snapshot.files:
        try:
            docs[f.relative_path] = yaml.safe_load(f.content)
        except Exception:
            docs[f.relative_path] = None
    paths, ids = [], []
    for rule in ruleset.rules:
        d = docs.get(rule.relative_path)
        if isinstance(d, dict) and classify_nuclei_template(d).category == ENDPOINT_SENSITIVE:
            paths.append(os.path.join(base_dir, rule.relative_path))
            ids.append(rule.detector_id)
    return base_dir, roots, severity, exclude, paths, ids, len(ruleset.rules)


def _active_scan_running(db, tenant: int) -> bool:
    from app.models.scanning import ScanRun

    return db.query(ScanRun).filter(ScanRun.tenant_id == tenant, ScanRun.status.in_(("running", "RUNNING"))).count() > 0


def _authorised_endpoints(db, tenant: int, cap: int):
    """The tenant's IN-SCOPE endpoint URLs, via the same boundary as the real nuclei pass."""
    from app.models.database import Asset
    from app.models.enrichment import Endpoint
    from app.services.scope_authorization import _active_authorizations
    from app.tasks.scanning import host_in_scope, normalize_host

    assets = db.query(Asset).filter(Asset.tenant_id == tenant, Asset.is_active == True).all()
    authorised_hosts = {normalize_host(a.identifier) for a in assets}
    authorised_hosts.discard("")
    scope_entries = [
        e for auth in _active_authorizations(db, tenant, datetime.now(timezone.utc)) for e in (auth.scope_entries or [])
    ]
    urls, seen = [], set()
    for (u,) in (
        db.query(Endpoint.url).join(Asset, Asset.id == Endpoint.asset_id).filter(Asset.tenant_id == tenant).all()
    ):
        if not u or u in seen:
            continue
        host = urlparse(u).hostname or ""
        if host_in_scope(host, authorised_hosts, scope_entries):
            seen.add(u)
            urls.append(u)
    return urls[:cap]


def cmd_dry_run(tier: int, tenant: int, cap: int):
    from app.database import SessionLocal

    _bd, roots, severity, exclude, paths, ids, total = _endpoint_templates(tier)
    db = SessionLocal()
    try:
        targets = _authorised_endpoints(db, tenant, cap)
        active = _active_scan_running(db, tenant)
    finally:
        db.close()
    print("=== DRY RUN (no nuclei, no traffic) ===")
    print(f"tier={tier} tenant={tenant}")
    print(f"applicable set (reconciled): {total}")
    print(f"endpoint_sensitive templates: {len(paths)}")
    print(f"authorised in-scope targets:  {len(targets)} (cap {cap})")
    print(f"active scan running for tenant: {active}  -> --run would {'REFUSE' if active else 'proceed'}")
    print(f"nuclei flags: -timeout {TIMEOUT} -rl {RATE} -c {CONCURRENCY} -duc -silent -jsonl (read-only)")
    print(f"est. request upper bound (templates x targets): {len(paths) * len(targets)}")
    print("\nfirst 5 templates:")
    for p in paths[:5]:
        print("  " + p)
    print("first 5 targets:")
    for t in targets[:5]:
        print("  " + t)


def cmd_reconcile(tier: int):
    base_dir, roots, severity, exclude, _snap, ruleset = _reconciled_ruleset(tier)
    catalog_rel = {r.relative_path for r in ruleset.rules}
    args = [
        "nuclei",
        "-tl",
        "-duc",
        "-silent",
        "-t",
        ",".join(roots),
        "-severity",
        ",".join(severity),
        "-etags",
        ",".join(exclude),
    ]
    print("=== RECONCILE (nuclei -tl: LIST ONLY, no scan/traffic) ===")
    print("  " + " ".join(args) + "\n")
    p = subprocess.run(args, capture_output=True, text=True, timeout=300)
    listed = set()
    for ln in p.stdout.splitlines():
        ln = ln.strip()
        if not ln:
            continue
        rel = ln.replace(base_dir.rstrip("/") + "/", "")
        listed.add(rel)
    print(f"catalog applicable: {len(catalog_rel)}   nuclei -tl listed: {len(listed)}   exit={p.returncode}")
    only_catalog = sorted(catalog_rel - listed)
    only_nuclei = sorted(listed - catalog_rel)
    print(f"\nin catalog but NOT loaded by nuclei ({len(only_catalog)}):")
    for rel in only_catalog[:40]:
        print("  " + rel)
    print(f"\nloaded by nuclei but NOT in catalog ({len(only_nuclei)}):")
    for rel in only_nuclei[:40]:
        print("  " + rel)
    if p.stderr.strip():
        print("\n[stderr tail]")
        for ln in p.stderr.splitlines()[-5:]:
            print("  " + ln)


def cmd_run(tier: int, tenant: int, cap: int):
    from app.database import SessionLocal

    _bd, roots, severity, exclude, paths, ids, total = _endpoint_templates(tier)
    db = SessionLocal()
    try:
        if _active_scan_running(db, tenant):
            print("REFUSING: a scan is currently running for this tenant (would compete / confuse).")
            return 2
        targets = _authorised_endpoints(db, tenant, cap)
    finally:
        db.close()
    if not paths or not targets:
        print(f"nothing to run (templates={len(paths)}, targets={len(targets)})")
        return 1
    tmpdir = tempfile.mkdtemp(prefix="ep_bench_")
    target_file = os.path.join(tmpdir, "targets.txt")
    with open(target_file, "w") as fh:
        fh.write("\n".join(targets))
    args = [
        "nuclei",
        "-t",
        ",".join(paths),
        "-l",
        target_file,
        "-timeout",
        str(TIMEOUT),
        "-rl",
        str(RATE),
        "-c",
        str(CONCURRENCY),
        "-duc",
        "-silent",
        "-no-color",
        "-jsonl",
        "-stats",
        "-si",
        "20",
    ]
    print("=== ACTIVE BENCHMARK ===")
    print(f"templates={len(paths)} targets={len(targets)} timeout={TIMEOUT} rate={RATE} c={CONCURRENCY}")
    t0 = time.time()
    p = subprocess.run(args, capture_output=True, text=True, timeout=1800)
    dt = time.time() - t0
    matches = sum(1 for ln in p.stdout.splitlines() if ln.strip().startswith("{"))
    req_lines = [ln for ln in p.stderr.splitlines() if "request" in ln.lower() or "matched" in ln.lower()]
    print(f"\nduration={dt:.1f}s  exit={p.returncode}  matches={matches}")
    for ln in req_lines[-6:]:
        print("  " + ln)
    try:
        os.unlink(target_file)
        os.rmdir(tmpdir)
    except OSError:
        pass
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--tier", type=int, default=1)
    ap.add_argument("--tenant", type=int, default=DEFAULT_TENANT)
    ap.add_argument("--cap", type=int, default=DEFAULT_CAP)
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--dry-run", action="store_true")
    g.add_argument("--reconcile", action="store_true")
    g.add_argument("--run", action="store_true")
    a = ap.parse_args()
    if a.reconcile:
        return cmd_reconcile(a.tier)
    if a.run:
        return cmd_run(a.tier, a.tenant, a.cap)
    return cmd_dry_run(a.tier, a.tenant, a.cap)  # default = dry-run


if __name__ == "__main__":
    sys.exit(main() or 0)
