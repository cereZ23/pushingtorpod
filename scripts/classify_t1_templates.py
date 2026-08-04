#!/usr/bin/env python3
"""Sprint-1 report (RECONCILED) — classify the EXACT nuclei applicable set for a tier.

Unlike a filesystem walk, this reproduces the pass's applicable set through the SAME machinery the
pipeline uses: shared roots+severity (app.services.scan_tiers) + exclude-tags (settings) →
resolve_nuclei_rule_snapshot → build_nuclei_policy_manifest → enumerate_nuclei_from_snapshot. So the
count matches nuclei's "Templates loaded" and can never diverge from detection.py. Each applicable
template is then classified by app.services.endpoint_template_classifier.

Run inside the worker container (has the app + PyYAML + the pinned templates):
    docker compose exec -T worker python scripts/classify_t1_templates.py [tier] [out.tsv]

Read-only; no DB writes, no pipeline change. Prints reconciled counts + a deterministic digest +
the endpoint_sensitive id list, and (optionally) writes the full id/category/reason/digest TSV.
"""

from __future__ import annotations

import hashlib
import sys
from collections import Counter, defaultdict

import yaml


def main(tier: int, out_path: str | None) -> int:
    from app.config import settings
    from app.services.coverage_emit import _split_roots
    from app.services.endpoint_template_classifier import (
        ENDPOINT_SENSITIVE,
        HOST_ONLY,
        UNKNOWN,
        classify_nuclei_template,
    )
    from app.services.rule_catalog import enumerate_nuclei_from_snapshot
    from app.services.rule_revision import resolve_nuclei_rule_snapshot
    from app.services.scan_policy import build_nuclei_policy_manifest
    from app.services.scan_tiers import http_stock_roots, nuclei_relevant_flags, tier_severity

    roots = http_stock_roots(tier)
    severity = tier_severity(tier)
    exclude_raw = getattr(settings, f"nuclei_exclude_tags_t{tier}", "")
    exclude = [t.strip() for t in str(exclude_raw).split(",") if t.strip()]

    base_dir, split_roots = _split_roots(list(roots))
    snapshot = resolve_nuclei_rule_snapshot(base_dir, split_roots)
    manifest = build_nuclei_policy_manifest(
        nuclei_version="report-tool",  # only affects policy_hash, not the applicable set
        template_revision=snapshot.revision.digest,
        pass_name="http_stock",
        tier=tier,
        severity=list(severity),
        template_roots=split_roots,
        exclude_tags=exclude,
        relevant_flags=nuclei_relevant_flags(interactsh_enabled=False),
    )
    ruleset = enumerate_nuclei_from_snapshot(manifest, snapshot, parse_yaml=yaml.safe_load)

    # Parse every snapshot file once so we can classify each applicable rule by its doc.
    docs = {}
    for f in snapshot.files:
        try:
            docs[f.relative_path] = yaml.safe_load(f.content)
        except Exception:
            docs[f.relative_path] = None

    by_cat = Counter()
    by_root = defaultdict(Counter)
    unk = Counter()
    rows = []  # (id, category, reason, digest)
    for rule in ruleset.rules:
        doc = docs.get(rule.relative_path)
        res = classify_nuclei_template(doc) if isinstance(doc, dict) else None
        cat = res.category if res else UNKNOWN
        reason = res.reason if res else "template not re-parseable"
        by_cat[cat] += 1
        by_root[rule.relative_path.split("/")[0]][cat] += 1
        if cat == UNKNOWN:
            unk[reason] += 1
        rows.append((rule.detector_id, cat, reason, rule.content_digest))

    rows.sort()
    total = len(rows)
    digest = hashlib.sha256("\n".join(f"{i}\t{c}" for i, c, _r, _d in rows).encode()).hexdigest()[:16]

    print(f"\n=== Tier-{tier} RECONCILED applicable-set classification ===")
    print(f"applicable detectors (enumerate_nuclei_from_snapshot): {total}")
    print(f"  roots={split_roots}")
    print(f"  severity={severity}  exclude_tags={exclude}")
    print(f"  reconcile vs nuclei 'Templates loaded'.  classification digest: {digest}\n")
    for c in (ENDPOINT_SENSITIVE, HOST_ONLY, UNKNOWN):
        n = by_cat.get(c, 0)
        print(f"  {c:20s} {n:6d}  ({100.0 * n / total if total else 0:5.1f}%)")
    print("\n--- per top-level root ---")
    for root in sorted(by_root):
        c = by_root[root]
        print(
            f"  {root:12s} endpoint={c.get(ENDPOINT_SENSITIVE, 0):4d} host={c.get(HOST_ONLY, 0):5d} unknown={c.get(UNKNOWN, 0):4d}"
        )
    print("\n--- unknown reasons ---")
    for reason, n in unk.most_common():
        print(f"  {n:5d}  {reason}")

    endpoint_ids = sorted(i for i, c, _r, _d in rows if c == ENDPOINT_SENSITIVE)
    print(f"\n--- endpoint_sensitive ids ({len(endpoint_ids)}) ---")
    for tid in endpoint_ids:
        print(f"  {tid}")

    if out_path:
        with open(out_path, "w") as fh:
            fh.write(f"# tier={tier} total={total} digest={digest}\n")
            fh.write("template_id\tcategory\treason\tcontent_digest\n")
            for i, c, r, d in rows:
                fh.write(f"{i}\t{c}\t{r}\t{d}\n")
        print(f"\nfull classification written to {out_path}")
    return 0


if __name__ == "__main__":
    _tier = int(sys.argv[1]) if len(sys.argv) > 1 else 1
    _out = sys.argv[2] if len(sys.argv) > 2 else None
    sys.exit(main(_tier, _out))
