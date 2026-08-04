#!/usr/bin/env python3
"""Sprint 1 report: classify the REAL Tier-1 nuclei templates as
host_only | endpoint_sensitive | unknown and print counts + per-root breakdown + samples.

Run it where the templates live (the runner container, or a local nuclei-templates clone):

    python scripts/classify_t1_templates.py /path/to/nuclei-templates
    # or set NUCLEI_TEMPLATES_DIR; default: ~/nuclei-templates

It walks the exact Tier-1 rule roots used by the pipeline (detection.py tier_templates[1]),
applies the T1 severity gate (critical/high/medium), classifies each template with the pure
app.services.endpoint_template_classifier, and reports. Read-only; no DB, no pipeline change.
"""

from __future__ import annotations

import os
import sys
from collections import Counter, defaultdict

import yaml

# T1 rule roots + severity gate — keep in sync with app/tasks/pipeline_phases/detection.py.
T1_ROOTS = (
    "http/cves/",
    "http/exposed-panels/",
    "http/takeovers/",
    "http/default-logins/",
    "http/exposures/",
    "http/honeypot/",
    "http/cnvd/",
    "http/technologies/wordpress/",
    "http/technologies/eol/",
    "ssl/",
)
T1_SEVERITIES = {"critical", "high", "medium"}


def _iter_template_files(base_dir: str):
    for root in T1_ROOTS:
        root_dir = os.path.join(base_dir, root)
        if not os.path.isdir(root_dir):
            print(f"  (missing root: {root})", file=sys.stderr)
            continue
        for dirpath, _dirs, names in os.walk(root_dir, followlinks=True):
            for name in names:
                if name.endswith((".yaml", ".yml")):
                    yield root, os.path.join(dirpath, name)


def main(base_dir: str) -> int:
    from app.services.endpoint_template_classifier import classify_nuclei_template

    by_cat = Counter()
    by_root_cat = defaultdict(Counter)
    reason_samples = defaultdict(list)
    skipped_severity = 0
    parse_errors = 0
    total = 0

    for root, path in _iter_template_files(base_dir):
        try:
            with open(path, "rb") as fh:
                doc = yaml.safe_load(fh)
        except Exception:
            parse_errors += 1
            continue
        if not isinstance(doc, dict):
            parse_errors += 1
            continue
        info = doc.get("info") or {}
        sev = str((info.get("severity") if isinstance(info, dict) else "") or "").strip().lower()
        if sev not in T1_SEVERITIES:
            skipped_severity += 1
            continue
        total += 1
        res = classify_nuclei_template(doc)
        by_cat[res.category] += 1
        by_root_cat[root][res.category] += 1
        if len(reason_samples[res.category]) < 8:
            reason_samples[res.category].append((doc.get("id", "?"), res.reason))

    print(f"\n=== Tier-1 template classification ({base_dir}) ===")
    print(f"templates in T1 roots @ crit/high/medium: {total}  (severity-skipped: {skipped_severity}, parse-errors: {parse_errors})\n")
    for cat in ("endpoint_sensitive", "host_only", "unknown"):
        n = by_cat.get(cat, 0)
        pct = (100.0 * n / total) if total else 0.0
        print(f"  {cat:20s} {n:6d}  ({pct:5.1f}%)")
    print("\n--- per root ---")
    for root in T1_ROOTS:
        c = by_root_cat.get(root)
        if not c:
            continue
        print(f"  {root:34s} endpoint={c.get('endpoint_sensitive', 0):4d}  host={c.get('host_only', 0):5d}  unknown={c.get('unknown', 0):4d}")
    print("\n--- sample reasons ---")
    for cat in ("endpoint_sensitive", "unknown"):
        print(f"  [{cat}]")
        for tid, reason in reason_samples.get(cat, []):
            print(f"    {tid}: {reason}")
    return 0


if __name__ == "__main__":
    base = sys.argv[1] if len(sys.argv) > 1 else os.environ.get(
        "NUCLEI_TEMPLATES_DIR", os.path.expanduser("~/nuclei-templates")
    )
    sys.exit(main(base))
