"""Pass wiring — emit coverage-ledger verdicts from the live scan passes.

The coverage foundation (PR #95, Steps 2A–2D) built the schema and the writer but
left the ledger empty: nothing called it. This module is the bridge. Each nuclei
pass, at its boundary, calls :func:`emit_nuclei_pass_coverage` with what it just did
(which assets, which templates/severity, whether it truncated). We turn that into a
policy identity, persist it idempotently, and record one conservative verdict per
asset.

Design contract — **fail-open for the scan, fail-closed for auto-close**:
a ledger write must NEVER break or slow a scan, so every failure here is caught and
logged, not raised. The cost of a missed write is simply that the pass has no COVERED
verdict for those assets — and the coverage-aware auto-close only ever closes on a
COVERED verdict, so a missing write can only *prevent* a close, never cause a wrong
one.
"""

from __future__ import annotations

import logging
import subprocess
from functools import lru_cache
from typing import Iterable, Sequence

from sqlalchemy.orm import Session

from app.repositories.coverage_repository import CoverageRepository, conservative_pass_status
from app.services.rule_revision import (
    CompletedCommand,
    RuleResolutionError,
    resolve_nuclei_rule_revision,
    resolve_nuclei_version,
)
from app.services.scan_policy import build_nuclei_policy_manifest

logger = logging.getLogger(__name__)

# Where the stock nuclei templates live inside the worker image (see nuclei_service).
NUCLEI_TEMPLATES_DIR = "/home/appuser/nuclei-templates"


def _run_nuclei_version_cmd(argv) -> CompletedCommand:
    proc = subprocess.run(list(argv), capture_output=True, text=True, timeout=30)
    return CompletedCommand(returncode=proc.returncode, stdout=proc.stdout, stderr=proc.stderr)


@lru_cache(maxsize=1)
def _cached_nuclei_version() -> str:
    """Resolve the nuclei version once per worker process (it does not change mid-run)."""
    return resolve_nuclei_version(_run_nuclei_version_cmd)


def _split_roots(templates: Sequence[str]) -> tuple[str, list[str]]:
    """Return (base_dir, relative_roots) for the revision resolver.

    Stock passes name roots relative to the templates dir ("http/", "ssl/"); the custom
    pass names one absolute dir ("/app/custom-nuclei-templates/"). Absolute roots are
    resolved against "/" with the leading slash stripped so a single resolver call
    covers both without re-walking anything twice.
    """
    if any(t.startswith("/") for t in templates):
        return "/", [t.lstrip("/") for t in templates]
    return NUCLEI_TEMPLATES_DIR, list(templates)


def emit_nuclei_pass_coverage(
    db: Session,
    *,
    tenant_id: int,
    scan_run_id: int | None,
    pass_name: str,
    tier: int,
    asset_ids: Iterable[int],
    severity: Sequence[str],
    templates: Sequence[str],
    exclude_tags: Sequence[str] | str | None,
    ran: bool,
    errored: bool,
    truncated: bool,
) -> None:
    """Record one conservative coverage verdict per asset for a finished nuclei pass.

    Never raises: a coverage-ledger failure must not affect the scan. ``scan_run_id``
    None (manual/adhoc run) is a no-op — coverage is only meaningful inside a real run.
    """
    asset_ids = sorted({int(a) for a in asset_ids})
    if scan_run_id is None or not asset_ids:
        return
    try:
        exclude = (
            list(exclude_tags)
            if isinstance(exclude_tags, (list, tuple))
            else [t.strip() for t in str(exclude_tags).split(",") if t.strip()]
            if exclude_tags
            else []
        )
        base_dir, roots = _split_roots(list(templates))
        revision = resolve_nuclei_rule_revision(base_dir, roots).digest
        manifest = build_nuclei_policy_manifest(
            nuclei_version=_cached_nuclei_version(),
            template_revision=revision,
            pass_name=pass_name,
            tier=tier,
            severity=list(severity),
            template_roots=roots,
            exclude_tags=exclude,
        )
        repo = CoverageRepository(db)
        repo.persist_policy(manifest)
        status = conservative_pass_status(ran=ran, errored=errored, truncated=truncated)
        written = repo.record_pass_coverage(
            tenant_id=tenant_id,
            scan_run_id=scan_run_id,
            phase=manifest.phase,
            pass_name=pass_name,
            policy_hash=manifest.policy_hash,
            asset_ids=asset_ids,
            status=status,
        )
        logger.info(
            "coverage: pass %s -> %s on %d assets (run %s, policy %s)",
            pass_name,
            status.value,
            written,
            scan_run_id,
            manifest.policy_hash[:12],
        )
    except (RuleResolutionError, subprocess.SubprocessError, OSError) as exc:
        logger.warning("coverage emit skipped for pass %s (resolution failed): %s", pass_name, exc)
    except Exception:  # noqa: BLE001 — fail-open: the ledger must never break a scan
        logger.exception("coverage emit failed for pass %s (run %s) — scan unaffected", pass_name, scan_run_id)


__all__ = ["emit_nuclei_pass_coverage", "NUCLEI_TEMPLATES_DIR"]
