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

from app.repositories.coverage_repository import (
    CoverageRepository,
    CoverageWriteError,
    conservative_pass_status,
)
from app.services.rule_catalog import RuleCatalogError, enumerate_nuclei_from_snapshot
from app.services.rule_revision import (
    CompletedCommand,
    ResolvedRuleSnapshot,
    RuleResolutionError,
    resolve_nuclei_rule_snapshot,
    resolve_nuclei_version,
)
from app.services.scan_policy import ScanPolicyManifest, build_nuclei_policy_manifest

logger = logging.getLogger(__name__)


def _parse_yaml(data: bytes):
    """Injected YAML loader for detector enumeration (nuclei templates are single-doc)."""
    import yaml

    return yaml.safe_load(data)


def _persist_pass_catalog(
    repo: CoverageRepository,
    manifest: ScanPolicyManifest,
    snapshot: ResolvedRuleSnapshot,
    *,
    parse_yaml=_parse_yaml,
) -> None:
    """P-B: persist the applicable-detector catalog for this policy, derived from the SAME
    snapshot the revision came from (single read → no race if templates change mid-emit).

    Observational and idempotent per ``policy_hash``: skip if already catalogued, so a pass
    with thousands of templates re-parses them only the first time a policy is seen. Fail-open
    — a catalog gap can only ever PREVENT a future auto-close, never cause a wrong one, so a
    failure here must never break or slow the scan.
    """
    try:
        if repo.catalog_exists(manifest.policy_hash):
            return
        ruleset = enumerate_nuclei_from_snapshot(manifest, snapshot, parse_yaml=parse_yaml)
        repo.persist_catalog(ruleset)
        logger.info(
            "coverage: catalog for pass %s policy %s -> %d applicable detectors",
            manifest.pass_name,
            manifest.policy_hash[:12],
            len(ruleset.rules),
        )
    except (RuleCatalogError, RuleResolutionError, CoverageWriteError) as exc:
        logger.warning("coverage: catalog skipped for policy %s: %s", manifest.policy_hash[:12], exc)
    except Exception:  # noqa: BLE001 — observational: never break the scan
        logger.exception("coverage: catalog persist crashed for policy %s — emit continues", manifest.policy_hash)


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


def nuclei_result_outcome(result, *, exception_occurred: bool) -> tuple[bool, bool]:
    """Map a ``run_nuclei_scan()`` return value to ``(errored, truncated)`` for coverage.

    ``run_nuclei_scan`` does NOT always raise: an internal failure comes back as a dict
    (``{"status": "failed", "error": ...}``), and a pass with nothing to scan returns
    ``{"status": "no_urls"}`` or ``None``. Keying ``errored`` only off a raised exception
    would let a dict-reported failure be recorded as COVERED — a false "fixed" once the
    consumer lands. So anything that is not a clean ``{"status": "success"}`` dict counts
    as errored; only a successful pass can be truncated (else the outcome is FAILED).
    """
    if exception_occurred or not isinstance(result, dict):
        return True, False
    errored = result.get("status") != "success" or bool(result.get("error"))
    truncated = bool(result.get("truncated"))
    return errored, truncated


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
        # Single filesystem read: the revision AND the exact bytes, so policy identity and
        # the applicable-detector catalog observe the same snapshot (single-snapshot contract).
        snapshot = resolve_nuclei_rule_snapshot(base_dir, roots)
        manifest = build_nuclei_policy_manifest(
            nuclei_version=_cached_nuclei_version(),
            template_revision=snapshot.revision.digest,
            pass_name=pass_name,
            tier=tier,
            severity=list(severity),
            template_roots=roots,
            exclude_tags=exclude,
        )
        repo = CoverageRepository(db)
        repo.persist_policy(manifest)
        _persist_pass_catalog(repo, manifest, snapshot)
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


__all__ = ["emit_nuclei_pass_coverage", "nuclei_result_outcome", "NUCLEI_TEMPLATES_DIR"]
