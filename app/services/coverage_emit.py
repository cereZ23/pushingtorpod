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
from app.services.rule_catalog import (
    RuleCatalogError,
    enumerate_misconfig_from_snapshot,
    enumerate_nuclei_from_snapshot,
)
from app.services.rule_revision import (
    CompletedCommand,
    MisconfigRuleSnapshot,
    ResolvedRuleSnapshot,
    RuleResolutionError,
    resolve_misconfig_rule_snapshot,
    resolve_nuclei_rule_snapshot,
    resolve_nuclei_version,
)
from app.services.scan_policy import (
    PASS_MISCONFIG,
    ScanPolicyManifest,
    build_misconfig_policy_manifest,
    build_nuclei_policy_manifest,
)

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

    Observational and idempotent per ``policy_hash``: re-enumeration (parsing thousands of
    templates) is skipped ONLY when the catalog is stamped built AND its live rows still match
    that stamp's ``(count, digest)`` — mere row presence is not accepted as completeness, so a
    partial or tampered catalog is rebuilt/flagged rather than trusted. Fail-open — a catalog
    gap can only ever PREVENT a future auto-close, never cause a wrong one, so a failure here
    must never break or slow the scan. (A partial/tampered catalog is already fail-closed at
    read time: ``applicable_detector_ids`` returns the empty set unless the live fingerprint
    still equals the stamped build, so a corrupt catalog stays non-authorising for every
    consumer.)
    """
    try:
        build = repo.catalog_build(manifest.policy_hash)
        if build is not None and repo.catalog_fingerprint(manifest.policy_hash) == build:
            return  # fully built AND the live rows still match the stamped (count, digest)
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


# --- misconfig (phase 8, built-in engine) ------------------------------------


def _app_version() -> str:
    """The application release identity used as the misconfig engine_version."""
    from app.config import settings

    return settings.app_version


def _persist_misconfig_catalog(
    repo: CoverageRepository,
    manifest: ScanPolicyManifest,
    snapshot: MisconfigRuleSnapshot,
) -> None:
    """Persist the applicable misconfig control catalog (detector_id = control_id) from the
    same snapshot the revision came from. Observational + fail-open; the control set is tiny
    (~dozens), so it just re-enumerates + persists each time (idempotent, stamps the build
    fingerprint like the nuclei path). A failure only ever prevents a future close."""
    try:
        ruleset = enumerate_misconfig_from_snapshot(manifest, snapshot)
        repo.persist_catalog(ruleset)
        logger.info(
            "coverage: misconfig catalog policy %s -> %d applicable controls",
            manifest.policy_hash[:12],
            len(ruleset.rules),
        )
    except (RuleCatalogError, RuleResolutionError, CoverageWriteError) as exc:
        logger.warning("coverage: misconfig catalog skipped for policy %s: %s", manifest.policy_hash[:12], exc)
    except Exception:  # noqa: BLE001 — observational: never break the scan
        logger.exception("coverage: misconfig catalog crashed for policy %s — emit continues", manifest.policy_hash)


def emit_misconfig_pass_coverage(
    db: Session,
    *,
    tenant_id: int,
    scan_run_id: int | None,
    tier: int,
    asset_ids: Iterable[int],
    controls: Sequence[dict],
    ran: bool,
    errored: bool,
    partial: bool,
) -> None:
    """Record one conservative coverage verdict per checked asset for the misconfig pass.

    Mirrors ``emit_nuclei_pass_coverage`` for the built-in engine (phase 8): identity +
    catalog + coverage all derive from a single active-control snapshot. ``asset_ids`` are
    the assets the pass ACTUALLY checked (not the whole tenant). Never raises — a ledger
    failure must not affect the scan; ``scan_run_id`` None or no assets → no-op.

    Status is conservative (``completed → COVERED, partial → PARTIAL, errored → FAILED``),
    so an error or partial run is never recorded as COVERED.
    """
    asset_ids = sorted({int(a) for a in asset_ids})
    if scan_run_id is None or not asset_ids:
        return
    try:
        snapshot = resolve_misconfig_rule_snapshot(controls)
        manifest = build_misconfig_policy_manifest(
            app_version=_app_version(),
            rule_revision=snapshot.revision,
            tier=tier,
        )
        repo = CoverageRepository(db)
        repo.persist_policy(manifest)
        _persist_misconfig_catalog(repo, manifest, snapshot)
        status = conservative_pass_status(ran=ran, errored=errored, truncated=partial)
        written = repo.record_pass_coverage(
            tenant_id=tenant_id,
            scan_run_id=scan_run_id,
            phase=manifest.phase,
            pass_name=PASS_MISCONFIG,
            policy_hash=manifest.policy_hash,
            asset_ids=asset_ids,
            status=status,
        )
        logger.info(
            "coverage: misconfig pass -> %s on %d assets (run %s, policy %s)",
            status.value,
            written,
            scan_run_id,
            manifest.policy_hash[:12],
        )
    except (RuleResolutionError, RuleCatalogError, CoverageWriteError) as exc:
        logger.warning("coverage: misconfig emit skipped (run %s): %s", scan_run_id, exc)
    except Exception:  # noqa: BLE001 — fail-open: the ledger must never break a scan
        logger.exception("coverage: misconfig emit failed (run %s) — scan unaffected", scan_run_id)


__all__ = [
    "emit_nuclei_pass_coverage",
    "emit_misconfig_pass_coverage",
    "nuclei_result_outcome",
    "NUCLEI_TEMPLATES_DIR",
]
