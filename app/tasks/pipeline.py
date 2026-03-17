"""
Pipeline orchestrator for EASM scan execution.

Manages the scan pipeline:
  Phase 0:  Seed Ingestion & Scope Validation
  Phase 1:  Passive Discovery (subfinder, crt.sh Certificate Transparency)
  Phase 1b: GitHub Dorking (optional, requires GITHUB_TOKEN)
  Phase 1c: WHOIS/RDAP + Reverse WHOIS
  Phase 1d: Cloud Bucket/Storage Discovery (S3, GCS, Azure Blob, DO Spaces)
  Phase 1e: Cloud Asset Enumeration (cloudlist, Tier 2+)
  Phase 2:  DNS Permutation & Bruteforce (alterx + puredns, Tier 2+)
  Phase 3:  DNS Resolution + SPF/MX Pivot
  Phase 4:  HTTP Probing (httpx)
  Phase 4b: TLS Certificate Collection (tlsx)
  Phase 5:  Port Scanning (naabu)
  Phase 5b: CDN/WAF Detection (cdncheck, all tiers)
  Phase 5c: Service Fingerprinting (fingerprintx, Tier 2+)
  Phase 6:  Technology Fingerprinting
  Phase 6b: Web Crawling (katana)
  Phase 6c: Sensitive Path Discovery
  Phase 7:  Visual Recon (stub)
  Phase 8:  Misconfiguration Detection
  Phase 9:  Vulnerability Scanning (nuclei, + interactsh on Tier 3)
  Phase 10: Correlation & Dedup
  Phase 11: Risk Scoring
  Phase 12: Diff, Alerting & Reporting

Phase implementations are in app.tasks.pipeline_phases/ submodules.
Helper functions are in app.tasks.pipeline_helpers.
"""

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

from celery.exceptions import SoftTimeLimitExceeded

from app.celery_app import celery
from app.config import settings  # noqa: F401 - kept for backward-compat test patches
from app.database import SessionLocal
from app.models.scanning import ScanRun, ScanRunStatus, PhaseResult, PhaseStatus, Project, ScanProfile
from app.utils.logger import TenantLoggerAdapter

# Phase implementations (extracted to pipeline_phases/ subpackage)
from app.tasks.pipeline_phases.discovery import (
    _phase_0_seed_ingestion,
    _phase_1_passive_discovery,
    _phase_1b_github_dorking,
    _phase_1c_whois_discovery,
    _phase_1d_cloud_buckets,
    _phase_1e_cloud_enum,
)
from app.tasks.pipeline_phases.enumeration import (
    _phase_2_dns_bruteforce,
    _phase_3_dns_resolution,
    _phase_4_http_probing,
    _phase_4b_tls_collection,
    _phase_5_port_scanning,
    _phase_5b_cdn_detection,
    _phase_5c_service_fingerprint,
)
from app.tasks.pipeline_phases.reconnaissance import (
    _phase_6_fingerprinting,
    _phase_6b_web_crawling,
    _phase_6c_sensitive_paths,
    _phase_7_visual_recon,
)
from app.tasks.pipeline_phases.detection import (
    _phase_8_misconfig_detection,
    _phase_9_vuln_scanning,
    _phase_10_correlation,
    _phase_11_risk_scoring,
    _phase_12_diff_alerting,
)

logger = logging.getLogger(__name__)

# Phase definitions (metadata lookup)
PHASE_DEFS = {
    "0": {"name": "Seed Ingestion", "required": True},
    "1": {"name": "Passive Discovery", "required": True},
    "1b": {"name": "GitHub Dorking", "required": False},
    "1c": {"name": "WHOIS/RDAP Discovery", "required": False},
    "1d": {"name": "Cloud Bucket Discovery", "required": False},
    "1e": {"name": "Cloud Asset Enumeration", "required": False},
    "2": {"name": "DNS Permutation & Bruteforce", "required": False},
    "3": {"name": "DNS Resolution", "required": True},
    "4": {"name": "HTTP Probing", "required": True},
    "4b": {"name": "TLS Certificate Collection", "required": False},
    "5": {"name": "Port Scanning", "required": True},
    "5b": {"name": "CDN/WAF Detection", "required": False},
    "5c": {"name": "Service Fingerprinting", "required": False},
    "6": {"name": "Technology Fingerprinting", "required": True},
    "6b": {"name": "Web Crawling", "required": True},
    "6c": {"name": "Sensitive Path Discovery", "required": False},
    "7": {"name": "Visual Recon", "required": False},
    "8": {"name": "Misconfiguration Detection", "required": True},
    "9": {"name": "Vulnerability Scanning", "required": True},
    "10": {"name": "Correlation & Dedup", "required": True},
    "11": {"name": "Risk Scoring", "required": True},
    "12": {"name": "Diff & Alerting", "required": True},
}

# Flat list of all phase IDs (for init and backwards compat)
PHASES = [{"id": pid, **pdef} for pid, pdef in PHASE_DEFS.items()]

# Execution plan: each step is either a single phase ID (sequential) or a
# list of phase IDs (run in parallel with ThreadPoolExecutor).
# Independent phases are grouped to cut total wall-clock time.
EXECUTION_PLAN = [
    "0",  # Seed ingestion (must be first)
    ["1", "1b", "1c", "1d", "1e"],  # Discovery: subfinder, GitHub, WHOIS, cloud in parallel
    "2",  # DNS bruteforce (needs Phase 1 results)
    "3",  # DNS resolution (needs Phase 2 results)
    "5b",  # CDN/WAF detection (before probing — skip CDN IPs)
    ["4", "4b", "5"],  # Probing: httpx, tlsx, naabu in parallel (all need DNS)
    ["5c", "6"],  # Fingerprint, tech detect in parallel
    ["6b", "6c", "7"],  # Crawl, sensitive paths, screenshots in parallel
    ["8", "9"],  # Misconfig + Nuclei in parallel (misconfig is read-only)
    ["10", "11"],  # Correlation + Risk scoring in parallel
    "12",  # Diff & alerting
]


def _update_phase(db, scan_run_id: int, phase_id: str, status: PhaseStatus, stats: dict = None, error: str = None):
    """Update or create a phase result record."""
    phase_result = (
        db.query(PhaseResult).filter(PhaseResult.scan_run_id == scan_run_id, PhaseResult.phase == phase_id).first()
    )

    if not phase_result:
        phase_result = PhaseResult(scan_run_id=scan_run_id, phase=phase_id, status=status)
        db.add(phase_result)
    else:
        phase_result.status = status

    if status == PhaseStatus.RUNNING:
        phase_result.started_at = datetime.now(timezone.utc)
    elif status in (PhaseStatus.COMPLETED, PhaseStatus.FAILED, PhaseStatus.SKIPPED):
        phase_result.completed_at = datetime.now(timezone.utc)

    if stats:
        phase_result.stats = stats
    if error:
        phase_result.error_message = error

    db.commit()
    return phase_result


def _update_scan_run(db, scan_run_id: int, status: ScanRunStatus, error: str = None, stats: dict = None):
    """Update scan run status."""
    scan_run = db.query(ScanRun).filter(ScanRun.id == scan_run_id).first()
    if not scan_run:
        return

    scan_run.status = status
    if status == ScanRunStatus.RUNNING:
        scan_run.started_at = datetime.now(timezone.utc)
    elif status in (ScanRunStatus.COMPLETED, ScanRunStatus.FAILED, ScanRunStatus.CANCELLED):
        scan_run.completed_at = datetime.now(timezone.utc)
    if error:
        scan_run.error_message = error
    if stats:
        scan_run.stats = stats

    db.commit()


def _run_single_phase(
    phase_id, tenant_id, project_id, scan_run_id, db, tenant_logger, scan_tier, throttle, pipeline_stats
):
    """Execute a single phase sequentially with the main DB session."""
    phase_def = PHASE_DEFS[phase_id]
    phase_name = phase_def["name"]

    tenant_logger.info(f"Starting phase {phase_id}: {phase_name}")
    _update_phase(db, scan_run_id, phase_id, PhaseStatus.RUNNING)

    try:
        result = _execute_phase(phase_id, tenant_id, project_id, scan_run_id, db, tenant_logger, scan_tier=scan_tier)

        _update_phase(db, scan_run_id, phase_id, PhaseStatus.COMPLETED, stats=result)
        pipeline_stats["phases_completed"] += 1

        if isinstance(result, dict):
            pipeline_stats["assets_discovered"] += result.get("assets_discovered", 0)
            pipeline_stats["findings_created"] += result.get("findings_created", 0)
            pipeline_stats["relationships_created"] += result.get("relationships_created", 0)

            phase_429s = result.get("http_429_count", 0)
            if phase_429s > 0:
                for _ in range(phase_429s):
                    throttle.report_429(f"phase_{phase_id}")
            else:
                throttle.report_phase_clean()

        tenant_logger.info(f"Phase {phase_id} ({phase_name}) completed: {result}")

    except Exception as e:
        error_msg = str(e)
        tenant_logger.error(
            f"Phase {phase_id} ({phase_name}) failed: {error_msg}",
            exc_info=True,
        )
        _update_phase(db, scan_run_id, phase_id, PhaseStatus.FAILED, error=error_msg)
        pipeline_stats["phases_failed"] += 1

        if phase_def["required"]:
            if phase_id == "0":
                _update_scan_run(
                    db, scan_run_id, ScanRunStatus.FAILED, error=f"Phase 0 failed: {error_msg}", stats=pipeline_stats
                )
                pipeline_stats["_fatal"] = True
                return
            tenant_logger.warning(f"Required phase {phase_id} failed, continuing pipeline")


@celery.task(
    name="app.tasks.pipeline.run_scan_pipeline",
    bind=True,
    max_retries=2,
    default_retry_delay=120,
    retry_backoff=True,
    retry_backoff_max=600,
    retry_jitter=True,
    acks_late=True,
    reject_on_worker_lost=True,
    soft_time_limit=10800,
    time_limit=11100,
)
def run_scan_pipeline(self, scan_run_id: int):
    """
    Execute the full scan pipeline for a scan run.

    Runs phases sequentially, tracking progress in phase_results.
    Each phase can be skipped if not required or if dependencies
    (like API keys) are missing.

    Retry policy:
    - Infrastructure errors (DB connection, Redis) trigger retries
      with exponential backoff (max 2 retries).
    - Business-logic phase failures are NOT retried; they are recorded
      in phase_results and the pipeline continues.
    - If retries are exhausted, the scan_run is marked FAILED.
    """
    db = SessionLocal()

    try:
        scan_run = db.query(ScanRun).filter(ScanRun.id == scan_run_id).first()
        if not scan_run:
            logger.error(f"ScanRun {scan_run_id} not found")
            return {"error": "ScanRun not found"}

        # Guard against duplicate/stale execution:
        # 1. Already completed/failed/cancelled — don't re-run
        # 2. Already running with a different Celery task — skip duplicate
        if scan_run.status in (ScanRunStatus.COMPLETED, ScanRunStatus.FAILED, ScanRunStatus.CANCELLED):
            logger.warning(
                f"ScanRun {scan_run_id} already {scan_run.status.value}, "
                f"skipping stale execution from task {self.request.id}"
            )
            return {"error": f"Already {scan_run.status.value}", "skipped": True}

        if (
            scan_run.status == ScanRunStatus.RUNNING
            and scan_run.celery_task_id
            and scan_run.celery_task_id != self.request.id
        ):
            logger.warning(
                f"ScanRun {scan_run_id} already running (task {scan_run.celery_task_id}), "
                f"skipping duplicate execution from task {self.request.id}"
            )
            return {"error": "Already running", "skipped": True}

        tenant_id = scan_run.tenant_id
        project_id = scan_run.project_id
        tenant_logger = TenantLoggerAdapter(logger, {"tenant_id": tenant_id})

        # Get project for seeds/settings
        project = db.query(Project).filter(Project.id == project_id).first()
        if not project:
            _update_scan_run(db, scan_run_id, ScanRunStatus.FAILED, error="Project not found")
            return {"error": "Project not found"}

        # Determine scan tier from profile or stats config (default: 1=Safe)
        scan_tier = 1
        if scan_run.profile_id:
            profile = db.query(ScanProfile).filter(ScanProfile.id == scan_run.profile_id).first()
            if profile:
                scan_tier = profile.scan_tier or 1
        # Allow override via stats.config.tier (for manual/API-triggered scans)
        if scan_run.stats and isinstance(scan_run.stats, dict):
            config_tier = scan_run.stats.get("config", {}).get("tier")
            if config_tier in (1, 2, 3):
                scan_tier = config_tier

        # Update celery task id
        scan_run.celery_task_id = self.request.id
        db.commit()

        # Mark as running
        _update_scan_run(db, scan_run_id, ScanRunStatus.RUNNING)
        tenant_logger.info(
            f"Scan tier: {scan_tier} ({'Safe' if scan_tier == 1 else 'Moderate' if scan_tier == 2 else 'Aggressive'})"
        )

        # Initialize all phase results as pending
        for phase_def in PHASES:
            _update_phase(db, scan_run_id, phase_def["id"], PhaseStatus.PENDING)

        tenant_logger.info(f"Starting scan pipeline for project {project.name} (run {scan_run_id})")

        # Initialize adaptive throttle for this scan
        from app.services.adaptive_throttle import get_throttle, cleanup_throttle

        throttle = get_throttle(tenant_id, scan_run_id)

        # Collect aggregate stats
        pipeline_stats = {
            "phases_completed": 0,
            "phases_failed": 0,
            "phases_skipped": 0,
            "assets_discovered": 0,
            "findings_created": 0,
            "relationships_created": 0,
        }

        # Execute phases following the execution plan (sequential + parallel groups)
        for step in EXECUTION_PLAN:
            # Check if scan was cancelled
            db.refresh(scan_run)
            if scan_run.status == ScanRunStatus.CANCELLED:
                tenant_logger.info(f"Scan {scan_run_id} was cancelled, stopping pipeline")
                break

            # Normalize step to a list of phase IDs
            phase_ids = step if isinstance(step, list) else [step]

            # Filter out phases that should be skipped
            phases_to_run = []
            for phase_id in phase_ids:
                phase_def = PHASE_DEFS[phase_id]
                phase_name = phase_def["name"]
                should_skip, skip_reason = _should_skip_phase(phase_id, project, scan_tier)
                if should_skip:
                    tenant_logger.info(f"Skipping phase {phase_id} ({phase_name}): {skip_reason}")
                    _update_phase(db, scan_run_id, phase_id, PhaseStatus.SKIPPED, stats={"skip_reason": skip_reason})
                    pipeline_stats["phases_skipped"] += 1
                else:
                    phases_to_run.append(phase_id)

            if not phases_to_run:
                continue

            # Run phases — parallel if multiple, sequential if single
            if len(phases_to_run) == 1:
                # Single phase: run directly (reuse main DB session)
                _run_single_phase(
                    phases_to_run[0],
                    tenant_id,
                    project_id,
                    scan_run_id,
                    db,
                    tenant_logger,
                    scan_tier,
                    throttle,
                    pipeline_stats,
                )
            else:
                # Parallel group: each phase gets its own DB session
                tenant_logger.info(f"Running parallel group: {', '.join(phases_to_run)}")
                # Mark all as RUNNING first
                for pid in phases_to_run:
                    _update_phase(db, scan_run_id, pid, PhaseStatus.RUNNING)

                def _run_parallel_phase(pid):
                    """Execute a phase in its own DB session (thread-safe)."""
                    thread_db = SessionLocal()
                    try:
                        result = _execute_phase(
                            pid,
                            tenant_id,
                            project_id,
                            scan_run_id,
                            thread_db,
                            tenant_logger,
                            scan_tier=scan_tier,
                        )
                        return pid, result, None
                    except Exception as exc:
                        return pid, None, str(exc)
                    finally:
                        thread_db.close()

                # Per-group wall-clock timeout: 30 min max for any parallel group.
                # Prevents the entire pipeline from hanging if one phase is stuck.
                group_timeout = 1800  # 30 min

                with ThreadPoolExecutor(max_workers=len(phases_to_run)) as executor:
                    futures = {executor.submit(_run_parallel_phase, pid): pid for pid in phases_to_run}
                    completed_pids = set()
                    try:
                        for future in as_completed(futures, timeout=group_timeout):
                            pid, result, error = future.result()
                            completed_pids.add(pid)
                            pdef = PHASE_DEFS[pid]
                            if error:
                                tenant_logger.error(f"Phase {pid} ({pdef['name']}) failed: {error}")
                                _update_phase(db, scan_run_id, pid, PhaseStatus.FAILED, error=error)
                                pipeline_stats["phases_failed"] += 1
                                if pdef["required"] and pid == "0":
                                    _update_scan_run(
                                        db,
                                        scan_run_id,
                                        ScanRunStatus.FAILED,
                                        error=f"Phase 0 failed: {error}",
                                        stats=pipeline_stats,
                                    )
                                    return {"error": error, "stats": pipeline_stats}
                            else:
                                _update_phase(db, scan_run_id, pid, PhaseStatus.COMPLETED, stats=result)
                                pipeline_stats["phases_completed"] += 1
                                if isinstance(result, dict):
                                    pipeline_stats["assets_discovered"] += result.get("assets_discovered", 0)
                                    pipeline_stats["findings_created"] += result.get("findings_created", 0)
                                    pipeline_stats["relationships_created"] += result.get("relationships_created", 0)
                                    phase_429s = result.get("http_429_count", 0)
                                    if phase_429s > 0:
                                        for _ in range(phase_429s):
                                            throttle.report_429(f"phase_{pid}")
                                    else:
                                        throttle.report_phase_clean()
                                tenant_logger.info(f"Phase {pid} ({pdef['name']}) completed: {result}")
                    except TimeoutError:
                        # Some phases in this group timed out — mark them as failed
                        timed_out_pids = set(phases_to_run) - completed_pids
                        for pid in timed_out_pids:
                            pdef = PHASE_DEFS[pid]
                            tenant_logger.error(f"Phase {pid} ({pdef['name']}) timed out after {group_timeout}s")
                            _update_phase(
                                db,
                                scan_run_id,
                                pid,
                                PhaseStatus.FAILED,
                                error=f"Timed out after {group_timeout}s",
                            )
                            pipeline_stats["phases_failed"] += 1

            # Fatal check: Phase 0 failure means we can't continue
            if pipeline_stats.get("_fatal"):
                return {"error": "Phase 0 failed", "stats": pipeline_stats}

        # Log adaptive throttle summary
        throttle_summary = cleanup_throttle(tenant_id, scan_run_id)
        if throttle_summary and throttle_summary.get("total_429s", 0) > 0:
            tenant_logger.warning(f"Adaptive throttle summary: {throttle_summary}")
            pipeline_stats["throttle"] = throttle_summary

        # Mark scan as completed
        _update_scan_run(db, scan_run_id, ScanRunStatus.COMPLETED, stats=pipeline_stats)
        tenant_logger.info(f"Scan pipeline completed for run {scan_run_id}: {pipeline_stats}")

        return pipeline_stats

    except SoftTimeLimitExceeded:
        logger.warning("Pipeline soft time limit reached for scan run %d", scan_run_id)
        try:
            _update_scan_run(
                db,
                scan_run_id,
                ScanRunStatus.FAILED,
                error="Pipeline exceeded 2h time limit",
                stats=pipeline_stats,
            )
        except Exception:
            logger.exception("Failed to update scan_run status after timeout")
        return {"error": "time_limit_exceeded", "stats": pipeline_stats}
    except Exception as exc:
        logger.exception("Pipeline error for scan run %d: %s", scan_run_id, exc)
        # Mark scan as failed before deciding whether to retry
        try:
            _update_scan_run(db, scan_run_id, ScanRunStatus.FAILED, error=str(exc))
        except Exception:
            logger.exception("Failed to update scan_run status after pipeline error")
        # Retry infrastructure-level failures (DB disconnect, Redis timeout, etc.)
        # The scan_run is already marked FAILED; if the retry succeeds it will
        # be re-marked as RUNNING at the top of the next attempt.
        raise self.retry(exc=exc)
    finally:
        db.close()


def _should_skip_phase(phase_id: str, project: Project, scan_tier: int = 1) -> tuple:
    """Determine if a phase should be skipped based on config and scan tier."""
    from app.config import settings as app_settings

    project_settings = project.settings or {}

    if phase_id == "1b":
        # GitHub dorking requires GITHUB_TOKEN
        if not getattr(app_settings, "github_token", None):
            return True, "GITHUB_TOKEN not configured"

    if phase_id == "1c":
        # WHOIS is optional - skip if explicitly disabled
        if not project_settings.get("whois_enabled", True):
            return True, "WHOIS discovery disabled in project settings"

    if phase_id == "1d":
        # Cloud bucket discovery is optional - skip if explicitly disabled
        if not project_settings.get("cloud_bucket_scan_enabled", True):
            return True, "Cloud bucket scanning disabled in project settings"

    if phase_id == "1e":
        # Cloud enumeration requires provider config + tier 2+
        if scan_tier < 2:
            return True, "Cloud enumeration requires tier 2+"
        providers = project_settings.get("cloud_providers")
        if not providers:
            return True, "No cloud providers configured"

    if phase_id == "2":
        # DNS permutation/bruteforce requires tier 2+
        if scan_tier < 2:
            return True, "DNS permutation requires tier 2+"

    if phase_id == "5b":
        # cdncheck is read-only DNS lookup, safe for all tiers
        pass

    if phase_id == "5c":
        # fingerprintx is a passive protocol handshake — safe for all tiers
        pass

    if phase_id == "7":
        if not getattr(app_settings, "feature_visual_recon_enabled", True):
            return True, "Visual recon disabled in feature flags"

    return False, ""


def _execute_phase(
    phase_id: str, tenant_id: int, project_id: int, scan_run_id: int, db, tenant_logger, scan_tier: int = 1
) -> dict:
    """Execute a specific pipeline phase and return results."""

    if phase_id == "0":
        return _phase_0_seed_ingestion(tenant_id, project_id, scan_run_id, db, tenant_logger)
    elif phase_id == "1":
        return _phase_1_passive_discovery(tenant_id, project_id, scan_run_id, db, tenant_logger)
    elif phase_id == "1b":
        return _phase_1b_github_dorking(tenant_id, project_id, scan_run_id, db, tenant_logger)
    elif phase_id == "1c":
        return _phase_1c_whois_discovery(tenant_id, project_id, scan_run_id, db, tenant_logger)
    elif phase_id == "1d":
        return _phase_1d_cloud_buckets(tenant_id, project_id, scan_run_id, db, tenant_logger)
    elif phase_id == "1e":
        return _phase_1e_cloud_enum(tenant_id, project_id, scan_run_id, db, tenant_logger)
    elif phase_id == "2":
        return _phase_2_dns_bruteforce(tenant_id, project_id, scan_run_id, db, tenant_logger, scan_tier)
    elif phase_id == "3":
        return _phase_3_dns_resolution(tenant_id, project_id, scan_run_id, db, tenant_logger)
    elif phase_id == "4":
        return _phase_4_http_probing(tenant_id, project_id, scan_run_id, db, tenant_logger)
    elif phase_id == "4b":
        return _phase_4b_tls_collection(tenant_id, project_id, scan_run_id, db, tenant_logger)
    elif phase_id == "5":
        return _phase_5_port_scanning(tenant_id, project_id, scan_run_id, db, tenant_logger, scan_tier)
    elif phase_id == "5b":
        return _phase_5b_cdn_detection(tenant_id, project_id, scan_run_id, db, tenant_logger)
    elif phase_id == "5c":
        return _phase_5c_service_fingerprint(tenant_id, project_id, scan_run_id, db, tenant_logger)
    elif phase_id == "6":
        return _phase_6_fingerprinting(tenant_id, project_id, scan_run_id, db, tenant_logger)
    elif phase_id == "6b":
        return _phase_6b_web_crawling(tenant_id, project_id, scan_run_id, db, tenant_logger)
    elif phase_id == "6c":
        return _phase_6c_sensitive_paths(tenant_id, project_id, scan_run_id, db, tenant_logger)
    elif phase_id == "7":
        return _phase_7_visual_recon(tenant_id, project_id, scan_run_id, db, tenant_logger)
    elif phase_id == "8":
        return _phase_8_misconfig_detection(tenant_id, project_id, scan_run_id, db, tenant_logger)
    elif phase_id == "9":
        return _phase_9_vuln_scanning(tenant_id, project_id, scan_run_id, db, tenant_logger, scan_tier)
    elif phase_id == "10":
        return _phase_10_correlation(tenant_id, project_id, scan_run_id, db, tenant_logger)
    elif phase_id == "11":
        return _phase_11_risk_scoring(tenant_id, project_id, scan_run_id, db, tenant_logger)
    elif phase_id == "12":
        return _phase_12_diff_alerting(tenant_id, project_id, scan_run_id, db, tenant_logger)

    return {"error": f"Unknown phase: {phase_id}"}


@celery.task(
    name="app.tasks.pipeline.cancel_scan",
    bind=True,
    max_retries=3,
    default_retry_delay=10,
    retry_backoff=True,
    retry_backoff_max=60,
    retry_jitter=True,
)
def cancel_scan(self, scan_run_id: int):
    """Cancel a running scan."""
    db = SessionLocal()
    try:
        scan_run = db.query(ScanRun).filter(ScanRun.id == scan_run_id).first()
        if not scan_run:
            return {"error": "ScanRun not found"}

        if scan_run.status != ScanRunStatus.RUNNING:
            return {"error": f"Cannot cancel scan in status {scan_run.status.value}"}

        scan_run.status = ScanRunStatus.CANCELLED
        scan_run.completed_at = datetime.now(timezone.utc)
        scan_run.error_message = "Cancelled by user"

        # Cancel celery task if running
        if scan_run.celery_task_id:
            celery.control.revoke(scan_run.celery_task_id, terminate=True)

        db.commit()
        return {"status": "cancelled", "scan_run_id": scan_run_id}
    except Exception as exc:
        logger.exception("Failed to cancel scan run %d: %s", scan_run_id, exc)
        raise self.retry(exc=exc)
    finally:
        db.close()
