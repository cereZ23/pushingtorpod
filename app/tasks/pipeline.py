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
"""

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Optional

from celery.exceptions import SoftTimeLimitExceeded

from app.celery_app import celery
from app.config import settings
from app.database import SessionLocal
from app.models.scanning import (
    ScanRun, ScanRunStatus, PhaseResult, PhaseStatus, Project, ScanProfile
)
from app.models.risk import Relationship
from app.utils.logger import TenantLoggerAdapter

logger = logging.getLogger(__name__)

# Phase definitions (metadata lookup)
PHASE_DEFS = {
    '0':  {'name': 'Seed Ingestion', 'required': True},
    '1':  {'name': 'Passive Discovery', 'required': True},
    '1b': {'name': 'GitHub Dorking', 'required': False},
    '1c': {'name': 'WHOIS/RDAP Discovery', 'required': False},
    '1d': {'name': 'Cloud Bucket Discovery', 'required': False},
    '1e': {'name': 'Cloud Asset Enumeration', 'required': False},
    '2':  {'name': 'DNS Permutation & Bruteforce', 'required': False},
    '3':  {'name': 'DNS Resolution', 'required': True},
    '4':  {'name': 'HTTP Probing', 'required': True},
    '4b': {'name': 'TLS Certificate Collection', 'required': False},
    '5':  {'name': 'Port Scanning', 'required': True},
    '5b': {'name': 'CDN/WAF Detection', 'required': False},
    '5c': {'name': 'Service Fingerprinting', 'required': False},
    '6':  {'name': 'Technology Fingerprinting', 'required': True},
    '6b': {'name': 'Web Crawling', 'required': True},
    '6c': {'name': 'Sensitive Path Discovery', 'required': False},
    '7':  {'name': 'Visual Recon', 'required': False},
    '8':  {'name': 'Misconfiguration Detection', 'required': True},
    '9':  {'name': 'Vulnerability Scanning', 'required': True},
    '10': {'name': 'Correlation & Dedup', 'required': True},
    '11': {'name': 'Risk Scoring', 'required': True},
    '12': {'name': 'Diff & Alerting', 'required': True},
}

# Flat list of all phase IDs (for init and backwards compat)
PHASES = [{'id': pid, **pdef} for pid, pdef in PHASE_DEFS.items()]

# Execution plan: each step is either a single phase ID (sequential) or a
# list of phase IDs (run in parallel with ThreadPoolExecutor).
# Independent phases are grouped to cut total wall-clock time.
EXECUTION_PLAN = [
    '0',                            # Seed ingestion (must be first)
    ['1', '1b', '1c', '1d', '1e'], # Discovery: subfinder, GitHub, WHOIS, cloud in parallel
    '2',                            # DNS bruteforce (needs Phase 1 results)
    '3',                            # DNS resolution (needs Phase 2 results)
    '5b',                           # CDN/WAF detection (before probing — skip CDN IPs)
    ['4', '4b', '5'],              # Probing: httpx, tlsx, naabu in parallel (all need DNS)
    ['5c', '6'],                    # Fingerprint, tech detect in parallel
    ['6b', '6c', '7'],             # Crawl, sensitive paths, screenshots in parallel
    ['8', '9'],                     # Misconfig + Nuclei in parallel (misconfig is read-only)
    ['10', '11'],                   # Correlation + Risk scoring in parallel
    '12',                           # Diff & alerting
]


def _update_phase(db, scan_run_id: int, phase_id: str, status: PhaseStatus,
                   stats: dict = None, error: str = None):
    """Update or create a phase result record."""
    phase_result = db.query(PhaseResult).filter(
        PhaseResult.scan_run_id == scan_run_id,
        PhaseResult.phase == phase_id
    ).first()

    if not phase_result:
        phase_result = PhaseResult(
            scan_run_id=scan_run_id,
            phase=phase_id,
            status=status
        )
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


def _update_scan_run(db, scan_run_id: int, status: ScanRunStatus,
                      error: str = None, stats: dict = None):
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


def _run_single_phase(phase_id, tenant_id, project_id, scan_run_id,
                       db, tenant_logger, scan_tier, throttle, pipeline_stats):
    """Execute a single phase sequentially with the main DB session."""
    phase_def = PHASE_DEFS[phase_id]
    phase_name = phase_def['name']

    tenant_logger.info(f"Starting phase {phase_id}: {phase_name}")
    _update_phase(db, scan_run_id, phase_id, PhaseStatus.RUNNING)

    try:
        result = _execute_phase(
            phase_id, tenant_id, project_id, scan_run_id, db, tenant_logger,
            scan_tier=scan_tier
        )

        _update_phase(db, scan_run_id, phase_id, PhaseStatus.COMPLETED, stats=result)
        pipeline_stats['phases_completed'] += 1

        if isinstance(result, dict):
            pipeline_stats['assets_discovered'] += result.get('assets_discovered', 0)
            pipeline_stats['findings_created'] += result.get('findings_created', 0)
            pipeline_stats['relationships_created'] += result.get('relationships_created', 0)

            phase_429s = result.get('http_429_count', 0)
            if phase_429s > 0:
                for _ in range(phase_429s):
                    throttle.report_429(f"phase_{phase_id}")
            else:
                throttle.report_phase_clean()

        tenant_logger.info(f"Phase {phase_id} ({phase_name}) completed: {result}")

    except Exception as e:
        error_msg = str(e)
        tenant_logger.error(
            f"Phase {phase_id} ({phase_name}) failed: {error_msg}", exc_info=True,
        )
        _update_phase(db, scan_run_id, phase_id, PhaseStatus.FAILED, error=error_msg)
        pipeline_stats['phases_failed'] += 1

        if phase_def['required']:
            if phase_id == '0':
                _update_scan_run(db, scan_run_id, ScanRunStatus.FAILED,
                                error=f"Phase 0 failed: {error_msg}",
                                stats=pipeline_stats)
                pipeline_stats['_fatal'] = True
                return
            tenant_logger.warning(f"Required phase {phase_id} failed, continuing pipeline")


@celery.task(
    name='app.tasks.pipeline.run_scan_pipeline',
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
            return {'error': 'ScanRun not found'}

        # Guard against duplicate/stale execution:
        # 1. Already completed/failed/cancelled — don't re-run
        # 2. Already running with a different Celery task — skip duplicate
        if scan_run.status in (ScanRunStatus.COMPLETED, ScanRunStatus.FAILED, ScanRunStatus.CANCELLED):
            logger.warning(
                f"ScanRun {scan_run_id} already {scan_run.status.value}, "
                f"skipping stale execution from task {self.request.id}"
            )
            return {'error': f'Already {scan_run.status.value}', 'skipped': True}

        if (scan_run.status == ScanRunStatus.RUNNING
                and scan_run.celery_task_id
                and scan_run.celery_task_id != self.request.id):
            logger.warning(
                f"ScanRun {scan_run_id} already running (task {scan_run.celery_task_id}), "
                f"skipping duplicate execution from task {self.request.id}"
            )
            return {'error': 'Already running', 'skipped': True}

        tenant_id = scan_run.tenant_id
        project_id = scan_run.project_id
        tenant_logger = TenantLoggerAdapter(logger, {'tenant_id': tenant_id})

        # Get project for seeds/settings
        project = db.query(Project).filter(Project.id == project_id).first()
        if not project:
            _update_scan_run(db, scan_run_id, ScanRunStatus.FAILED, error='Project not found')
            return {'error': 'Project not found'}

        # Determine scan tier from profile or stats config (default: 1=Safe)
        scan_tier = 1
        if scan_run.profile_id:
            profile = db.query(ScanProfile).filter(ScanProfile.id == scan_run.profile_id).first()
            if profile:
                scan_tier = profile.scan_tier or 1
        # Allow override via stats.config.tier (for manual/API-triggered scans)
        if scan_run.stats and isinstance(scan_run.stats, dict):
            config_tier = scan_run.stats.get('config', {}).get('tier')
            if config_tier in (1, 2, 3):
                scan_tier = config_tier

        # Update celery task id
        scan_run.celery_task_id = self.request.id
        db.commit()

        # Mark as running
        _update_scan_run(db, scan_run_id, ScanRunStatus.RUNNING)
        tenant_logger.info(f"Scan tier: {scan_tier} ({'Safe' if scan_tier == 1 else 'Moderate' if scan_tier == 2 else 'Aggressive'})")

        # Initialize all phase results as pending
        for phase_def in PHASES:
            _update_phase(db, scan_run_id, phase_def['id'], PhaseStatus.PENDING)

        tenant_logger.info(f"Starting scan pipeline for project {project.name} (run {scan_run_id})")

        # Initialize adaptive throttle for this scan
        from app.services.adaptive_throttle import get_throttle, cleanup_throttle
        throttle = get_throttle(tenant_id, scan_run_id)

        # Collect aggregate stats
        pipeline_stats = {
            'phases_completed': 0,
            'phases_failed': 0,
            'phases_skipped': 0,
            'assets_discovered': 0,
            'findings_created': 0,
            'relationships_created': 0,
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
                phase_name = phase_def['name']
                should_skip, skip_reason = _should_skip_phase(phase_id, project, scan_tier)
                if should_skip:
                    tenant_logger.info(f"Skipping phase {phase_id} ({phase_name}): {skip_reason}")
                    _update_phase(db, scan_run_id, phase_id, PhaseStatus.SKIPPED,
                                 stats={'skip_reason': skip_reason})
                    pipeline_stats['phases_skipped'] += 1
                else:
                    phases_to_run.append(phase_id)

            if not phases_to_run:
                continue

            # Run phases — parallel if multiple, sequential if single
            if len(phases_to_run) == 1:
                # Single phase: run directly (reuse main DB session)
                _run_single_phase(
                    phases_to_run[0], tenant_id, project_id, scan_run_id,
                    db, tenant_logger, scan_tier, throttle, pipeline_stats,
                )
            else:
                # Parallel group: each phase gets its own DB session
                tenant_logger.info(
                    f"Running parallel group: {', '.join(phases_to_run)}"
                )
                # Mark all as RUNNING first
                for pid in phases_to_run:
                    _update_phase(db, scan_run_id, pid, PhaseStatus.RUNNING)

                def _run_parallel_phase(pid):
                    """Execute a phase in its own DB session (thread-safe)."""
                    thread_db = SessionLocal()
                    try:
                        result = _execute_phase(
                            pid, tenant_id, project_id, scan_run_id,
                            thread_db, tenant_logger, scan_tier=scan_tier,
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
                    futures = {
                        executor.submit(_run_parallel_phase, pid): pid
                        for pid in phases_to_run
                    }
                    completed_pids = set()
                    try:
                        for future in as_completed(futures, timeout=group_timeout):
                            pid, result, error = future.result()
                            completed_pids.add(pid)
                            pdef = PHASE_DEFS[pid]
                            if error:
                                tenant_logger.error(f"Phase {pid} ({pdef['name']}) failed: {error}")
                                _update_phase(db, scan_run_id, pid, PhaseStatus.FAILED, error=error)
                                pipeline_stats['phases_failed'] += 1
                                if pdef['required'] and pid == '0':
                                    _update_scan_run(db, scan_run_id, ScanRunStatus.FAILED,
                                                    error=f"Phase 0 failed: {error}",
                                                    stats=pipeline_stats)
                                    return {'error': error, 'stats': pipeline_stats}
                            else:
                                _update_phase(db, scan_run_id, pid, PhaseStatus.COMPLETED, stats=result)
                                pipeline_stats['phases_completed'] += 1
                                if isinstance(result, dict):
                                    pipeline_stats['assets_discovered'] += result.get('assets_discovered', 0)
                                    pipeline_stats['findings_created'] += result.get('findings_created', 0)
                                    pipeline_stats['relationships_created'] += result.get('relationships_created', 0)
                                    phase_429s = result.get('http_429_count', 0)
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
                            tenant_logger.error(
                                f"Phase {pid} ({pdef['name']}) timed out after {group_timeout}s"
                            )
                            _update_phase(
                                db, scan_run_id, pid, PhaseStatus.FAILED,
                                error=f"Timed out after {group_timeout}s",
                            )
                            pipeline_stats['phases_failed'] += 1

            # Fatal check: Phase 0 failure means we can't continue
            if pipeline_stats.get('_fatal'):
                return {'error': 'Phase 0 failed', 'stats': pipeline_stats}

        # Log adaptive throttle summary
        throttle_summary = cleanup_throttle(tenant_id, scan_run_id)
        if throttle_summary and throttle_summary.get('total_429s', 0) > 0:
            tenant_logger.warning(f"Adaptive throttle summary: {throttle_summary}")
            pipeline_stats['throttle'] = throttle_summary

        # Mark scan as completed
        _update_scan_run(db, scan_run_id, ScanRunStatus.COMPLETED, stats=pipeline_stats)
        tenant_logger.info(f"Scan pipeline completed for run {scan_run_id}: {pipeline_stats}")

        return pipeline_stats

    except SoftTimeLimitExceeded:
        logger.warning("Pipeline soft time limit reached for scan run %d", scan_run_id)
        try:
            _update_scan_run(
                db, scan_run_id, ScanRunStatus.FAILED,
                error="Pipeline exceeded 2h time limit",
                stats=pipeline_stats,
            )
        except Exception:
            logger.exception("Failed to update scan_run status after timeout")
        return {'error': 'time_limit_exceeded', 'stats': pipeline_stats}
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

    if phase_id == '1b':
        # GitHub dorking requires GITHUB_TOKEN
        if not getattr(app_settings, 'github_token', None):
            return True, 'GITHUB_TOKEN not configured'

    if phase_id == '1c':
        # WHOIS is optional - skip if explicitly disabled
        if not project_settings.get('whois_enabled', True):
            return True, 'WHOIS discovery disabled in project settings'

    if phase_id == '1d':
        # Cloud bucket discovery is optional - skip if explicitly disabled
        if not project_settings.get('cloud_bucket_scan_enabled', True):
            return True, 'Cloud bucket scanning disabled in project settings'

    if phase_id == '1e':
        # Cloud enumeration requires provider config + tier 2+
        if scan_tier < 2:
            return True, 'Cloud enumeration requires tier 2+'
        providers = project_settings.get('cloud_providers')
        if not providers:
            return True, 'No cloud providers configured'

    if phase_id == '2':
        # DNS permutation/bruteforce requires tier 2+
        if scan_tier < 2:
            return True, 'DNS permutation requires tier 2+'

    if phase_id == '5b':
        # cdncheck is read-only DNS lookup, safe for all tiers
        pass

    if phase_id == '5c':
        # fingerprintx requires tier 2+
        if scan_tier < 2:
            return True, 'Service fingerprinting requires tier 2+'

    if phase_id == '7':
        if not getattr(app_settings, 'feature_visual_recon_enabled', True):
            return True, 'Visual recon disabled in feature flags'

    return False, ''


def _execute_phase(phase_id: str, tenant_id: int, project_id: int,
                   scan_run_id: int, db, tenant_logger, scan_tier: int = 1) -> dict:
    """Execute a specific pipeline phase and return results."""

    # Import phase executors lazily to avoid circular imports
    if phase_id == '0':
        return _phase_0_seed_ingestion(tenant_id, project_id, scan_run_id, db, tenant_logger)
    elif phase_id == '1':
        return _phase_1_passive_discovery(tenant_id, project_id, scan_run_id, db, tenant_logger)
    elif phase_id == '1b':
        return _phase_1b_github_dorking(tenant_id, project_id, scan_run_id, db, tenant_logger)
    elif phase_id == '1c':
        return _phase_1c_whois_discovery(tenant_id, project_id, scan_run_id, db, tenant_logger)
    elif phase_id == '1d':
        return _phase_1d_cloud_buckets(tenant_id, project_id, scan_run_id, db, tenant_logger)
    elif phase_id == '1e':
        return _phase_1e_cloud_enum(tenant_id, project_id, scan_run_id, db, tenant_logger)
    elif phase_id == '2':
        return _phase_2_dns_bruteforce(tenant_id, project_id, scan_run_id, db, tenant_logger, scan_tier)
    elif phase_id == '3':
        return _phase_3_dns_resolution(tenant_id, project_id, scan_run_id, db, tenant_logger)
    elif phase_id == '4':
        return _phase_4_http_probing(tenant_id, project_id, scan_run_id, db, tenant_logger)
    elif phase_id == '4b':
        return _phase_4b_tls_collection(tenant_id, project_id, scan_run_id, db, tenant_logger)
    elif phase_id == '5':
        return _phase_5_port_scanning(tenant_id, project_id, scan_run_id, db, tenant_logger, scan_tier)
    elif phase_id == '5b':
        return _phase_5b_cdn_detection(tenant_id, project_id, scan_run_id, db, tenant_logger)
    elif phase_id == '5c':
        return _phase_5c_service_fingerprint(tenant_id, project_id, scan_run_id, db, tenant_logger)
    elif phase_id == '6':
        return _phase_6_fingerprinting(tenant_id, project_id, scan_run_id, db, tenant_logger)
    elif phase_id == '6b':
        return _phase_6b_web_crawling(tenant_id, project_id, scan_run_id, db, tenant_logger)
    elif phase_id == '6c':
        return _phase_6c_sensitive_paths(tenant_id, project_id, scan_run_id, db, tenant_logger)
    elif phase_id == '7':
        return _phase_7_visual_recon(tenant_id, project_id, scan_run_id, db, tenant_logger)
    elif phase_id == '8':
        return _phase_8_misconfig_detection(tenant_id, project_id, scan_run_id, db, tenant_logger)
    elif phase_id == '9':
        return _phase_9_vuln_scanning(tenant_id, project_id, scan_run_id, db, tenant_logger, scan_tier)
    elif phase_id == '10':
        return _phase_10_correlation(tenant_id, project_id, scan_run_id, db, tenant_logger)
    elif phase_id == '11':
        return _phase_11_risk_scoring(tenant_id, project_id, scan_run_id, db, tenant_logger)
    elif phase_id == '12':
        return _phase_12_diff_alerting(tenant_id, project_id, scan_run_id, db, tenant_logger)

    return {'error': f'Unknown phase: {phase_id}'}


# ============================================================================
# RELATIONSHIP HELPERS
# ============================================================================

def _get_seed_domains(tenant_id: int, project_id: int, db) -> set:
    """Get all seed domains for scope filtering.

    Returns a set of root domains (e.g. {'example.com', 'example.org'}).
    Hostnames must be a subdomain of one of these to be in scope.
    """
    from app.models.scanning import Project
    from app.models.database import Seed

    domains = set()

    # From project seeds
    project = db.query(Project).filter(Project.id == project_id).first()
    if project and project.seeds:
        for seed in project.seeds:
            if seed.get('type') in ('domain', 'subdomain'):
                domains.add(seed['value'].lower().strip())

    # From tenant seeds
    tenant_seeds = db.query(Seed).filter(
        Seed.tenant_id == tenant_id,
        Seed.enabled == True,
        Seed.type.in_(['domain', 'subdomain']),
    ).all()
    for s in tenant_seeds:
        domains.add(s.value.lower().strip())

    return domains


def _is_hostname_in_scope(hostname: str, seed_domains: set) -> bool:
    """Check if a hostname belongs to one of the seed domains.

    E.g., 'api.example.com' is in scope if 'example.com' is a seed.
    'cdn.b-cdn.net' is NOT in scope if only 'example.com' is a seed.
    """
    hostname = hostname.lower().strip().rstrip('.')
    for domain in seed_domains:
        if hostname == domain or hostname.endswith('.' + domain):
            return True
    return False


def _upsert_relationship(db, tenant_id: int, source_asset_id: int,
                         target_asset_id: int, rel_type: str,
                         metadata: dict = None) -> bool:
    """Upsert a Relationship edge between two assets.

    Returns True if a new relationship was created, False if an existing
    one was updated.
    """
    from sqlalchemy.exc import IntegrityError

    existing = db.query(Relationship).filter(
        Relationship.tenant_id == tenant_id,
        Relationship.source_asset_id == source_asset_id,
        Relationship.target_asset_id == target_asset_id,
        Relationship.rel_type == rel_type,
    ).first()

    if existing:
        existing.last_seen_at = datetime.now(timezone.utc)
        return False

    rel = Relationship(
        tenant_id=tenant_id,
        source_asset_id=source_asset_id,
        target_asset_id=target_asset_id,
        rel_type=rel_type,
        rel_metadata=metadata or {},
        first_seen_at=datetime.now(timezone.utc),
        last_seen_at=datetime.now(timezone.utc),
    )
    db.add(rel)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        return False
    return True


def _extract_parent_domain(identifier: str) -> Optional[str]:
    """Extract the parent domain from a subdomain identifier.

    For example:
        'api.example.com'   -> 'example.com'
        'a.b.example.co.uk' -> 'example.co.uk'  (approximation)
        'example.com'       -> None  (already a root domain)

    Uses a simple heuristic: strip the leftmost label. For known
    two-part TLDs (co.uk, com.au, etc.) an extra label is kept.
    """
    parts = identifier.lower().strip('.').split('.')
    if len(parts) <= 2:
        return None  # Already a root-level domain (e.g. example.com)

    # Common two-part TLDs where the "real" root is three labels
    two_part_tlds = {
        'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'com.au', 'org.au',
        'co.nz', 'co.za', 'co.in', 'co.jp', 'or.jp', 'ne.jp',
        'com.br', 'org.br', 'co.kr', 'or.kr', 'com.cn', 'org.cn',
        'com.mx', 'com.ar', 'com.tw', 'co.il', 'co.th',
    }

    tld_candidate = '.'.join(parts[-2:])
    if tld_candidate in two_part_tlds:
        # Root domain needs at least 3 labels (e.g. example.co.uk)
        if len(parts) <= 3:
            return None
        return '.'.join(parts[-3:])
    else:
        return '.'.join(parts[-2:])


# ============================================================================
# PHASE IMPLEMENTATIONS
# ============================================================================

def _phase_0_seed_ingestion(tenant_id, project_id, scan_run_id, db, tenant_logger):
    """Phase 0: Parse seeds from project, validate scope, create initial assets.

    After upserting seed assets, counts total active assets available for
    subsequent pipeline phases. This ensures the stats reflect the real
    scanning surface rather than just newly-created rows.
    """
    from app.models.scanning import Project, Scope, Observation
    from app.models.database import Asset, AssetType, Seed

    project = db.query(Project).filter(Project.id == project_id).first()
    seeds = project.seeds or []

    if not seeds:
        # Fall back to tenant seeds
        tenant_seeds = db.query(Seed).filter(
            Seed.tenant_id == tenant_id,
            Seed.enabled == True
        ).all()
        seeds = [{'type': s.type, 'value': s.value} for s in tenant_seeds]

    if not seeds:
        raise ValueError("No seeds configured for project or tenant")

    # Load scope rules
    scopes = db.query(Scope).filter(Scope.project_id == project_id).all()

    assets_created = 0
    assets_updated = 0
    for seed in seeds:
        seed_type = seed.get('type', 'domain')
        seed_value = seed.get('value', '').strip()

        if not seed_value:
            continue

        # Determine asset type
        if seed_type in ('domain', 'subdomain'):
            asset_type = AssetType.DOMAIN
        elif seed_type == 'ip':
            asset_type = AssetType.IP
        else:
            # For ASN, IP range - store as observation for later expansion
            obs = Observation(
                tenant_id=tenant_id,
                scan_run_id=scan_run_id,
                source='seed',
                observation_type=f'seed_{seed_type}',
                raw_data=seed
            )
            db.add(obs)
            continue

        # Check scope rules
        if not _is_in_scope(seed_value, scopes):
            tenant_logger.warning(f"Seed {seed_value} out of scope, skipping")
            continue

        # Upsert asset
        existing = db.query(Asset).filter(
            Asset.tenant_id == tenant_id,
            Asset.identifier == seed_value,
            Asset.type == asset_type
        ).first()

        if not existing:
            asset = Asset(
                tenant_id=tenant_id,
                type=asset_type,
                identifier=seed_value,
                is_active=True,
            )
            db.add(asset)
            assets_created += 1
        else:
            existing.last_seen = datetime.now(timezone.utc)
            existing.is_active = True
            assets_updated += 1

    db.commit()

    # --- Create parent_domain relationships for seeded subdomains ---
    relationships_created = 0
    seed_assets = db.query(Asset).filter(
        Asset.tenant_id == tenant_id,
        Asset.type.in_([AssetType.DOMAIN, AssetType.SUBDOMAIN]),
        Asset.is_active == True,
    ).all()

    # Build a lookup by identifier so we can find parent assets
    asset_by_identifier = {a.identifier.lower(): a for a in seed_assets}

    for asset in seed_assets:
        parent_domain = _extract_parent_domain(asset.identifier)
        if parent_domain and parent_domain in asset_by_identifier:
            parent_asset = asset_by_identifier[parent_domain]
            if _upsert_relationship(
                db, tenant_id,
                source_asset_id=asset.id,
                target_asset_id=parent_asset.id,
                rel_type='parent_domain',
                metadata={'source': 'seed_ingestion'},
            ):
                relationships_created += 1

    if relationships_created:
        db.commit()

    # Count total active assets available for subsequent phases
    total_active = db.query(Asset).filter(
        Asset.tenant_id == tenant_id,
        Asset.is_active == True
    ).count()

    return {
        'seeds_processed': len(seeds),
        'assets_discovered': assets_created,
        'assets_updated': assets_updated,
        'relationships_created': relationships_created,
        'total_active_assets': total_active,
    }


def _is_in_scope(value: str, scopes: list) -> bool:
    """Check if a value is within project scope rules."""
    import re
    import ipaddress

    if not scopes:
        return True  # No scope rules = everything in scope

    # Check exclude rules first
    for scope in scopes:
        if scope.rule_type != 'exclude':
            continue
        if _scope_matches(value, scope):
            return False

    # Check include rules
    include_rules = [s for s in scopes if s.rule_type == 'include']
    if not include_rules:
        return True  # No include rules = everything included

    for scope in include_rules:
        if _scope_matches(value, scope):
            return True

    return False


def _scope_matches(value: str, scope) -> bool:
    """Check if a value matches a scope rule."""
    import re
    import ipaddress

    if scope.match_type == 'domain':
        pattern = scope.pattern.lower()
        v = value.lower()
        return v == pattern or v.endswith('.' + pattern)

    elif scope.match_type == 'regex':
        return bool(re.match(scope.pattern, value, re.IGNORECASE))

    elif scope.match_type == 'ip':
        return value == scope.pattern

    elif scope.match_type == 'cidr':
        try:
            network = ipaddress.ip_network(scope.pattern, strict=False)
            ip = ipaddress.ip_address(value)
            return ip in network
        except ValueError:
            return False

    return False


def _phase_1_passive_discovery(tenant_id, project_id, scan_run_id, db, tenant_logger):
    """Phase 1: Run subfinder + crt.sh for passive subdomain discovery."""
    from app.tasks.discovery import run_subfinder
    from app.models.database import Asset, AssetType

    # Get root domains from assets
    domains = db.query(Asset.identifier).filter(
        Asset.tenant_id == tenant_id,
        Asset.type == AssetType.DOMAIN,
        Asset.is_active == True
    ).all()
    domain_list = [d[0] for d in domains]

    if not domain_list:
        return {'assets_discovered': 0, 'domains_checked': 0}

    # run_subfinder expects (seed_data: dict, tenant_id: int)
    seed_data = {'domains': domain_list}
    result = run_subfinder(seed_data, tenant_id)

    # Count subdomains found, filter to in-scope only
    subdomains = result.get('subdomains', []) if isinstance(result, dict) else []
    seed_domains = _get_seed_domains(tenant_id, project_id, db)
    subdomains = [s for s in subdomains if _is_hostname_in_scope(s.strip().lower(), seed_domains)]
    assets_discovered = len(subdomains)

    # Upsert discovered subdomains as assets
    for sub in subdomains:
        sub = sub.strip().lower()
        if not sub:
            continue
        existing = db.query(Asset.id).filter(
            Asset.tenant_id == tenant_id,
            Asset.identifier == sub
        ).first()
        if not existing:
            db.add(Asset(
                tenant_id=tenant_id,
                type=AssetType.SUBDOMAIN,
                identifier=sub,
                is_active=True,
            ))
    if subdomains:
        db.commit()

    # Run crt.sh Certificate Transparency log search
    crtsh_total = 0
    crtsh_new = 0
    for domain in domain_list:
        try:
            total, new = _query_crtsh(domain, tenant_id, db, tenant_logger)
            crtsh_total += total
            crtsh_new += new
        except Exception as e:
            tenant_logger.warning(f"crt.sh query failed for {domain} (non-fatal): {e}")

    assets_discovered += crtsh_new

    return {
        'assets_discovered': assets_discovered,
        'crtsh_found': crtsh_total,
        'crtsh_new': crtsh_new,
        'domains_checked': len(domain_list),
    }


def _query_crtsh(domain: str, tenant_id: int, db, tenant_logger) -> tuple[int, int]:
    """Query crt.sh Certificate Transparency logs for subdomains.

    Returns:
        Tuple of (total_found, new_created).
    """
    import requests as req_lib
    from app.models.database import Asset, AssetType

    url = f"https://crt.sh/?q=%.{domain}&output=json"
    try:
        resp = req_lib.get(url, timeout=30, headers={'User-Agent': 'EASM-Scanner/1.0'})
        if resp.status_code != 200:
            return 0, 0

        entries = resp.json()
    except (req_lib.RequestException, ValueError) as exc:
        tenant_logger.debug("crt.sh query for %s failed: %s", domain, exc)
        return 0, 0

    # Extract unique subdomain names from CN and SAN fields
    seen = set()
    for entry in entries:
        name_value = entry.get('name_value', '')
        for name in name_value.split('\n'):
            name = name.strip().lower()
            if name and '*' not in name and name.endswith('.' + domain):
                seen.add(name)

    # Upsert discovered subdomains
    created = 0
    for subdomain in seen:
        existing = db.query(Asset.id).filter(
            Asset.tenant_id == tenant_id,
            Asset.identifier == subdomain
        ).first()
        if not existing:
            asset = Asset(
                tenant_id=tenant_id,
                type=AssetType.SUBDOMAIN,
                identifier=subdomain,
                is_active=True,
            )
            db.add(asset)
            created += 1

    if created:
        db.commit()
        tenant_logger.info(f"crt.sh found {created} new subdomains for {domain}")

    return len(seen), created


def _phase_1b_github_dorking(tenant_id, project_id, scan_run_id, db, tenant_logger):
    """Phase 1b: GitHub code search for leaked secrets."""
    # Will be implemented in Phase 3 of the plan
    return {'findings_created': 0, 'status': 'stub'}


def _phase_1c_whois_discovery(tenant_id, project_id, scan_run_id, db, tenant_logger):
    """Phase 1c: WHOIS/RDAP + reverse WHOIS + GeoIP + CDN/WAF discovery.

    Enriches all active domain, subdomain, and IP assets with:
    - WHOIS registration data (registrar, org, dates, nameservers)
    - Reverse DNS (PTR records)
    - ASN / BGP information
    - GeoIP geolocation (country, city, lat/lon)
    - CDN detection (Cloudflare, Akamai, Fastly, etc.)
    - WAF detection (Cloudflare, AWS WAF, Imperva, etc.)
    - Cloud provider detection (AWS, GCP, Azure, etc.)

    Results are stored in asset.raw_metadata under structured keys.
    """
    from app.tasks.network_enrichment import phase_1c_network_enrichment
    from app.models.database import Asset, AssetType

    # Only enrich root DOMAIN + IP assets with full WHOIS/GeoIP.
    # Subdomains share the same WHOIS as their parent domain, so running
    # WHOIS on each one is redundant and slow (~0.5-2s per lookup × hundreds).
    # CDN/WAF detection for subdomains is handled in Phase 5b (cdncheck).
    assets = db.query(Asset).filter(
        Asset.tenant_id == tenant_id,
        Asset.type.in_([AssetType.DOMAIN, AssetType.IP]),
        Asset.is_active == True  # noqa: E712
    ).all()

    if not assets:
        return {'assets_discovered': 0, 'assets_enriched': 0}

    asset_ids = [a.id for a in assets]
    tenant_logger.info(
        f"Phase 1c: {len(asset_ids)} assets for network enrichment "
        f"(domains + IPs only, subdomains inherit WHOIS from parent)"
    )

    return phase_1c_network_enrichment(tenant_id, asset_ids, db, tenant_logger)


def _phase_1d_cloud_buckets(tenant_id, project_id, scan_run_id, db, tenant_logger):
    """Phase 1d: Cloud Bucket/Storage Discovery.

    Generates bucket name permutations from root domains and subdomains,
    then probes AWS S3, Google Cloud Storage, Azure Blob Storage, and
    DigitalOcean Spaces for publicly accessible buckets.

    Runs after seed ingestion and passive discovery so that both root domains
    and discovered subdomains are available as inputs for name generation.
    """
    from app.tasks.cloud_scan import run_cloud_bucket_scan
    from app.models.database import Asset, AssetType

    # Only use ROOT domains for bucket name generation (not subdomains).
    # Subdomains like mail.example.com generate too many useless permutations.
    assets = db.query(Asset).filter(
        Asset.tenant_id == tenant_id,
        Asset.type == AssetType.DOMAIN,
        Asset.is_active == True  # noqa: E712
    ).all()

    if not assets:
        return {'findings_created': 0, 'domains_processed': 0}

    asset_ids = [a.id for a in assets]
    tenant_logger.info(f"Cloud bucket scan: {len(asset_ids)} domain assets")

    result = run_cloud_bucket_scan(
        tenant_id, asset_ids, db=db, scan_run_id=scan_run_id
    )

    return {
        'findings_created': result.get('findings_created', 0) if isinstance(result, dict) else 0,
        'findings_updated': result.get('findings_updated', 0) if isinstance(result, dict) else 0,
        'domains_processed': result.get('domains_processed', 0) if isinstance(result, dict) else 0,
        'bucket_names_generated': result.get('bucket_names_generated', 0) if isinstance(result, dict) else 0,
        'targets_probed': result.get('targets_probed', 0) if isinstance(result, dict) else 0,
        'buckets_found': result.get('buckets_found', 0) if isinstance(result, dict) else 0,
    }


def _phase_1e_cloud_enum(tenant_id, project_id, scan_run_id, db, tenant_logger):
    """Phase 1e: Cloud asset enumeration with cloudlist.

    Reads cloud provider credentials from project.settings['cloud_providers'],
    runs cloudlist, and upserts discovered IPs/hostnames as assets.
    """
    from app.tasks.cloud_enum import run_cloudlist
    from app.models.database import Asset, AssetType
    from app.models.scanning import Project

    project = db.query(Project).filter(Project.id == project_id).first()
    provider_config = (project.settings or {}).get('cloud_providers', [])

    if not provider_config:
        return {'assets_discovered': 0, 'providers_scanned': 0}

    cloud_assets = run_cloudlist(tenant_id, provider_config)

    assets_created = 0
    for ca in cloud_assets:
        identifier = ca.get('hostname') or ca.get('ip', '')
        if not identifier:
            continue

        asset_type = AssetType.IP if _is_ip(identifier) else AssetType.SUBDOMAIN

        existing = db.query(Asset).filter(
            Asset.tenant_id == tenant_id,
            Asset.identifier == identifier,
            Asset.type == asset_type,
        ).first()

        if not existing:
            asset = Asset(
                tenant_id=tenant_id,
                type=asset_type,
                identifier=identifier,
                is_active=True,
                cloud_provider=ca.get('provider', ''),
            )
            db.add(asset)
            assets_created += 1
        else:
            existing.last_seen = datetime.now(timezone.utc)
            existing.is_active = True
            if ca.get('provider'):
                existing.cloud_provider = ca['provider']

    db.commit()

    return {
        'assets_discovered': assets_created,
        'providers_scanned': len(provider_config),
        'total_cloud_assets': len(cloud_assets),
    }


def _phase_2_dns_bruteforce(tenant_id, project_id, scan_run_id, db, tenant_logger, scan_tier=2):
    """Phase 2: DNS permutation & bruteforce with alterx + puredns.

    1. Reads known subdomains/domains from the DB
    2. Generates permutation candidates via alterx
    3. Validates candidates with puredns (wildcard filtering)
    4. Upserts validated subdomains as new assets
    """
    from app.tasks.dns_bruteforce import run_alterx, run_puredns
    from app.models.database import Asset, AssetType

    # Gather known subdomains
    subdomains = db.query(Asset).filter(
        Asset.tenant_id == tenant_id,
        Asset.type.in_([AssetType.DOMAIN, AssetType.SUBDOMAIN]),
        Asset.is_active == True,
    ).all()

    if not subdomains:
        return {'assets_discovered': 0, 'candidates_generated': 0}

    subdomain_list = [a.identifier for a in subdomains]

    # DNS rate limits per tier (queries/second — distributed across resolvers)
    tier_rate = {2: 200, 3: 300}
    rate = tier_rate.get(scan_tier, 200)

    # Generate permutations
    candidates = run_alterx(subdomain_list, tenant_id)
    tenant_logger.info("alterx generated %d permutation candidates", len(candidates))

    # Validate via puredns
    validated = run_puredns(candidates, tenant_id, rate=rate)
    tenant_logger.info("puredns validated %d / %d candidates", len(validated), len(candidates))

    # Filter validated hostnames to only in-scope domains
    seed_domains = _get_seed_domains(tenant_id, project_id, db)
    in_scope = [h for h in validated if _is_hostname_in_scope(h.strip().lower(), seed_domains)]
    if len(in_scope) < len(validated):
        tenant_logger.info(
            f"Scope filter: {len(in_scope)} in-scope, "
            f"{len(validated) - len(in_scope)} out-of-scope filtered"
        )
    validated = in_scope

    # Upsert validated subdomains
    assets_created = 0
    relationships_created = 0
    for hostname in validated:
        hostname = hostname.strip().lower()
        if not hostname:
            continue

        existing = db.query(Asset).filter(
            Asset.tenant_id == tenant_id,
            Asset.identifier == hostname,
            Asset.type == AssetType.SUBDOMAIN,
        ).first()

        if not existing:
            asset = Asset(
                tenant_id=tenant_id,
                type=AssetType.SUBDOMAIN,
                identifier=hostname,
                is_active=True,
            )
            db.add(asset)
            db.flush()
            assets_created += 1

            # Create parent_domain relationship
            parent_domain = _extract_parent_domain(hostname)
            if parent_domain:
                parent_asset = db.query(Asset).filter(
                    Asset.tenant_id == tenant_id,
                    Asset.identifier == parent_domain,
                    Asset.type.in_([AssetType.DOMAIN, AssetType.SUBDOMAIN]),
                ).first()
                if parent_asset:
                    if _upsert_relationship(
                        db, tenant_id,
                        source_asset_id=asset.id,
                        target_asset_id=parent_asset.id,
                        rel_type='parent_domain',
                        metadata={'source': 'dns_bruteforce'},
                    ):
                        relationships_created += 1
        else:
            existing.last_seen = datetime.now(timezone.utc)
            existing.is_active = True

    db.commit()

    return {
        'assets_discovered': assets_created,
        'candidates_generated': len(candidates),
        'candidates_validated': len(validated),
        'relationships_created': relationships_created,
    }


def _phase_3_dns_resolution(tenant_id, project_id, scan_run_id, db, tenant_logger):
    """Phase 3: DNS resolution with DNSX.

    After resolving DNS records this phase creates relationship edges:
    - resolves_to:   subdomain/domain -> IP  (A/AAAA records)
    - cname_to:      subdomain/domain -> CNAME target
    - parent_domain: subdomain -> parent domain hierarchy
    """
    from app.tasks.discovery import run_dnsx
    from app.models.database import Asset, AssetType

    # Get all subdomains to resolve
    subdomains = db.query(Asset).filter(
        Asset.tenant_id == tenant_id,
        Asset.type.in_([AssetType.DOMAIN, AssetType.SUBDOMAIN]),
        Asset.is_active == True
    ).all()

    if not subdomains:
        return {'records_resolved': 0, 'relationships_created': 0}

    subdomain_list = [a.identifier for a in subdomains]

    # run_dnsx expects (subfinder_result: dict, tenant_id: int)
    subfinder_result = {'subdomains': subdomain_list}
    result = run_dnsx(subfinder_result, tenant_id)

    resolved = result.get('resolved', []) if isinstance(result, dict) else []

    # Collect unique IPs from all resolved records
    unique_ips = set()
    for record in resolved:
        for ip in record.get('a', []):
            unique_ips.add(ip)
        for ip in record.get('aaaa', []):
            unique_ips.add(ip)

    # Collect unique CNAME targets (they may be new subdomains)
    unique_cnames = set()
    for record in resolved:
        for cname in record.get('cname', []):
            cname = cname.strip().rstrip('.').lower()
            if cname:
                unique_cnames.add(cname)

    # Create IP assets (deduped, skip existing)
    ips_created = 0
    for ip in unique_ips:
        existing = db.query(Asset.id).filter(
            Asset.tenant_id == tenant_id,
            Asset.identifier == ip
        ).first()
        if not existing:
            db.add(Asset(
                tenant_id=tenant_id,
                type=AssetType.IP,
                identifier=ip,
                is_active=True,
            ))
            ips_created += 1
    if ips_created:
        db.commit()

    # Ensure CNAME targets exist as assets (subdomains), but only if in scope.
    # CNAME chains often point to CDN/cloud infrastructure (b-cdn.net,
    # azureedge.net, etc.) that we must NOT scan.
    seed_domains = _get_seed_domains(tenant_id, project_id, db)
    cnames_created = 0
    cnames_skipped = 0
    for cname in unique_cnames:
        if not _is_hostname_in_scope(cname, seed_domains):
            cnames_skipped += 1
            continue
        existing = db.query(Asset.id).filter(
            Asset.tenant_id == tenant_id,
            Asset.identifier == cname,
        ).first()
        if not existing:
            db.add(Asset(
                tenant_id=tenant_id,
                type=AssetType.SUBDOMAIN,
                identifier=cname,
                is_active=True,
            ))
            cnames_created += 1
    if cnames_created:
        db.commit()
    if cnames_skipped:
        tenant_logger.info(
            f"Skipped {cnames_skipped} out-of-scope CNAME targets "
            f"(CDN/cloud infrastructure)"
        )

    # ------------------------------------------------------------------
    # Build asset lookup for relationship creation
    # ------------------------------------------------------------------
    all_assets = db.query(Asset).filter(
        Asset.tenant_id == tenant_id,
        Asset.is_active == True,
    ).all()
    asset_by_identifier = {a.identifier.lower(): a for a in all_assets}

    relationships_created = 0

    for record in resolved:
        host = record.get('host', '').lower()
        source_asset = asset_by_identifier.get(host)
        if not source_asset:
            continue

        # --- resolves_to: subdomain/domain -> IP (A records) ---
        for ip in record.get('a', []):
            target_asset = asset_by_identifier.get(ip)
            if target_asset:
                if _upsert_relationship(
                    db, tenant_id,
                    source_asset_id=source_asset.id,
                    target_asset_id=target_asset.id,
                    rel_type='resolves_to',
                    metadata={'record_type': 'A', 'value': ip},
                ):
                    relationships_created += 1

        # --- resolves_to: subdomain/domain -> IP (AAAA records) ---
        for ip in record.get('aaaa', []):
            target_asset = asset_by_identifier.get(ip)
            if target_asset:
                if _upsert_relationship(
                    db, tenant_id,
                    source_asset_id=source_asset.id,
                    target_asset_id=target_asset.id,
                    rel_type='resolves_to',
                    metadata={'record_type': 'AAAA', 'value': ip},
                ):
                    relationships_created += 1

        # --- cname_to: subdomain/domain -> CNAME target ---
        for cname in record.get('cname', []):
            cname_clean = cname.strip().rstrip('.').lower()
            target_asset = asset_by_identifier.get(cname_clean)
            if target_asset:
                if _upsert_relationship(
                    db, tenant_id,
                    source_asset_id=source_asset.id,
                    target_asset_id=target_asset.id,
                    rel_type='cname_to',
                    metadata={'cname': cname_clean},
                ):
                    relationships_created += 1

        # --- parent_domain: subdomain -> parent domain ---
        parent_domain = _extract_parent_domain(host)
        if parent_domain:
            parent_asset = asset_by_identifier.get(parent_domain)
            if parent_asset:
                if _upsert_relationship(
                    db, tenant_id,
                    source_asset_id=source_asset.id,
                    target_asset_id=parent_asset.id,
                    rel_type='parent_domain',
                    metadata={'source': 'dns_resolution'},
                ):
                    relationships_created += 1

    if relationships_created:
        db.commit()

    tenant_logger.info(
        f"Phase 3 relationships: {relationships_created} edges created "
        f"(resolves_to, cname_to, parent_domain)"
    )

    return {
        'records_resolved': len(resolved),
        'ips_created': ips_created,
        'cnames_created': cnames_created,
        'hosts_resolved': len(subdomain_list),
        'relationships_created': relationships_created,
    }


def _phase_4_http_probing(tenant_id, project_id, scan_run_id, db, tenant_logger):
    """Phase 4: HTTP probing with HTTPx.

    Probes all active domain, subdomain, and IP assets for HTTP/HTTPS
    services. Results are stored as Service records linked to assets.

    After probing, creates ``hosts`` relationship edges from each asset
    to every Service-type asset discovered on it (one edge per distinct
    port).
    """
    from app.tasks.enrichment import run_httpx
    from app.models.database import Asset, AssetType, Service

    assets = db.query(Asset).filter(
        Asset.tenant_id == tenant_id,
        Asset.type.in_([AssetType.DOMAIN, AssetType.SUBDOMAIN, AssetType.IP]),
        Asset.is_active == True
    ).all()

    if not assets:
        tenant_logger.warning("No active assets for HTTP probing")
        return {'services_discovered': 0, 'hosts_probed': 0, 'relationships_created': 0}

    asset_ids = [a.id for a in assets]
    tenant_logger.info(f"HTTPx: probing {len(asset_ids)} assets")
    result = run_httpx(tenant_id, asset_ids)

    services_created = result.get('services_created', 0) if isinstance(result, dict) else 0
    services_updated = result.get('services_updated', 0) if isinstance(result, dict) else 0

    # ------------------------------------------------------------------
    # Create 'hosts' edges: asset -> service asset
    #
    # The Service table links services to assets, but the Relationship
    # table needs asset-to-asset edges. We model each (asset, port)
    # pair as a logical "hosts" edge from the asset to itself. If
    # dedicated SERVICE-type assets existed we would link to those;
    # for now we create an asset of type SERVICE for each unique
    # (identifier:port) so the graph can visualize them.
    # ------------------------------------------------------------------
    relationships_created = 0

    # Refresh the session to pick up services written by run_httpx
    db.expire_all()

    for asset in assets:
        services = db.query(Service).filter(
            Service.asset_id == asset.id,
        ).all()

        for svc in services:
            if svc.port is None:
                continue

            # Upsert a SERVICE-type asset for the (host, port) combo
            svc_identifier = f"{asset.identifier}:{svc.port}"
            svc_asset = db.query(Asset).filter(
                Asset.tenant_id == tenant_id,
                Asset.identifier == svc_identifier,
                Asset.type == AssetType.SERVICE,
            ).first()

            if not svc_asset:
                svc_asset = Asset(
                    tenant_id=tenant_id,
                    type=AssetType.SERVICE,
                    identifier=svc_identifier,
                    is_active=True,
                )
                db.add(svc_asset)
                db.flush()  # Get the id for the relationship

            # Create the hosts relationship: domain/IP -> service
            if _upsert_relationship(
                db, tenant_id,
                source_asset_id=asset.id,
                target_asset_id=svc_asset.id,
                rel_type='hosts',
                metadata={
                    'port': svc.port,
                    'protocol': svc.protocol,
                    'http_status': svc.http_status,
                    'web_server': svc.web_server,
                },
            ):
                relationships_created += 1

    if relationships_created:
        db.commit()

    tenant_logger.info(
        f"Phase 4 relationships: {relationships_created} 'hosts' edges created"
    )

    return {
        'services_discovered': services_created + services_updated,
        'services_created': services_created,
        'services_updated': services_updated,
        'hosts_probed': len(asset_ids),
        'relationships_created': relationships_created,
    }


def _phase_4b_tls_collection(tenant_id, project_id, scan_run_id, db, tenant_logger):
    """Phase 4b: TLS certificate collection with tlsx.

    Runs tlsx against all active DOMAIN and SUBDOMAIN assets to collect
    TLS/SSL certificate metadata (validity, SANs, cipher suites, TLS
    versions, certificate chain). Results are stored as Certificate
    records and linked Service records via the enrichment task.
    """
    from app.tasks.enrichment import run_tlsx
    from app.models.database import Asset, AssetType

    assets = db.query(Asset).filter(
        Asset.tenant_id == tenant_id,
        Asset.type.in_([AssetType.DOMAIN, AssetType.SUBDOMAIN]),
        Asset.is_active == True,
    ).all()

    if not assets:
        tenant_logger.warning("No active domain/subdomain assets for TLS collection")
        return {'certificates_collected': 0, 'hosts_analyzed': 0}

    asset_ids = [a.id for a in assets]
    tenant_logger.info(f"TLSx: collecting certificates from {len(asset_ids)} assets")
    result = run_tlsx(tenant_id, asset_ids)

    certificates_collected = result.get('certificates_discovered', 0) if isinstance(result, dict) else 0
    certificates_created = result.get('certificates_created', 0) if isinstance(result, dict) else 0
    certificates_updated = result.get('certificates_updated', 0) if isinstance(result, dict) else 0
    hosts_analyzed = result.get('hosts_analyzed', 0) if isinstance(result, dict) else 0

    return {
        'certificates_collected': certificates_collected,
        'certificates_created': certificates_created,
        'certificates_updated': certificates_updated,
        'hosts_analyzed': hosts_analyzed,
    }


def _phase_5_port_scanning(tenant_id, project_id, scan_run_id, db, tenant_logger, scan_tier=1):
    """Phase 5: Port scanning with Naabu. Ports/rate depend on scan tier.

    The scan_tier controls the full_scan parameter passed to run_naabu:
    - Tier 1 (Safe):       top ports (default), full_scan=False
    - Tier 2 (Moderate):   top ports (default), full_scan=False
    - Tier 3 (Aggressive): all 65535 ports,     full_scan=True
    """
    from app.tasks.enrichment import run_naabu
    from app.models.database import Asset, AssetType

    # Tier-based port configuration
    # Tier 1 uses top-100 with 300s timeout (connect scan in Docker is slow)
    tier_config = {
        1: {'top_ports': '100', 'rate': 100, 'full_scan': False, 'timeout': 300},
        2: {'top_ports': '1000', 'rate': 500, 'full_scan': False, 'timeout': 600},
        3: {'top_ports': '1000', 'rate': 1000, 'full_scan': False, 'timeout': 600},
    }
    config = tier_config.get(scan_tier, tier_config[1])

    # Apply adaptive throttle if active
    from app.services.adaptive_throttle import get_throttle
    throttle = get_throttle(tenant_id, scan_run_id)
    effective_rate = throttle.get_rate(config['rate'])

    # Get domains/subdomains — naabu resolves hostnames to IPs internally,
    # so scanning both a subdomain AND its resolved IP is redundant.
    # Only include standalone IPs (not the target of any resolves_to relationship).
    hostname_assets = db.query(Asset).filter(
        Asset.tenant_id == tenant_id,
        Asset.type.in_([AssetType.DOMAIN, AssetType.SUBDOMAIN]),
        Asset.is_active == True,
    ).all()

    # Find IPs that are NOT covered by any hostname (standalone IPs from seeds/uncover)
    from sqlalchemy import exists
    covered_ip_ids = {
        r.target_asset_id for r in db.query(Relationship.target_asset_id).filter(
            Relationship.tenant_id == tenant_id,
            Relationship.rel_type == 'resolves_to',
        ).all()
    }
    standalone_ips = db.query(Asset).filter(
        Asset.tenant_id == tenant_id,
        Asset.type == AssetType.IP,
        Asset.is_active == True,
        ~Asset.id.in_(covered_ip_ids) if covered_ip_ids else True,
    ).all()

    assets = hostname_assets + standalone_ips

    if not assets:
        return {'ports_discovered': 0, 'scan_tier': scan_tier}

    asset_ids = [a.id for a in assets]
    tenant_logger.info(
        f"Naabu: top_ports={config['top_ports']}, rate={effective_rate} pkt/s "
        f"{'(throttled) ' if throttle.is_throttled else ''}"
        f"full_scan={config['full_scan']} (tier {scan_tier}), "
        f"targets={len(asset_ids)} ({len(hostname_assets)} hostnames + {len(standalone_ips)} standalone IPs, "
        f"{len(covered_ip_ids)} duplicate IPs skipped)"
    )
    result = run_naabu(
        tenant_id, asset_ids, full_scan=config['full_scan'],
        rate=effective_rate, timeout=config.get('timeout'),
    )

    return {
        'ports_discovered': result.get('ports_discovered', 0) if isinstance(result, dict) else 0,
        'services_created': result.get('services_created', 0) if isinstance(result, dict) else 0,
        'hosts_scanned': result.get('hosts_scanned', 0) if isinstance(result, dict) else 0,
        'scan_tier': scan_tier,
        'top_ports': config['top_ports'],
        'rate': config['rate'],
    }


def _is_ip(value: str) -> bool:
    """Check if a string is an IP address."""
    import ipaddress
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _phase_5b_cdn_detection(tenant_id, project_id, scan_run_id, db, tenant_logger):
    """Phase 5b: CDN/WAF detection with cdncheck.

    Runs on all tiers (read-only DNS lookup). Updates cdn_name, waf_name,
    and cloud_provider columns on the Asset model.
    """
    from app.tasks.service_fingerprint import run_cdncheck
    from app.models.database import Asset, AssetType

    assets = db.query(Asset).filter(
        Asset.tenant_id == tenant_id,
        Asset.type.in_([AssetType.DOMAIN, AssetType.SUBDOMAIN, AssetType.IP]),
        Asset.is_active == True,
    ).all()

    if not assets:
        return {'hosts_checked': 0, 'cdn_detected': 0, 'waf_detected': 0}

    hosts = [a.identifier for a in assets]
    results = run_cdncheck(hosts, tenant_id)

    cdn_count = 0
    waf_count = 0
    updated = 0

    for asset in assets:
        info = results.get(asset.identifier)
        if not info:
            continue

        changed = False
        if info.get('cdn') and info.get('cdn_name'):
            asset.cdn_name = info['cdn_name']
            cdn_count += 1
            changed = True
        if info.get('waf') and info.get('waf_name'):
            asset.waf_name = info['waf_name']
            waf_count += 1
            changed = True
        if info.get('cloud'):
            asset.cloud_provider = info['cloud']
            changed = True

        if changed:
            updated += 1

    db.commit()

    return {
        'hosts_checked': len(results),
        'cdn_detected': cdn_count,
        'waf_detected': waf_count,
        'assets_updated': updated,
    }


def _phase_5c_service_fingerprint(tenant_id, project_id, scan_run_id, db, tenant_logger):
    """Phase 5c: Service fingerprinting with fingerprintx.

    Runs on open ports discovered by naabu (Phase 5). Updates service
    product/version with more accurate protocol-level identification.
    """
    from app.tasks.service_fingerprint import run_fingerprintx
    from app.models.database import Asset, AssetType, Service

    # Build host:port targets from services table
    services = db.query(Service).join(Asset).filter(
        Asset.tenant_id == tenant_id,
        Asset.is_active == True,
        Service.port.isnot(None),
    ).all()

    if not services:
        return {'services_fingerprinted': 0, 'protocols_identified': 0}

    # Build target list as host:port
    targets = []
    service_map: dict[str, Service] = {}
    for svc in services:
        asset = svc.asset
        if asset and svc.port:
            target = f"{asset.identifier}:{svc.port}"
            targets.append(target)
            service_map[target] = svc

    if not targets:
        return {'services_fingerprinted': 0, 'protocols_identified': 0}

    results = run_fingerprintx(targets, tenant_id)

    protocols_identified = 0
    services_updated = 0

    for entry in results:
        host = entry.get('host', '')
        port = entry.get('port', 0)
        target_key = f"{host}:{port}"

        svc = service_map.get(target_key)
        if not svc:
            continue

        # Update with more precise fingerprint data
        if entry.get('service'):
            svc.product = entry['service']
            services_updated += 1
        if entry.get('version'):
            svc.version = entry['version']
        if entry.get('protocol'):
            svc.protocol = entry['protocol']
            protocols_identified += 1
        if entry.get('tls'):
            svc.has_tls = True
        # Mark enrichment source
        svc.enrichment_source = 'fingerprintx'

    db.commit()

    return {
        'services_fingerprinted': services_updated,
        'protocols_identified': protocols_identified,
        'targets_scanned': len(targets),
    }


def _phase_6_fingerprinting(tenant_id, project_id, scan_run_id, db, tenant_logger):
    """Phase 6: Technology fingerprinting."""
    from app.tasks.fingerprint import run_fingerprinting

    result = run_fingerprinting(tenant_id, scan_run_id=scan_run_id)

    if isinstance(result, dict):
        return {
            'technologies_detected': result.get('technologies_detected', 0),
            'services_fingerprinted': result.get('services_analyzed', 0),
        }
    return {'technologies_detected': 0}


def _phase_6b_web_crawling(tenant_id, project_id, scan_run_id, db, tenant_logger):
    """Phase 6b: Web crawling with Katana.

    Katana depends on live HTTP services discovered by Phase 4 (HTTPx).
    Only crawls hostnames + standalone IPs (skip IPs already resolved from hostnames).
    """
    from app.tasks.enrichment import run_katana
    from app.models.database import Asset, AssetType

    hostname_assets = db.query(Asset).filter(
        Asset.tenant_id == tenant_id,
        Asset.type.in_([AssetType.DOMAIN, AssetType.SUBDOMAIN]),
        Asset.is_active == True,
    ).all()

    covered_ip_ids = {
        r.target_asset_id for r in db.query(Relationship.target_asset_id).filter(
            Relationship.tenant_id == tenant_id,
            Relationship.rel_type == 'resolves_to',
        ).all()
    }
    standalone_ips = db.query(Asset).filter(
        Asset.tenant_id == tenant_id,
        Asset.type == AssetType.IP,
        Asset.is_active == True,
        ~Asset.id.in_(covered_ip_ids) if covered_ip_ids else True,
    ).all()

    assets = hostname_assets + standalone_ips

    if not assets:
        return {'endpoints_discovered': 0}

    asset_ids = [a.id for a in assets]
    tenant_logger.info(f"Katana: crawling {len(asset_ids)} assets (deduped IPs)")
    result = run_katana(tenant_id, asset_ids)

    return {
        'endpoints_discovered': result.get('endpoints_discovered', 0) if isinstance(result, dict) else 0,
        'endpoints_created': result.get('endpoints_created', 0) if isinstance(result, dict) else 0,
        'urls_crawled': result.get('urls_crawled', 0) if isinstance(result, dict) else 0,
    }


def _phase_6c_sensitive_paths(tenant_id, project_id, scan_run_id, db, tenant_logger):
    """Phase 6c: Sensitive path discovery.

    Probes assets with HTTP services for commonly exposed sensitive paths
    (config files, VCS metadata, backups, admin panels, debug endpoints).
    Only scans hostnames + standalone IPs (skip resolved-from-hostname IPs).
    """
    from app.tasks.sensitive_paths import run_sensitive_path_scan
    from app.models.database import Asset, AssetType

    hostname_assets = db.query(Asset).filter(
        Asset.tenant_id == tenant_id,
        Asset.type.in_([AssetType.DOMAIN, AssetType.SUBDOMAIN]),
        Asset.is_active == True,
    ).all()

    covered_ip_ids = {
        r.target_asset_id for r in db.query(Relationship.target_asset_id).filter(
            Relationship.tenant_id == tenant_id,
            Relationship.rel_type == 'resolves_to',
        ).all()
    }
    standalone_ips = db.query(Asset).filter(
        Asset.tenant_id == tenant_id,
        Asset.type == AssetType.IP,
        Asset.is_active == True,
        ~Asset.id.in_(covered_ip_ids) if covered_ip_ids else True,
    ).all()

    assets = hostname_assets + standalone_ips

    if not assets:
        return {'findings_created': 0, 'assets_scanned': 0}

    asset_ids = [a.id for a in assets]
    tenant_logger.info(f"Sensitive path scan: {len(asset_ids)} assets (deduped IPs)")
    result = run_sensitive_path_scan(
        tenant_id, asset_ids, db=db, scan_run_id=scan_run_id
    )

    return {
        'findings_created': result.get('findings_created', 0) if isinstance(result, dict) else 0,
        'findings_updated': result.get('findings_updated', 0) if isinstance(result, dict) else 0,
        'assets_scanned': result.get('assets_scanned', 0) if isinstance(result, dict) else 0,
        'paths_checked': result.get('paths_checked', 0) if isinstance(result, dict) else 0,
    }


def _phase_7_visual_recon(tenant_id, project_id, scan_run_id, db, tenant_logger):
    """Phase 7: Visual Recon - capture screenshots of discovered HTTP services.

    Uses Playwright headless Chromium to screenshot all live web services.
    Stores full-size (1920x1080) and thumbnail (320x240) PNGs in MinIO.
    """
    from app.config import settings

    if not getattr(settings, 'feature_visual_recon_enabled', True):
        tenant_logger.info("Visual recon disabled in feature flags, skipping Phase 7")
        return {'screenshots_taken': 0, 'status': 'disabled'}

    from app.tasks.visual_recon import run_visual_recon
    from app.models.database import Asset, AssetType

    assets = db.query(Asset).filter(
        Asset.tenant_id == tenant_id,
        Asset.type.in_([AssetType.DOMAIN, AssetType.SUBDOMAIN, AssetType.IP]),
        Asset.is_active == True,  # noqa: E712
    ).all()

    if not assets:
        return {'screenshots_taken': 0, 'status': 'no_assets'}

    asset_ids = [a.id for a in assets]
    tenant_logger.info(f"Visual recon: {len(asset_ids)} candidate assets")

    result = run_visual_recon(
        tenant_id=tenant_id,
        asset_ids=asset_ids,
    )

    return {
        'screenshots_taken': result.get('screenshots_taken', 0) if isinstance(result, dict) else 0,
        'status': result.get('status', 'completed') if isinstance(result, dict) else 'completed',
    }


def _phase_8_misconfig_detection(tenant_id, project_id, scan_run_id, db, tenant_logger):
    """Phase 8: Misconfiguration detection (50 controls)."""
    from app.tasks.misconfig import run_misconfig_detection

    result = run_misconfig_detection(tenant_id, scan_run_id=scan_run_id)

    if isinstance(result, dict):
        return {
            'findings_created': result.get('findings_created', 0),
            'findings_updated': result.get('findings_updated', 0),
            'assets_checked': result.get('assets_checked', 0),
            'controls_executed': result.get('controls_executed', 0),
            'status': result.get('status', 'unknown'),
        }
    return {'findings_created': 0, 'status': 'unknown'}


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
    # Tier 3 excludes 'info' — those are mostly tech-detection templates
    # (4000+) that duplicate Phase 6 and add 20+ min to scan time.
    tier_severity = {
        1: ['critical', 'high'],
        2: ['critical', 'high', 'medium'],
        3: ['critical', 'high', 'medium', 'low'],
    }
    severity = tier_severity.get(scan_tier, tier_severity[1])

    # Only scan hostnames — Nuclei resolves them internally via services.
    # Skip IP assets that are already covered by a hostname's DNS resolution.
    hostname_assets = db.query(Asset).filter(
        Asset.tenant_id == tenant_id,
        Asset.type.in_([AssetType.DOMAIN, AssetType.SUBDOMAIN]),
        Asset.is_active == True,
    ).all()

    covered_ip_ids = {
        r.target_asset_id for r in db.query(Relationship.target_asset_id).filter(
            Relationship.tenant_id == tenant_id,
            Relationship.rel_type == 'resolves_to',
        ).all()
    }
    standalone_ips = db.query(Asset).filter(
        Asset.tenant_id == tenant_id,
        Asset.type == AssetType.IP,
        Asset.is_active == True,
        ~Asset.id.in_(covered_ip_ids) if covered_ip_ids else True,
    ).all()

    # Split assets: CDN-fronted hosts only get takeover/ssl checks (CVE scans
    # would hit the CDN edge, not the origin, producing false positives).
    all_assets = hostname_assets + standalone_ips
    direct_assets = [a for a in all_assets if not a.cdn_name]
    cdn_assets = [a for a in all_assets if a.cdn_name]

    if not all_assets:
        return {'findings_created': 0, 'scan_tier': scan_tier}

    asset_ids = [a.id for a in direct_assets]
    cdn_asset_ids = [a.id for a in cdn_assets]
    tenant_logger.info(
        f"Nuclei targets: {len(all_assets)} total ({len(direct_assets)} direct + "
        f"{len(cdn_assets)} CDN-fronted, {len(covered_ip_ids)} duplicate IPs skipped)"
    )

    # Interactsh OOB callback support (Tier 3 only)
    from app.config import settings as app_settings
    use_interactsh = scan_tier >= 3 and getattr(app_settings, 'interactsh_enabled', False)
    interactsh_server = ''
    if use_interactsh:
        interactsh_server = app_settings.interactsh_server or 'oast.pro'
        tenant_logger.info("Nuclei: interactsh enabled (server=%s)", interactsh_server)

    # Tier-based concurrency, rate limit, and timeout
    # Tier 1 uses reduced template set (~2k) and finishes in 5-10 min
    # Tier 2/3 use full template set (~7k) and need more time
    tier_concurrency = {1: 25, 2: 25, 3: 30}
    tier_rate_limit = {1: 150, 2: 300, 3: 500}
    tier_timeout = {1: 600, 2: 1200, 3: 1800}
    concurrency = tier_concurrency.get(scan_tier, 25)
    rate_limit = tier_rate_limit.get(scan_tier, 300)
    timeout = tier_timeout.get(scan_tier, 1800)

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

    # Tier 1 "fast" scan: only the highest-value template dirs (~2k templates).
    # dns/ and network/ are slow (many socket-based checks) and low-yield for EASM.
    # http/misconfiguration/ overlaps with Phase 8 misconfig.py (50 controls).
    # Tier 2+ gets the full set for deeper analysis.
    tier_templates = {
        1: ['http/cves/', 'http/exposed-panels/', 'http/takeovers/',
            'http/default-logins/', 'ssl/'],
        # Tier 2/3: None = use nuclei_service default (all 10 dirs)
    }
    templates_for_scan = tier_templates.get(scan_tier)

    # Pass 1: Full scan on direct (non-CDN) assets
    if asset_ids:
        result = run_nuclei_scan(
            tenant_id, asset_ids, severity=severity,
            templates=templates_for_scan,
            rate_limit=rate_limit,
            concurrency=concurrency,
            timeout=timeout,
            interactsh_server=interactsh_server if use_interactsh else None,
        )
        if isinstance(result, dict):
            total_created += result.get('findings_created', 0)
            total_updated += result.get('findings_updated', 0)
            total_scanned += result.get('assets_scanned', 0)
            total_urls += result.get('urls_scanned', 0)

    # Pass 2: CDN-fronted assets — only takeover + SSL checks (fast, ~2 min)
    if cdn_asset_ids:
        tenant_logger.info(
            f"Nuclei CDN pass: {len(cdn_asset_ids)} CDN-fronted assets "
            f"(takeovers + ssl only)"
        )
        cdn_result = run_nuclei_scan(
            tenant_id, cdn_asset_ids, severity=['critical', 'high', 'medium'],
            templates=['http/takeovers/', 'ssl/'],
            rate_limit=rate_limit,
            concurrency=concurrency,
            timeout=300,  # CDN pass is fast — 5 min max
        )
        if isinstance(cdn_result, dict):
            total_created += cdn_result.get('findings_created', 0)
            total_updated += cdn_result.get('findings_updated', 0)
            total_scanned += cdn_result.get('assets_scanned', 0)
            total_urls += cdn_result.get('urls_scanned', 0)

    return {
        'findings_created': total_created,
        'findings_updated': total_updated,
        'assets_scanned': total_scanned,
        'urls_scanned': total_urls,
        'scan_tier': scan_tier,
        'severity_filter': severity,
        'interactsh_enabled': use_interactsh,
        'cdn_assets_scanned': len(cdn_asset_ids),
    }


def _phase_10_correlation(tenant_id, project_id, scan_run_id, db, tenant_logger):
    """Phase 10: Correlation & deduplication."""
    from app.tasks.correlation import run_correlation

    result = run_correlation(tenant_id, scan_run_id=scan_run_id)

    if isinstance(result, dict):
        return {
            'issues_created': result.get('issues_created', 0),
            'issues_updated': result.get('issues_updated', 0),
            'findings_processed': result.get('findings_processed', 0),
        }
    return {'issues_created': 0}


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
        compute_issue_score, compute_org_score,
        IssueScoreInput,
    )
    from app.services.risk_scoring import recalculate_asset_risk
    from app.models.database import Asset, Finding
    from app.models.issues import Issue, IssueFinding, IssueStatus
    from app.models.risk import RiskScore

    scores_computed = 0

    # ------------------------------------------------------------------
    # 1. Score each open issue with real threat intel from linked findings
    # ------------------------------------------------------------------
    issues = db.query(Issue).filter(
        Issue.tenant_id == tenant_id,
        Issue.status.in_([
            IssueStatus.OPEN,
            IssueStatus.TRIAGED,
            IssueStatus.IN_PROGRESS,
        ]),
    ).all()

    # Build a lightweight threat intel helper (may be None if Redis is down)
    threat_intel_svc = None
    try:
        from app.services.threat_intel import ThreatIntelService
        threat_intel_svc = ThreatIntelService()
    except Exception as exc:
        tenant_logger.warning(
            "ThreatIntelService unavailable for issue scoring: %s", exc,
        )

    for issue in issues:
        mitigation = 0.5 if issue.status == IssueStatus.MITIGATED else 0.0
        severity_str = (
            issue.severity if isinstance(issue.severity, str)
            else str(issue.severity)
        )

        # Derive EPSS/KEV from the highest-severity linked finding
        issue_epss = 0.0
        issue_is_kev = False

        issue_is_cdn = False

        linked_finding_ids = [
            row.finding_id
            for row in db.query(IssueFinding.finding_id)
            .filter_by(issue_id=issue.id)
            .all()
        ]
        if linked_finding_ids:
            linked_findings = (
                db.query(Finding)
                .filter(Finding.id.in_(linked_finding_ids))
                .all()
            )

            # Check CDN status from linked assets
            linked_asset_ids = list({f.asset_id for f in linked_findings})
            if linked_asset_ids:
                cdn_assets = db.query(Asset.id).filter(
                    Asset.id.in_(linked_asset_ids),
                    Asset.cdn_name.isnot(None),
                ).count()
                if cdn_assets > 0:
                    issue_is_cdn = True

            if threat_intel_svc is not None:
                for finding in linked_findings:
                    if not finding.cve_id:
                        continue
                    evidence = finding.evidence or {}
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
                                finding.cve_id, _ti_exc,
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
    assets = db.query(Asset).filter(
        Asset.tenant_id == tenant_id,
        Asset.is_active == True,
    ).all()

    asset_scores = []
    for asset in assets:
        try:
            result = recalculate_asset_risk(asset.id, db)
            score = result.get('risk_score', 0.0)
            if 'error' not in result:
                asset_scores.append(score)
                scores_computed += 1
        except Exception as exc:
            tenant_logger.error(
                "Risk scoring failed for asset %d: %s", asset.id, exc,
            )

    db.flush()

    # ------------------------------------------------------------------
    # 3. Org score (top-weighted aggregation with dampening)
    # ------------------------------------------------------------------
    if asset_scores:
        # Fetch previous org score for dampening
        prev_row = (
            db.query(RiskScore.score)
            .filter_by(tenant_id=tenant_id, scope_type='organization')
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
            scope_type='organization',
            scope_id=None,
            scan_run_id=scan_run_id,
            score=org_result.score,
            grade=org_result.grade,
            previous_score=previous_score,
            delta=org_result.delta,
            components={
                'top_contribution': round(org_result.score, 2),
                'asset_count': len(asset_scores),
            },
            explanation={
                'total_assets_scored': len(asset_scores),
                'average_asset_score': round(
                    sum(asset_scores) / len(asset_scores), 2,
                ),
                'max_asset_score': round(max(asset_scores), 2),
            },
        )
        db.add(risk_score_row)
        scores_computed += 1

    db.commit()

    return {'scores_computed': scores_computed}


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
            tenant_id, scan_run_id,
        )
    except Exception as exc:
        # Non-fatal: policy evaluation failure should not break the pipeline
        tenant_logger.error(
            "Failed to dispatch alert policy evaluation: %s", exc,
        )

    if isinstance(result, dict):
        return {
            'new_assets': result.get('new_assets', 0),
            'new_findings': result.get('new_findings', 0),
            'alerts_sent': result.get('alerts_sent', 0),
            'is_suspicious': result.get('is_suspicious', False),
        }
    return {'alerts_sent': 0}


@celery.task(
    name='app.tasks.pipeline.cancel_scan',
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
            return {'error': 'ScanRun not found'}

        if scan_run.status != ScanRunStatus.RUNNING:
            return {'error': f'Cannot cancel scan in status {scan_run.status.value}'}

        scan_run.status = ScanRunStatus.CANCELLED
        scan_run.completed_at = datetime.now(timezone.utc)
        scan_run.error_message = 'Cancelled by user'

        # Cancel celery task if running
        if scan_run.celery_task_id:
            celery.control.revoke(scan_run.celery_task_id, terminate=True)

        db.commit()
        return {'status': 'cancelled', 'scan_run_id': scan_run_id}
    except Exception as exc:
        logger.exception("Failed to cancel scan run %d: %s", scan_run_id, exc)
        raise self.retry(exc=exc)
    finally:
        db.close()
