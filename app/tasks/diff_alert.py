"""
Diff, Alerting & Reporting Engine - Phase 12

Computes changes between scan runs:
- New/removed assets
- New/removed services (ports)
- New/resolved findings
- Content hash changes

Sanity check: >50% asset removal = likely scan failure, not real changes.
Alert evaluation with cooldown dedup + volume cap (50/run).
"""

import logging
import hashlib
from datetime import datetime
from dataclasses import dataclass, field

from app.celery_app import celery
from app.config import settings
from app.database import SessionLocal
from app.models.database import Asset, AssetType, Service, Finding, FindingStatus
from app.models.scanning import ScanRun, ScanRunStatus
from app.models.risk import Alert, AlertStatus, AlertPolicy
from app.utils.logger import TenantLoggerAdapter

logger = logging.getLogger(__name__)


@dataclass
class RunSnapshot:
    """Point-in-time snapshot of tenant attack surface state.

    Captures sets of unique keys for assets, services, and findings
    to enable efficient set-based diff computation between scan runs.

    Attributes:
        asset_keys: Set of "tenant:type:identifier" strings.
        service_keys: Set of "asset_id:port:proto" strings.
        finding_keys: Set of "asset_id:template_id:matcher_name" strings.
        content_hashes: Mapping of asset_key to metadata hash for
            detecting content-level changes beyond presence/absence.
    """

    asset_keys: set = field(default_factory=set)
    service_keys: set = field(default_factory=set)
    finding_keys: set = field(default_factory=set)
    content_hashes: dict = field(default_factory=dict)


@dataclass
class DiffResult:
    """Result of comparing two RunSnapshot instances.

    Attributes:
        new_assets: Asset keys present in current but not previous.
        removed_assets: Asset keys present in previous but not current.
        new_services: Service keys present in current but not previous.
        removed_services: Service keys present in previous but not current.
        new_findings: Finding keys present in current but not previous.
        resolved_findings: Finding keys present in previous but not current.
        is_suspicious: True when >50% of previous assets were removed,
            indicating a probable scan failure rather than real changes.
        change_events: Aggregated change event descriptors.
    """

    new_assets: list = field(default_factory=list)
    removed_assets: list = field(default_factory=list)
    new_services: list = field(default_factory=list)
    removed_services: list = field(default_factory=list)
    new_findings: list = field(default_factory=list)
    resolved_findings: list = field(default_factory=list)
    is_suspicious: bool = False
    change_events: list = field(default_factory=list)


@celery.task(
    name="app.tasks.diff_alert.run_diff_and_alert",
    bind=True,
    max_retries=3,
    default_retry_delay=60,
    retry_backoff=True,
    retry_backoff_max=600,
    retry_jitter=True,
)
def run_diff_and_alert(self, tenant_id: int, scan_run_id: int):
    """Compute diff between current and previous scan, generate alerts.

    Args:
        tenant_id: Tenant whose attack surface is being compared.
        scan_run_id: The just-completed scan run to diff against the
            most recent prior completed run.

    Returns:
        Dict with counts of new/removed assets, services, findings,
        suspicion flag, and number of alerts dispatched.
    """
    db = SessionLocal()
    tenant_logger = TenantLoggerAdapter(logger, {"tenant_id": tenant_id})

    try:
        # Build current snapshot
        current = _build_snapshot(db, tenant_id)

        # Find previous completed scan run
        current_run = db.query(ScanRun).filter(ScanRun.id == scan_run_id).first()
        if not current_run:
            return {"error": "ScanRun not found"}

        prev_run = (
            db.query(ScanRun)
            .filter(
                ScanRun.tenant_id == tenant_id,
                ScanRun.id != scan_run_id,
                ScanRun.status == ScanRunStatus.COMPLETED,
            )
            .order_by(ScanRun.completed_at.desc())
            .first()
        )

        if not prev_run or not prev_run.stats:
            # First scan - everything is new, no diff
            tenant_logger.info("First scan run, no diff to compute")
            return {
                "new_assets": len(current.asset_keys),
                "is_baseline": True,
            }

        # Build previous snapshot from stored stats
        previous = _snapshot_from_stats(prev_run.stats)

        # Compute diff
        diff = _compute_diff(current, previous, tenant_logger)

        # Sanity check
        if diff.is_suspicious:
            tenant_logger.warning(
                f"Suspicious diff: >50% asset removal "
                f"({len(diff.removed_assets)}/{len(previous.asset_keys)}). "
                f"Possible scan failure."
            )

        # Generate events, enriching finding events with actual DB data
        events = []
        for asset_key in diff.new_assets:
            events.append(
                {
                    "type": "asset_new",
                    "severity": "info",
                    "identifier": asset_key,
                }
            )

        # Build a lookup of finding rows keyed by their diff key so
        # events carry real severity/name/IDs for policy matching.
        finding_lookup: dict[str, Finding] = {}
        if diff.new_findings:
            open_findings = (
                db.query(Finding)
                .join(Asset)
                .filter(
                    Asset.tenant_id == tenant_id,
                    Finding.status == FindingStatus.OPEN,
                )
                .all()
            )
            for f in open_findings:
                key = f"{f.asset_id}:{f.template_id}:{f.matcher_name}"
                finding_lookup[key] = f

        for finding_key in diff.new_findings:
            finding_row = finding_lookup.get(finding_key)
            if finding_row:
                sev = (
                    finding_row.severity.value
                    if hasattr(finding_row.severity, "value")
                    else str(finding_row.severity)
                )
                events.append(
                    {
                        "type": "finding_new",
                        "severity": sev,
                        "name": finding_row.name,
                        "finding_key": finding_key,
                        "asset_id": finding_row.asset_id,
                        "finding_id": finding_row.id,
                        "template_id": finding_row.template_id,
                    }
                )
            else:
                events.append(
                    {
                        "type": "finding_new",
                        "severity": "info",
                        "finding_key": finding_key,
                    }
                )

        for svc_key in diff.new_services:
            events.append(
                {
                    "type": "service_new",
                    "severity": "info",
                    "service_key": svc_key,
                }
            )

        # Evaluate alert policies
        if events and not diff.is_suspicious:
            from app.tasks.alerting import evaluate_alert_policies

            evaluate_alert_policies.delay(
                tenant_id, events[: settings.alert_max_per_run]
            )

        # Store snapshot in scan run stats
        current_run.stats = current_run.stats or {}
        current_run.stats["snapshot"] = {
            "asset_keys": list(current.asset_keys),
            "service_keys": list(current.service_keys),
            "finding_keys": list(current.finding_keys),
        }
        current_run.stats["change_events"] = [
            {"type": e["type"], "count": 1} for e in events[:100]
        ]
        db.commit()

        result = {
            "new_assets": len(diff.new_assets),
            "removed_assets": len(diff.removed_assets),
            "new_services": len(diff.new_services),
            "removed_services": len(diff.removed_services),
            "new_findings": len(diff.new_findings),
            "resolved_findings": len(diff.resolved_findings),
            "is_suspicious": diff.is_suspicious,
            "alerts_sent": len(events),
        }
        tenant_logger.info(f"Diff completed: {result}")
        return result

    except Exception as exc:
        tenant_logger.error("Diff error: %s", exc, exc_info=True)
        try:
            db.rollback()
        except Exception:
            pass
        raise self.retry(exc=exc)
    finally:
        db.close()


def _build_snapshot(db, tenant_id: int) -> RunSnapshot:
    """Build current state snapshot from DB.

    Queries all active assets, their services, and open findings for
    the given tenant and constructs a RunSnapshot with unique keys.

    Args:
        db: SQLAlchemy session.
        tenant_id: Tenant to snapshot.

    Returns:
        Populated RunSnapshot instance.
    """
    snapshot = RunSnapshot()

    assets = (
        db.query(Asset)
        .filter(Asset.tenant_id == tenant_id, Asset.is_active == True)
        .all()
    )
    for a in assets:
        key = f"{tenant_id}:{a.type.value}:{a.identifier}"
        snapshot.asset_keys.add(key)

        # Content hash from raw_metadata for change detection
        if a.raw_metadata:
            metadata_hash = hashlib.sha256(
                str(a.raw_metadata).encode()
            ).hexdigest()[:16]
            snapshot.content_hashes[key] = metadata_hash

    services = (
        db.query(Service).join(Asset).filter(Asset.tenant_id == tenant_id).all()
    )
    for s in services:
        key = f"{s.asset_id}:{s.port}:{s.protocol}"
        snapshot.service_keys.add(key)

    findings = (
        db.query(Finding)
        .join(Asset)
        .filter(
            Asset.tenant_id == tenant_id,
            Finding.status == FindingStatus.OPEN,
        )
        .all()
    )
    for f in findings:
        key = f"{f.asset_id}:{f.template_id}:{f.matcher_name}"
        snapshot.finding_keys.add(key)

    return snapshot


def _snapshot_from_stats(stats: dict) -> RunSnapshot:
    """Reconstruct snapshot from stored stats JSON.

    Args:
        stats: The ``ScanRun.stats`` JSON dict containing a ``snapshot``
            sub-dict with serialized key sets.

    Returns:
        RunSnapshot with asset_keys, service_keys, and finding_keys
        restored from the stored lists.
    """
    snap_data = stats.get("snapshot", {})
    snapshot = RunSnapshot()
    snapshot.asset_keys = set(snap_data.get("asset_keys", []))
    snapshot.service_keys = set(snap_data.get("service_keys", []))
    snapshot.finding_keys = set(snap_data.get("finding_keys", []))
    return snapshot


def _compute_diff(
    current: RunSnapshot,
    previous: RunSnapshot,
    tenant_logger: TenantLoggerAdapter,
) -> DiffResult:
    """Compute diff between two snapshots.

    Performs set subtraction to identify new and removed items across
    assets, services, and findings.  Flags the diff as suspicious if
    more than 50% of the previous assets are absent in the current
    snapshot, which typically indicates a scan failure rather than
    genuine attack surface reduction.

    Args:
        current: Snapshot of the current scan state.
        previous: Snapshot of the prior completed scan state.
        tenant_logger: Logger with tenant context.

    Returns:
        Populated DiffResult.
    """
    diff = DiffResult()

    diff.new_assets = list(current.asset_keys - previous.asset_keys)
    diff.removed_assets = list(previous.asset_keys - current.asset_keys)
    diff.new_services = list(current.service_keys - previous.service_keys)
    diff.removed_services = list(previous.service_keys - current.service_keys)
    diff.new_findings = list(current.finding_keys - previous.finding_keys)
    diff.resolved_findings = list(previous.finding_keys - current.finding_keys)

    # Sanity: >50% removal = suspicious
    if previous.asset_keys and len(diff.removed_assets) > len(
        previous.asset_keys
    ) * 0.5:
        diff.is_suspicious = True

    return diff
