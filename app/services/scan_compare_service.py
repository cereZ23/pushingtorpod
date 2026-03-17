"""Scan comparison service.

Compares two scan run snapshots and resolves diff keys to full DB objects.
Extracted from ``app.api.routers.projects.compare_scan_runs``.
"""

from __future__ import annotations

import logging

from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.api.schemas.scan_diff import (
    DiffAssetItem,
    DiffAssets,
    DiffFindingItem,
    DiffFindings,
    DiffServiceItem,
    DiffServices,
    DiffSummary,
    ScanCompareResponse,
    ScanRunSummary,
)
from app.models.database import Asset, Finding
from app.models.scanning import ScanRun, ScanRunStatus
from app.tasks.diff_alert import _compute_diff, _snapshot_from_stats
from app.utils.logger import TenantLoggerAdapter

logger = logging.getLogger(__name__)


class ScanCompareService:
    """Compare two completed scan runs and return enriched item-level diff."""

    def __init__(self, db: Session):
        self.db = db

    def compare(
        self,
        tenant_id: int,
        project_id: int,
        base_run_id: int,
        compare_run_id: int,
    ) -> ScanCompareResponse:
        """Compare two scan runs and return enriched diff.

        Uses stored snapshots from ``ScanRun.stats["snapshot"]`` to compute
        set-based differences in assets, services, and findings. Resolves
        diff keys back to DB objects for enriched output.

        Both runs must belong to the same project/tenant and be COMPLETED.

        Args:
            tenant_id: Tenant ID.
            project_id: Project ID.
            base_run_id: Base (older) scan run ID.
            compare_run_id: Compare (newer) scan run ID.

        Returns:
            ScanCompareResponse with enriched diff data.

        Raises:
            HTTPException: 404 if runs not found, 400 if not completed
                or missing snapshot data.
        """
        # Fetch both runs scoped to tenant + project
        base_run = (
            self.db.query(ScanRun)
            .filter(
                ScanRun.id == base_run_id,
                ScanRun.project_id == project_id,
                ScanRun.tenant_id == tenant_id,
            )
            .first()
        )
        compare_run = (
            self.db.query(ScanRun)
            .filter(
                ScanRun.id == compare_run_id,
                ScanRun.project_id == project_id,
                ScanRun.tenant_id == tenant_id,
            )
            .first()
        )

        if not base_run or not compare_run:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="One or both scan runs not found in this project",
            )

        if base_run.status != ScanRunStatus.COMPLETED or compare_run.status != ScanRunStatus.COMPLETED:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Both scan runs must be in COMPLETED status",
            )

        base_stats = base_run.stats or {}
        compare_stats = compare_run.stats or {}

        if "snapshot" not in base_stats or "snapshot" not in compare_stats:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="One or both scan runs lack snapshot data (runs before diff engine was enabled)",
            )

        base_snapshot = _snapshot_from_stats(base_stats)
        compare_snapshot = _snapshot_from_stats(compare_stats)

        tenant_logger = TenantLoggerAdapter(logger, {"tenant_id": tenant_id})
        diff = _compute_diff(compare_snapshot, base_snapshot, tenant_logger)

        # --- Resolve asset keys: "tenant_id:type:identifier" ---
        added_assets = []
        for key in diff.new_assets:
            parts = key.split(":", 2)
            if len(parts) == 3:
                added_assets.append(DiffAssetItem(identifier=parts[2], type=parts[1]))

        removed_assets = []
        for key in diff.removed_assets:
            parts = key.split(":", 2)
            if len(parts) == 3:
                removed_assets.append(DiffAssetItem(identifier=parts[2], type=parts[1]))

        # --- Resolve service keys: "asset_id:port:proto" ---
        # Build asset_id -> identifier lookup for referenced assets
        all_service_asset_ids: set[int] = set()
        for key in list(diff.new_services) + list(diff.removed_services):
            parts = key.split(":")
            if len(parts) >= 3:
                try:
                    all_service_asset_ids.add(int(parts[0]))
                except ValueError:
                    pass

        asset_id_to_identifier: dict[int, str] = {}
        if all_service_asset_ids:
            rows = self.db.query(Asset.id, Asset.identifier).filter(Asset.id.in_(all_service_asset_ids)).all()
            asset_id_to_identifier = {r.id: r.identifier for r in rows}

        added_services = []
        for key in diff.new_services:
            parts = key.split(":")
            if len(parts) >= 3:
                try:
                    aid = int(parts[0])
                    added_services.append(
                        DiffServiceItem(
                            asset_identifier=asset_id_to_identifier.get(aid, str(aid)),
                            port=int(parts[1]),
                            protocol=parts[2],
                        )
                    )
                except (ValueError, IndexError):
                    pass

        removed_services = []
        for key in diff.removed_services:
            parts = key.split(":")
            if len(parts) >= 3:
                try:
                    aid = int(parts[0])
                    removed_services.append(
                        DiffServiceItem(
                            asset_identifier=asset_id_to_identifier.get(aid, str(aid)),
                            port=int(parts[1]),
                            protocol=parts[2],
                        )
                    )
                except (ValueError, IndexError):
                    pass

        # --- Resolve finding keys: "asset_id:template_id:matcher_name" ---
        all_finding_asset_ids: set[int] = set()
        for key in list(diff.new_findings) + list(diff.resolved_findings):
            parts = key.split(":", 2)
            if len(parts) >= 1:
                try:
                    all_finding_asset_ids.add(int(parts[0]))
                except ValueError:
                    pass

        # Extend the asset lookup
        missing_ids = all_finding_asset_ids - set(asset_id_to_identifier.keys())
        if missing_ids:
            rows = self.db.query(Asset.id, Asset.identifier).filter(Asset.id.in_(missing_ids)).all()
            for r in rows:
                asset_id_to_identifier[r.id] = r.identifier

        # Build finding lookup for enrichment
        finding_lookup: dict[str, Finding] = {}
        if diff.new_findings or diff.resolved_findings:
            all_fkeys = set(diff.new_findings) | set(diff.resolved_findings)
            candidate_asset_ids = set()
            for key in all_fkeys:
                parts = key.split(":", 2)
                if parts:
                    try:
                        candidate_asset_ids.add(int(parts[0]))
                    except ValueError:
                        pass

            if candidate_asset_ids:
                findings_rows = self.db.query(Finding).filter(Finding.asset_id.in_(candidate_asset_ids)).all()
                for f in findings_rows:
                    fkey = f"{f.asset_id}:{f.template_id}:{f.matcher_name}"
                    finding_lookup[fkey] = f

        added_findings = []
        for key in diff.new_findings:
            parts = key.split(":", 2)
            f = finding_lookup.get(key)
            aid = None
            try:
                aid = int(parts[0]) if parts else None
            except ValueError:
                pass
            added_findings.append(
                DiffFindingItem(
                    id=f.id if f else None,
                    name=f.name if f else (parts[1] if len(parts) > 1 else None),
                    severity=(
                        f.severity.value if f and hasattr(f.severity, "value") else (str(f.severity) if f else None)
                    ),
                    asset_identifier=asset_id_to_identifier.get(aid, str(aid)) if aid else None,
                )
            )

        resolved_findings = []
        for key in diff.resolved_findings:
            parts = key.split(":", 2)
            f = finding_lookup.get(key)
            aid = None
            try:
                aid = int(parts[0]) if parts else None
            except ValueError:
                pass
            resolved_findings.append(
                DiffFindingItem(
                    id=f.id if f else None,
                    name=f.name if f else (parts[1] if len(parts) > 1 else None),
                    severity=(
                        f.severity.value if f and hasattr(f.severity, "value") else (str(f.severity) if f else None)
                    ),
                    asset_identifier=asset_id_to_identifier.get(aid, str(aid)) if aid else None,
                )
            )

        return ScanCompareResponse(
            base_run=ScanRunSummary(
                id=base_run.id,
                status=base_run.status.value if hasattr(base_run.status, "value") else str(base_run.status),
                completed_at=base_run.completed_at,
            ),
            compare_run=ScanRunSummary(
                id=compare_run.id,
                status=compare_run.status.value if hasattr(compare_run.status, "value") else str(compare_run.status),
                completed_at=compare_run.completed_at,
            ),
            is_suspicious=diff.is_suspicious,
            summary=DiffSummary(
                new_assets=len(diff.new_assets),
                removed_assets=len(diff.removed_assets),
                new_services=len(diff.new_services),
                removed_services=len(diff.removed_services),
                new_findings=len(diff.new_findings),
                resolved_findings=len(diff.resolved_findings),
            ),
            assets=DiffAssets(added=added_assets, removed=removed_assets),
            services=DiffServices(added=added_services, removed=removed_services),
            findings=DiffFindings(added=added_findings, resolved=resolved_findings),
        )
