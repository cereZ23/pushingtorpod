"""
Repository pattern for Finding data access

Provides bulk operations for vulnerability findings with:
- Efficient bulk UPSERT (deduplication)
- first_seen/last_seen tracking
- Status management
- Severity-based querying
- Risk score calculation
"""

import logging

from sqlalchemy.orm import Session
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy import and_, or_, func, text
from typing import List, Dict, Optional

logger = logging.getLogger(__name__)
from datetime import datetime, timedelta, timezone
import json

from app.models.database import Finding, FindingSeverity, FindingStatus, Asset
from app.services.dedup import compute_finding_fingerprint
from app.services.endpoint_identity import is_shape_hash


class FindingRepository:
    """Repository for Finding entity operations"""

    def __init__(self, db: Session):
        """
        Initialize repository with database session

        Args:
            db: SQLAlchemy database session
        """
        self.db = db

    def get_by_id(self, finding_id: int) -> Optional[Finding]:
        """Get finding by ID"""
        return self.db.query(Finding).filter_by(id=finding_id).first()

    def get_findings(
        self,
        tenant_id: int,
        severity: Optional[List[str]] = None,
        status: Optional[List[str]] = None,
        asset_id: Optional[int] = None,
        cve_id: Optional[str] = None,
        template_id: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[Finding]:
        """
        Get findings with filters

        Args:
            tenant_id: Tenant ID
            severity: Filter by severity (critical, high, medium, low, info)
            status: Filter by status (open, suppressed, fixed)
            asset_id: Filter by asset ID
            cve_id: Filter by CVE ID
            template_id: Filter by template ID
            limit: Maximum results
            offset: Results offset

        Returns:
            List of findings
        """
        # Join with assets to filter by tenant
        query = self.db.query(Finding).join(Asset).filter(Asset.tenant_id == tenant_id)

        # Apply filters
        if severity:
            severity_enums = [FindingSeverity[s.upper()] for s in severity if s.upper() in FindingSeverity.__members__]
            if severity_enums:
                query = query.filter(Finding.severity.in_(severity_enums))

        if status:
            status_enums = [FindingStatus[s.upper()] for s in status if s.upper() in FindingStatus.__members__]
            if status_enums:
                query = query.filter(Finding.status.in_(status_enums))

        if asset_id:
            query = query.filter(Finding.asset_id == asset_id)

        if cve_id:
            query = query.filter(Finding.cve_id == cve_id)

        if template_id:
            query = query.filter(Finding.template_id == template_id)

        # Order by severity (critical first) then by first_seen (newest first)
        severity_order = {
            FindingSeverity.CRITICAL: 0,
            FindingSeverity.HIGH: 1,
            FindingSeverity.MEDIUM: 2,
            FindingSeverity.LOW: 3,
            FindingSeverity.INFO: 4,
        }

        findings = query.order_by(Finding.severity, Finding.first_seen.desc()).limit(limit).offset(offset).all()

        return findings

    def bulk_upsert_findings(
        self, findings: List[Dict], tenant_id: int, scan_run_id: Optional[int] = None
    ) -> Dict[str, int]:
        """
        Bulk insert or update findings with deduplication

        Uses PostgreSQL UPSERT to efficiently handle findings that may
        already exist. Deduplication key: (asset_id, template_id, matcher_name)

        PERFORMANCE:
        - Batch size of 100 findings: ~100ms
        - Single transaction, one DB round-trip
        - Preserves first_seen timestamp for existing findings

        Args:
            findings: List of finding dicts with:
                - asset_id: int (required)
                - template_id: str (required)
                - name: str (required)
                - severity: str (required)
                - cvss_score: float (optional)
                - cve_id: str (optional)
                - evidence: str/dict (optional)
                - matched_at: str (optional)
                - host: str (optional)
                - matcher_name: str (optional)
                - source: str (optional, default: 'nuclei')
                - endpoint_shape_hash + origin_policy_hash: optional paired endpoint provenance;
                  requires an owned scan run and a phase-9 http_endpoint policy
            tenant_id: Tenant ID for validation

        Returns:
            Dict with counts:
            {
                'created': int,
                'updated': int,
                'total_processed': int,
                'errors': List[str]
            }
        """
        if not findings:
            return {"created": 0, "updated": 0, "total_processed": 0, "errors": []}

        # Never attribute detection to a run that isn't this tenant's: validate ownership and
        # drop a foreign/unknown scan_run_id to None (so it degrades to "no attribution").
        if scan_run_id is not None:
            from app.models.scanning import ScanRun

            owned = self.db.query(ScanRun.id).filter(ScanRun.id == scan_run_id, ScanRun.tenant_id == tenant_id).first()
            if owned is None:
                scan_run_id = None

        # Prepare records
        records = []
        errors = []
        current_time = datetime.now(timezone.utc)

        for idx, finding in enumerate(findings):
            try:
                # Validate required fields
                if "asset_id" not in finding:
                    errors.append(f"Finding {idx}: Missing asset_id")
                    continue

                if "template_id" not in finding:
                    errors.append(f"Finding {idx}: Missing template_id")
                    continue

                if "name" not in finding:
                    errors.append(f"Finding {idx}: Missing name")
                    continue

                if "severity" not in finding:
                    errors.append(f"Finding {idx}: Missing severity")
                    continue

                # Verify asset belongs to tenant
                asset = self.db.query(Asset).filter_by(id=finding["asset_id"], tenant_id=tenant_id).first()

                if not asset:
                    errors.append(f"Finding {idx}: Asset {finding['asset_id']} not found for tenant {tenant_id}")
                    continue

                # Normalize severity
                severity_str = finding["severity"].lower()
                if severity_str not in ["critical", "high", "medium", "low", "info"]:
                    errors.append(f"Finding {idx}: Invalid severity '{severity_str}'")
                    continue

                severity_enum = FindingSeverity[severity_str.upper()]

                shape_hash = finding.get("endpoint_shape_hash")
                policy_hash = finding.get("origin_policy_hash")
                if (shape_hash is None) != (policy_hash is None):
                    errors.append(f"Finding {idx}: endpoint provenance must contain both shape and policy")
                    continue
                if shape_hash is not None:
                    if scan_run_id is None:
                        errors.append(f"Finding {idx}: endpoint provenance requires an owned scan_run_id")
                        continue
                    if not is_shape_hash(shape_hash):
                        errors.append(f"Finding {idx}: invalid endpoint_shape_hash")
                        continue
                    from app.models.coverage import ScanPolicy, ScanPolicyCatalog, ScanPolicyTemplate

                    policy = self.db.query(ScanPolicy).filter(ScanPolicy.policy_hash == policy_hash).first()
                    if policy is None or policy.phase != "9" or policy.pass_name != "http_endpoint":
                        errors.append(f"Finding {idx}: origin policy is not an http_endpoint phase-9 policy")
                        continue
                    catalog = (
                        self.db.query(ScanPolicyCatalog).filter(ScanPolicyCatalog.policy_hash == policy_hash).first()
                    )
                    applicable = (
                        self.db.query(ScanPolicyTemplate.id)
                        .filter(
                            ScanPolicyTemplate.policy_hash == policy_hash,
                            ScanPolicyTemplate.detector_id == finding["template_id"],
                        )
                        .first()
                    )
                    if catalog is None or applicable is None:
                        errors.append(f"Finding {idx}: detector is not applicable to the endpoint policy")
                        continue

                # Process evidence. Finding.evidence is a JSON column: pass a dict/list
                # straight to SQLAlchemy — do NOT json.dumps a dict (that stored a
                # double-encoded JSON *string*, which then broke every reader that calls
                # .get() on evidence, e.g. correlation). Non-JSON-native values → str.
                evidence = finding.get("evidence")
                if evidence is not None and not isinstance(evidence, (dict, list, str)):
                    evidence = str(evidence)

                # Compute fingerprint for deduplication
                fp = compute_finding_fingerprint(
                    tenant_id=tenant_id,
                    asset_identifier=asset.identifier,
                    template_id=finding["template_id"],
                    matcher_name=finding.get("matcher_name"),
                    source=finding.get("source", "nuclei"),
                    endpoint_shape_hash=shape_hash,
                )

                # Build record
                record = {
                    "asset_id": finding["asset_id"],
                    "source": finding.get("source", "nuclei"),
                    "template_id": finding["template_id"],
                    "name": finding["name"][:500],  # Truncate to field limit
                    "severity": severity_enum,
                    "cvss_score": finding.get("cvss_score"),
                    "cve_id": finding.get("cve_id"),
                    "evidence": evidence,
                    "matched_at": finding.get("matched_at"),
                    "host": finding.get("host"),
                    "matcher_name": finding.get("matcher_name"),
                    "fingerprint": fp,
                    "occurrence_count": 1,
                    "endpoint_shape_hash": shape_hash,
                    "origin_policy_hash": policy_hash,
                    "first_seen": current_time,
                    "last_seen": current_time,
                    "status": FindingStatus.OPEN,
                }

                # Detection attribution (P-C): a finding seen in THIS run resets its
                # miss-streak and records the run. Only with a real run — a manual run must
                # update last_seen but never invent a run id.
                if scan_run_id is not None:
                    record["last_detected_scan_run_id"] = scan_run_id
                    record["eligible_miss_streak"] = 0

                records.append(record)

            except Exception as e:
                errors.append(f"Finding {idx}: {str(e)}")
                continue

        if not records:
            return {"created": 0, "updated": 0, "total_processed": 0, "errors": errors}

        # Deduplicate within the batch: PostgreSQL ON CONFLICT cannot
        # update the same row twice in a single INSERT statement.
        # Keep the last occurrence (most recent evidence) per fingerprint.
        seen_fps = {}
        for record in records:
            seen_fps[record["fingerprint"]] = record
        records = list(seen_fps.values())

        # Build UPSERT statement using fingerprint as the unique key
        stmt = insert(Finding).values(records)

        # On conflict (fingerprint), update last_seen, evidence, and bump count
        update_dict = {
            "last_seen": stmt.excluded.last_seen,
            "evidence": stmt.excluded.evidence,
            "matched_at": stmt.excluded.matched_at,
            "cvss_score": stmt.excluded.cvss_score,
            "cve_id": stmt.excluded.cve_id,
            "occurrence_count": Finding.occurrence_count + 1,
            # Do NOT update: first_seen, severity, name, template_id, fingerprint
        }

        # Detection attribution on re-detection (P-C): reset the miss-streak and record the
        # run. Skipped for a manual run (no scan_run_id) so we never fabricate a run id.
        if scan_run_id is not None:
            update_dict["last_detected_scan_run_id"] = stmt.excluded.last_detected_scan_run_id
            update_dict["eligible_miss_streak"] = stmt.excluded.eligible_miss_streak
        # Endpoint fingerprint identity already pins the shape. On re-detection, move provenance to
        # the current applicable policy atomically with last_detected_scan_run_id.
        update_dict["endpoint_shape_hash"] = stmt.excluded.endpoint_shape_hash
        update_dict["origin_policy_hash"] = stmt.excluded.origin_policy_hash

        stmt = stmt.on_conflict_do_update(index_elements=["fingerprint"], set_=update_dict).returning(
            Finding.id, Finding.first_seen
        )

        # Execute and get affected rows
        result = self.db.execute(stmt)
        returned_rows = result.fetchall()

        self.db.commit()

        # Count created vs updated
        # New records have first_seen very close to current_time
        created = 0
        for row in returned_rows:
            finding_id, first_seen = row
            if first_seen:
                if first_seen.tzinfo is None:
                    first_seen = first_seen.replace(tzinfo=timezone.utc)
            if first_seen and (current_time - first_seen).total_seconds() < 2:
                created += 1

        return {
            "created": created,
            "updated": len(returned_rows) - created,
            "total_processed": len(records),
            "errors": errors,
        }

    def update_finding_status(self, finding_id: int, status: str, notes: Optional[str] = None) -> Optional[Finding]:
        """
        Update finding status

        Args:
            finding_id: Finding ID
            status: New status (open, suppressed, fixed)
            notes: Optional notes about status change

        Returns:
            Updated finding or None
        """
        finding = self.db.query(Finding).filter_by(id=finding_id).first()

        if not finding:
            return None

        # Validate status
        status_upper = status.upper()
        if status_upper not in FindingStatus.__members__:
            raise ValueError(f"Invalid status: {status}")

        finding.status = FindingStatus[status_upper]

        # Append notes to evidence if provided. evidence is a JSON column: work on a dict and
        # assign a dict back (never json.dumps — that would re-introduce a double-encoded
        # string). Tolerate legacy string rows.
        if notes:
            if isinstance(finding.evidence, dict):
                evidence = dict(finding.evidence)
            elif isinstance(finding.evidence, str):
                try:
                    parsed = json.loads(finding.evidence)
                    evidence = parsed if isinstance(parsed, dict) else {}
                except (json.JSONDecodeError, TypeError, ValueError):
                    evidence = {}
            else:
                evidence = {}
            evidence.setdefault("status_notes", []).append(
                {"timestamp": datetime.now(timezone.utc).isoformat(), "status": status, "notes": notes}
            )
            finding.evidence = evidence

        self.db.commit()
        self.db.refresh(finding)

        return finding

    def get_finding_stats(self, tenant_id: int, days: int = 30) -> Dict:
        """
        Get finding statistics for tenant

        Args:
            tenant_id: Tenant ID
            days: Number of days to include (0 = all time)

        Returns:
            Statistics dict
        """
        # Base query — active assets only (dead-asset findings must not inflate
        # counts vs the findings list).
        query = self.db.query(Finding).join(Asset).filter(Asset.tenant_id == tenant_id, Asset.is_active.is_(True))

        # Apply time filter
        if days > 0:
            cutoff = datetime.now(timezone.utc) - timedelta(days=days)
            query = query.filter(Finding.first_seen >= cutoff)

        # Count by severity (OPEN only — matches the findings list / dashboard)
        by_severity = {}
        for severity in FindingSeverity:
            count = query.filter(Finding.severity == severity, Finding.status == FindingStatus.OPEN).count()
            by_severity[severity.value] = count

        # Count by status
        by_status = {}
        for status in FindingStatus:
            count = query.filter(Finding.status == status).count()
            by_status[status.value] = count

        # Count total
        total = query.count()

        # Get top CVEs
        top_cves = (
            self.db.query(Finding.cve_id, func.count(Finding.id).label("count"))
            .join(Asset)
            .filter(Asset.tenant_id == tenant_id, Finding.cve_id.isnot(None))
            .group_by(Finding.cve_id)
            .order_by(func.count(Finding.id).desc())
            .limit(10)
            .all()
        )

        # Get top templates
        top_templates = (
            self.db.query(Finding.template_id, func.count(Finding.id).label("count"))
            .join(Asset)
            .filter(Asset.tenant_id == tenant_id)
            .group_by(Finding.template_id)
            .order_by(func.count(Finding.id).desc())
            .limit(10)
            .all()
        )

        return {
            "total": total,
            "by_severity": by_severity,
            "by_status": by_status,
            "top_cves": [{"cve": cve, "count": count} for cve, count in top_cves],
            "top_templates": [{"template": tpl, "count": count} for tpl, count in top_templates],
        }

    def get_new_findings(self, tenant_id: int, since_hours: int = 24) -> List[Finding]:
        """
        Get findings discovered in last N hours

        Args:
            tenant_id: Tenant ID
            since_hours: Hours to look back

        Returns:
            List of new findings
        """
        cutoff = datetime.now(timezone.utc) - timedelta(hours=since_hours)

        findings = (
            self.db.query(Finding)
            .join(Asset)
            .filter(
                and_(Asset.tenant_id == tenant_id, Finding.first_seen >= cutoff, Finding.status == FindingStatus.OPEN)
            )
            .order_by(Finding.severity, Finding.first_seen.desc())
            .all()
        )

        return findings

    def count_by_asset(self, asset_id: int) -> int:
        """Count findings for asset"""
        return self.db.query(Finding).filter_by(asset_id=asset_id).count()

    def delete_by_asset(self, asset_id: int) -> int:
        """
        Delete all findings for asset

        Args:
            asset_id: Asset ID

        Returns:
            Number of findings deleted
        """
        count = self.db.query(Finding).filter_by(asset_id=asset_id).delete()
        self.db.commit()
        return count
