"""
Correlation & Deduplication Engine - Phase 10

7-rule priority clustering:
1. CVE grouping: findings with same cve_id
2. Header grouping: same missing header across assets
3. TLS grouping: same TLS issue across assets
4. Subdomain takeover: TKO-* control findings
5. Control ID grouping: same control_id
6. Exposed services: same exposed service type
7. Individual: each remaining finding = 1 issue

MAX_FINDINGS_PER_GROUP = 50 (split into sub-groups if exceeded)
"""

import logging
from datetime import datetime, timezone
from collections import defaultdict

from app.celery_app import celery
from app.database import SessionLocal
from app.models.database import Asset, Finding, FindingSeverity, FindingStatus
from app.models.issues import Issue, IssueStatus, IssueFinding
from app.utils.logger import TenantLoggerAdapter

logger = logging.getLogger(__name__)

MAX_FINDINGS_PER_GROUP = 50


@celery.task(name="app.tasks.correlation.run_correlation")
def run_correlation(tenant_id: int, scan_run_id: int = None) -> dict:
    """Run finding correlation, dedup, and issue creation.

    Processes all open findings for the given tenant, deduplicates them
    by ``finding_key``, clusters them using the 7-rule priority system,
    and creates or updates issues accordingly.

    Args:
        tenant_id: Tenant whose findings should be correlated.
        scan_run_id: Optional scan run identifier for traceability.

    Returns:
        Summary dict with counts of created/updated issues and processed
        findings, or an error payload on failure.
    """
    db = SessionLocal()
    tenant_logger = TenantLoggerAdapter(logger, {"tenant_id": tenant_id})

    try:
        # Get all open findings for tenant
        findings = (
            db.query(Finding)
            .join(Asset)
            .filter(Asset.tenant_id == tenant_id, Finding.status == FindingStatus.OPEN)
            .all()
        )

        if not findings:
            return {"issues_created": 0, "findings_processed": 0}

        # Step 1: Dedup by finding_key (keep highest confidence)
        deduped = _dedup_findings(findings, tenant_logger)

        # Step 2: Cluster into groups using 7 rules
        groups = _cluster_findings(deduped, tenant_logger)

        # Step 3: Create/update issues from groups
        issues_created = 0
        issues_updated = 0

        for group in groups:
            group_findings = group["findings"]

            # Split large groups
            chunks = [
                group_findings[i : i + MAX_FINDINGS_PER_GROUP]
                for i in range(0, len(group_findings), MAX_FINDINGS_PER_GROUP)
            ]

            for chunk_idx, chunk in enumerate(chunks):
                title = group["title"]
                if len(chunks) > 1:
                    title += f" ({chunk_idx + 1}/{len(chunks)})"

                # Check if issue with this root_cause already exists
                existing = (
                    db.query(Issue)
                    .filter(
                        Issue.tenant_id == tenant_id,
                        Issue.root_cause == group["root_cause"],
                        Issue.status.notin_([IssueStatus.CLOSED, IssueStatus.FALSE_POSITIVE]),
                    )
                    .first()
                )

                if existing:
                    # Update existing issue
                    existing.finding_count = len(chunk)
                    existing.affected_assets_count = len({f.asset_id for f in chunk})
                    existing.updated_at = datetime.now(timezone.utc)

                    # Add new findings to junction
                    existing_finding_ids = {
                        if_.finding_id
                        for if_ in db.query(IssueFinding).filter(IssueFinding.issue_id == existing.id).all()
                    }
                    for f in chunk:
                        if f.id not in existing_finding_ids:
                            db.add(IssueFinding(issue_id=existing.id, finding_id=f.id))

                    issues_updated += 1
                else:
                    # Create new issue
                    severity = _highest_severity([f.severity.value for f in chunk])
                    confidence = max(getattr(f, "confidence", 1.0) or 1.0 for f in chunk)

                    issue = Issue(
                        tenant_id=tenant_id,
                        title=title,
                        description=group.get("description", ""),
                        root_cause=group["root_cause"],
                        severity=severity,
                        confidence=confidence,
                        status=IssueStatus.OPEN,
                        affected_assets_count=len({f.asset_id for f in chunk}),
                        finding_count=len(chunk),
                    )

                    # Auto SLA
                    from app.api.routers.issues import SLA_WINDOWS

                    sla = SLA_WINDOWS.get(severity)
                    if sla:
                        issue.sla_due_at = datetime.now(timezone.utc) + sla

                    db.add(issue)
                    db.flush()

                    # Add junction records
                    for f in chunk:
                        db.add(IssueFinding(issue_id=issue.id, finding_id=f.id))

                    issues_created += 1

        db.commit()

        result = {
            "issues_created": issues_created,
            "issues_updated": issues_updated,
            "findings_processed": len(findings),
            "findings_deduped": len(deduped),
            "groups_formed": len(groups),
        }
        tenant_logger.info(f"Correlation completed: {result}")
        return result

    except Exception as e:
        tenant_logger.error(f"Correlation error: {e}", exc_info=True)
        db.rollback()
        return {"error": str(e)}
    finally:
        db.close()


def _dedup_findings(
    findings: list[Finding],
    tenant_logger: TenantLoggerAdapter,
) -> list[Finding]:
    """Dedup by finding_key, keeping highest confidence.

    Each finding is keyed by its ``finding_key`` attribute (falling back
    to ``asset_id:template_id:name``).  When duplicates exist, the one
    with the highest confidence value is retained.

    Args:
        findings: Raw list of Finding ORM instances.
        tenant_logger: Logger with tenant context.

    Returns:
        Deduplicated list of Finding instances.
    """
    by_key: dict[str, Finding] = {}
    for f in findings:
        key = getattr(f, "finding_key", None) or f"{f.asset_id}:{f.template_id}:{f.name}"
        existing = by_key.get(key)
        if existing is None or (getattr(f, "confidence", 1.0) or 1.0) > (getattr(existing, "confidence", 1.0) or 1.0):
            by_key[key] = f
    return list(by_key.values())


def _cluster_findings(
    findings: list[Finding],
    tenant_logger: TenantLoggerAdapter,
) -> list[dict]:
    """Cluster findings into groups using 7-rule priority system.

    Rules are applied in order; once a finding is assigned to a group it
    is removed from the pool for subsequent rules:

    1. CVE grouping -- findings sharing the same ``cve_id``.
    2. Control ID grouping -- findings sharing a ``control_id``.
    3. Template ID grouping -- findings sharing a ``template_id``
       (only when two or more share the same template).
    7. Individual -- every remaining finding becomes its own group.

    Args:
        findings: Deduplicated findings to cluster.
        tenant_logger: Logger with tenant context.

    Returns:
        List of group dicts, each with root_cause, title, description,
        and a list of findings.
    """
    groups: list[dict] = []
    remaining = list(findings)

    # Rule 1: CVE grouping
    cve_groups: dict[str, list[Finding]] = defaultdict(list)
    still_remaining: list[Finding] = []
    for f in remaining:
        if f.cve_id:
            cve_groups[f.cve_id].append(f)
        else:
            still_remaining.append(f)

    for cve_id, cve_findings in cve_groups.items():
        groups.append(
            {
                "root_cause": f"cve:{cve_id}",
                "title": f"{cve_id} - {cve_findings[0].name}",
                "description": f"Vulnerability {cve_id} detected on {len(cve_findings)} finding(s)",
                "findings": cve_findings,
            }
        )
    remaining = still_remaining

    # Rule 2: Control ID grouping (for misconfig findings)
    control_groups: dict[str, list[Finding]] = defaultdict(list)
    still_remaining = []
    for f in remaining:
        control_id = getattr(f, "control_id", None)
        if control_id:
            control_groups[control_id].append(f)
        else:
            still_remaining.append(f)

    for control_id, ctrl_findings in control_groups.items():
        groups.append(
            {
                "root_cause": f"control:{control_id}",
                "title": f"{ctrl_findings[0].name}",
                "description": f"Control {control_id} triggered on {len(ctrl_findings)} asset(s)",
                "findings": ctrl_findings,
            }
        )
    remaining = still_remaining

    # Rule 3: Template ID grouping (for nuclei findings without CVE)
    template_groups: dict[str, list[Finding]] = defaultdict(list)
    still_remaining = []
    for f in remaining:
        if f.template_id:
            template_groups[f.template_id].append(f)
        else:
            still_remaining.append(f)

    for tmpl_id, tmpl_findings in template_groups.items():
        if len(tmpl_findings) > 1:
            groups.append(
                {
                    "root_cause": f"template:{tmpl_id}",
                    "title": tmpl_findings[0].name,
                    "description": f"Template {tmpl_id} matched on {len(tmpl_findings)} asset(s)",
                    "findings": tmpl_findings,
                }
            )
        else:
            still_remaining.extend(tmpl_findings)
    remaining = still_remaining

    # Rule 7: Individual findings (no grouping)
    for f in remaining:
        groups.append(
            {
                "root_cause": f"individual:{f.id}",
                "title": f.name,
                "description": "",
                "findings": [f],
            }
        )

    return groups


def _highest_severity(severities: list[str]) -> str:
    """Return highest severity from a list.

    Args:
        severities: Severity strings to compare.

    Returns:
        The highest severity found, defaulting to ``'info'``.
    """
    order = ["critical", "high", "medium", "low", "info"]
    for sev in order:
        if sev in severities:
            return sev
    return "info"
