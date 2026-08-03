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

import json
import logging
from datetime import datetime, timezone
from collections import defaultdict

from app.celery_app import celery


def evidence_dict(value) -> dict:
    """Coerce a Finding.evidence value to a dict.

    Historically some rows stored evidence as a JSON *string* (bulk_upsert used to
    ``json.dumps`` a dict into the JSON column, bypassing the ORM validator). Reading such a
    value and calling ``.get()`` on it raised ``'str' object has no attribute 'get'`` and
    aborted correlation. This tolerates both shapes: a dict passes through; a JSON-object
    string is decoded; anything else (JSON list/scalar, invalid string, None) → ``{}``.
    """
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            decoded = json.loads(value)
            return decoded if isinstance(decoded, dict) else {}
        except (TypeError, ValueError, json.JSONDecodeError):
            return {}
    return {}


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


# ---------------------------------------------------------------------------
# Network/service finding dedup by shared resolved IP
# ---------------------------------------------------------------------------

# nuclei protocol types whose findings are IP-level (no virtual-host concept):
# the same service on two hostnames that resolve to the same IP is ONE finding.
# HTTP is excluded — vhosts serve different content per Host header.
_NETWORK_FINDING_TYPES = {"tcp", "network"}

# SSL findings are a mixed bag: server-TLS-config checks (cipher suites, TLS
# versions, DH params) are a property of the listening socket (IP:port) and are
# identical across SNI, so they dedup by IP. Cert-specific checks (expired,
# self-signed, SAN mismatch, weak signature) depend on the certificate served
# for a given SNI and legitimately differ per hostname — those stay per-host.
# Only dedup an SSL finding when its template id matches a server-config check.
_SSL_SERVER_CONFIG_KEYWORDS = (
    "cipher",
    "tls-version",
    "deprecated-tls",
    "insecure-tls",
    "dh-param",
    "ssl-dh",
    "3des",
    "rc4",
)


def _is_dedupable_by_ip(finding) -> bool:
    """Whether a finding represents an IP:port-level fact (dedup by IP) rather
    than a per-hostname (vhost/cert) one."""
    ev = evidence_dict(finding.evidence)
    ftype = ev.get("type")
    if ftype in _NETWORK_FINDING_TYPES:
        return True
    if ftype == "ssl":
        tid = (finding.template_id or "").lower()
        return any(k in tid for k in _SSL_SERVER_CONFIG_KEYWORDS)
    return False


def _network_dupe_groups(findings, ip_by_asset):
    """Group network findings that share (template_id, resolved-IP-set).

    Pure/testable. ``ip_by_asset`` maps asset_id -> set(ip identifiers). Returns
    a list of (keep_finding, [duplicate_findings...]) for each group with >1
    member; the lowest-id finding is kept as representative.
    """
    groups = defaultdict(list)
    for f in findings:
        ips = ip_by_asset.get(f.asset_id)
        if not ips:
            continue  # can't attribute to an IP — leave it alone
        key = (f.template_id, tuple(sorted(ips)))
        groups[key].append(f)

    result = []
    for members in groups.values():
        if len(members) < 2:
            continue
        ordered = sorted(members, key=lambda f: f.id)
        result.append((ordered[0], ordered[1:]))
    return result


def dedup_network_findings_by_ip(tenant_id: int, db, tenant_logger) -> int:
    """Collapse network/service nuclei findings sharing a resolved IP.

    FTP/SSH/etc. detected on both example.com and www.example.com (same IP) is
    one real service. Keep one representative (affected hosts recorded in its
    evidence) and mark the rest SUPPRESSED so the findings list shows one row.
    Idempotent: re-detected duplicates on the next scan are re-collapsed here.
    """
    from app.models.risk import Relationship
    from app.models.database import AssetType

    findings = (
        db.query(Finding)
        .join(Asset)
        .filter(
            Asset.tenant_id == tenant_id,
            Finding.source == "nuclei",
            Finding.status == FindingStatus.OPEN,
        )
        .all()
    )
    net = [f for f in findings if _is_dedupable_by_ip(f)]
    if len(net) < 2:
        return 0

    asset_ids = {f.asset_id for f in net}
    ip_by_asset: dict[int, set] = defaultdict(set)

    # hostname assets -> resolved IP identifiers
    rels = (
        db.query(Relationship.source_asset_id, Asset.identifier)
        .join(Asset, Asset.id == Relationship.target_asset_id)
        .filter(
            Relationship.tenant_id == tenant_id,
            Relationship.rel_type == "resolves_to",
            Relationship.source_asset_id.in_(asset_ids),
        )
        .all()
    )
    for src_id, ip_ident in rels:
        ip_by_asset[src_id].add(ip_ident)

    # IP-type assets resolve to themselves
    ip_assets = db.query(Asset.id, Asset.identifier).filter(Asset.id.in_(asset_ids), Asset.type == AssetType.IP).all()
    for aid, ident in ip_assets:
        ip_by_asset[aid].add(ident)

    suppressed = 0
    for keep, dupes in _network_dupe_groups(net, ip_by_asset):
        all_hosts = sorted({f.host for f in [keep, *dupes] if f.host})
        ev = dict(evidence_dict(keep.evidence))
        ev["affected_hosts"] = all_hosts
        ev["shared_ip"] = sorted(ip_by_asset.get(keep.asset_id, set()))
        ev["deduped_by_ip"] = True
        keep.evidence = ev
        keep.last_seen = datetime.now(timezone.utc)
        for d in dupes:
            d.status = FindingStatus.SUPPRESSED
            dev = dict(evidence_dict(d.evidence))
            dev["suppressed_reason"] = "duplicate_service_on_shared_ip"
            dev["deduped_into"] = keep.id
            d.evidence = dev
            suppressed += 1

    if suppressed:
        db.commit()
        tenant_logger.info(
            f"Network-finding dedup: collapsed {suppressed} duplicate service finding(s) "
            "on shared IPs (same service, multiple hostnames)"
        )
    return suppressed
