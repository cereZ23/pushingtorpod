"""
IP-level deduplication for scan targets.

Multiple hostnames often resolve to the same IP address. Scanning
each hostname separately wastes time (port scan, fingerprint, vuln scan
all hit the same server) and produces duplicate findings.

This module groups assets by resolved IP and returns one representative
hostname per unique IP, reducing scan targets by 50-90% in typical EASM
deployments.
"""

import logging
from sqlalchemy.orm import Session

from app.models.database import Asset, AssetType
from app.models.risk import Relationship

logger = logging.getLogger(__name__)


def dedup_by_resolved_ip(
    assets: list[Asset],
    tenant_id: int,
    db: Session,
) -> tuple[list[Asset], int]:
    """Deduplicate assets that resolve to the same IP.

    For each group of hostnames resolving to the same IP, keeps
    only the first one (preferring the root domain over subdomains).
    Services discovered on the representative hostname apply to all
    assets sharing that IP.

    Args:
        assets: List of Asset objects (domains, subdomains, IPs).
        tenant_id: Tenant ID for relationship queries.
        db: SQLAlchemy session.

    Returns:
        Tuple of (deduped_assets, skipped_count).
    """
    if not assets:
        return [], 0

    # Separate IPs from hostnames (IPs don't need dedup)
    ip_assets = [a for a in assets if a.type == AssetType.IP]
    hostname_assets = [a for a in assets if a.type in (AssetType.DOMAIN, AssetType.SUBDOMAIN)]

    if not hostname_assets:
        return assets, 0

    # Build hostname → resolved IPs map from relationships
    hostname_ids = [a.id for a in hostname_assets]
    relationships = (
        db.query(Relationship)
        .filter(
            Relationship.tenant_id == tenant_id,
            Relationship.rel_type == "resolves_to",
            Relationship.source_asset_id.in_(hostname_ids),
        )
        .all()
    )

    # Map: asset_id → set of resolved IPs (via target_asset)
    # Batch-load all target IP assets in one query to avoid N+1.
    # NOTE: use a distinct variable name (target_ip_rows) — reusing the
    # outer `ip_assets` here previously shadowed the standalone-IP list
    # with the target-IP identifier lookup rows, and the final `result`
    # then concatenated those rows back as if they were standalone IPs,
    # doubling the naabu target count (119 instead of 61 on IFO T3).
    target_ip_ids = list({rel.target_asset_id for rel in relationships})
    ip_identifier_by_id: dict[int, str] = {}
    if target_ip_ids:
        target_ip_rows = (
            db.query(Asset.id, Asset.identifier).filter(Asset.id.in_(target_ip_ids)).all()
        )
        ip_identifier_by_id = {row.id: row.identifier for row in target_ip_rows}

    asset_to_ips: dict[int, set[str]] = {}
    for rel in relationships:
        ip_str = ip_identifier_by_id.get(rel.target_asset_id)
        if ip_str:
            asset_to_ips.setdefault(rel.source_asset_id, set()).add(ip_str)

    # Group hostnames by their primary resolved IP
    ip_to_assets: dict[str, list[Asset]] = {}
    no_ip_assets: list[Asset] = []

    for asset in hostname_assets:
        ips = asset_to_ips.get(asset.id, set())
        if ips:
            primary_ip = sorted(ips)[0]  # Deterministic: pick first IP alphabetically
            ip_to_assets.setdefault(primary_ip, []).append(asset)
        else:
            # No resolved IP — keep (might be new, not yet resolved)
            no_ip_assets.append(asset)

    # Pick one representative per IP group (prefer domain over subdomain)
    deduped: list[Asset] = []
    skipped = 0

    for ip, group in ip_to_assets.items():
        if len(group) == 1:
            deduped.append(group[0])
        else:
            # Sort: domains first, then by shortest identifier
            group.sort(key=lambda a: (0 if a.type == AssetType.DOMAIN else 1, len(a.identifier)))
            representative = group[0]
            deduped.append(representative)
            skipped += len(group) - 1
            if len(group) > 2:
                logger.debug(
                    "IP %s: kept %s, skipped %d others (%s)",
                    ip,
                    representative.identifier,
                    len(group) - 1,
                    ", ".join(a.identifier for a in group[1:4]),  # Log first 3
                )

    result = deduped + no_ip_assets + ip_assets

    if skipped:
        logger.info(
            "IP dedup: %d hostnames → %d unique IPs + %d no-resolve + %d standalone IPs (%d duplicates skipped)",
            len(hostname_assets),
            len(deduped),
            len(no_ip_assets),
            len(ip_assets),
            skipped,
        )

    return result, skipped
