"""Scope, relationship, and utility helpers for the scan pipeline.

These functions are used by phase implementations in pipeline_phases/
to validate scope, manage asset relationships, and perform common
lookups. Extracted from pipeline.py for maintainability.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Optional

from app.models.risk import Relationship

logger = logging.getLogger(__name__)


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
            if seed.get("type") in ("domain", "subdomain"):
                domains.add(seed["value"].lower().strip())

    # From tenant seeds
    tenant_seeds = (
        db.query(Seed)
        .filter(
            Seed.tenant_id == tenant_id,
            Seed.enabled == True,
            Seed.type.in_(["domain", "subdomain"]),
        )
        .all()
    )
    for s in tenant_seeds:
        domains.add(s.value.lower().strip())

    return domains


def _is_hostname_in_scope(hostname: str, seed_domains: set) -> bool:
    """Check if a hostname belongs to one of the seed domains.

    E.g., 'api.example.com' is in scope if 'example.com' is a seed.
    'cdn.b-cdn.net' is NOT in scope if only 'example.com' is a seed.
    """
    hostname = hostname.lower().strip().rstrip(".")
    for domain in seed_domains:
        if hostname == domain or hostname.endswith("." + domain):
            return True
    return False


def _upsert_relationship(
    db, tenant_id: int, source_asset_id: int, target_asset_id: int, rel_type: str, metadata: dict = None
) -> bool:
    """Upsert a Relationship edge between two assets.

    Returns True if a new relationship was created, False if an existing
    one was updated.
    """
    from sqlalchemy.exc import IntegrityError

    existing = (
        db.query(Relationship)
        .filter(
            Relationship.tenant_id == tenant_id,
            Relationship.source_asset_id == source_asset_id,
            Relationship.target_asset_id == target_asset_id,
            Relationship.rel_type == rel_type,
        )
        .first()
    )

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
    parts = identifier.lower().strip(".").split(".")
    if len(parts) <= 2:
        return None  # Already a root-level domain (e.g. example.com)

    # Common two-part TLDs where the "real" root is three labels
    two_part_tlds = {
        "co.uk",
        "org.uk",
        "ac.uk",
        "gov.uk",
        "com.au",
        "org.au",
        "co.nz",
        "co.za",
        "co.in",
        "co.jp",
        "or.jp",
        "ne.jp",
        "com.br",
        "org.br",
        "co.kr",
        "or.kr",
        "com.cn",
        "org.cn",
        "com.mx",
        "com.ar",
        "com.tw",
        "co.il",
        "co.th",
    }

    tld_candidate = ".".join(parts[-2:])
    if tld_candidate in two_part_tlds:
        # Root domain needs at least 3 labels (e.g. example.co.uk)
        if len(parts) <= 3:
            return None
        return ".".join(parts[-3:])
    else:
        return ".".join(parts[-2:])


def _is_in_scope(value: str, scopes: list) -> bool:
    """Check if a value is within project scope rules."""
    import re
    import ipaddress

    if not scopes:
        return True  # No scope rules = everything in scope

    # Check exclude rules first
    for scope in scopes:
        if scope.rule_type != "exclude":
            continue
        if _scope_matches(value, scope):
            return False

    # Check include rules
    include_rules = [s for s in scopes if s.rule_type == "include"]
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

    if scope.match_type == "domain":
        pattern = scope.pattern.lower()
        v = value.lower()
        return v == pattern or v.endswith("." + pattern)

    elif scope.match_type == "regex":
        return bool(re.match(scope.pattern, value, re.IGNORECASE))

    elif scope.match_type == "ip":
        return value == scope.pattern

    elif scope.match_type == "cidr":
        try:
            network = ipaddress.ip_network(scope.pattern, strict=False)
            ip = ipaddress.ip_address(value)
            return ip in network
        except ValueError:
            return False

    return False


def _query_crtsh(domain: str, tenant_id: int, db, tenant_logger) -> tuple[int, int]:
    """Query crt.sh Certificate Transparency logs for subdomains.

    Returns:
        Tuple of (total_found, new_created).
    """
    import requests as req_lib
    from app.models.database import Asset, AssetType

    url = f"https://crt.sh/?q=%.{domain}&output=json"
    try:
        resp = req_lib.get(url, timeout=30, headers={"User-Agent": "EASM-Scanner/1.0"})
        if resp.status_code != 200:
            return 0, 0

        entries = resp.json()
    except (req_lib.RequestException, ValueError) as exc:
        tenant_logger.debug("crt.sh query for %s failed: %s", domain, exc)
        return 0, 0

    # Extract unique subdomain names from CN and SAN fields
    seen = set()
    for entry in entries:
        name_value = entry.get("name_value", "")
        for name in name_value.split("\n"):
            name = name.strip().lower()
            if name and "*" not in name and name.endswith("." + domain):
                seen.add(name)

    # Upsert discovered subdomains
    created = 0
    for subdomain in seen:
        existing = db.query(Asset.id).filter(Asset.tenant_id == tenant_id, Asset.identifier == subdomain).first()
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


def _san_candidates_in_scope(sans, seed_domains: set, scopes: list) -> list[str]:
    """Normalize certificate SAN entries and keep only in-scope hostnames.

    Pure (no DB) so it can be unit-tested directly. Drops wildcard entries
    (``*.example.com`` reveals no specific host — same choice as the crt.sh path),
    then keeps names that are under a seed root (:func:`_is_hostname_in_scope`) and
    not excluded by project scope rules (:func:`_is_in_scope`). This is what keeps
    third-party SANs on a shared-hosting certificate (e.g. a co-tenant's mail host)
    out of the tenant's asset table.
    """
    out: set[str] = set()
    for raw in sans or []:
        if not raw:
            continue
        host = str(raw).lower().strip().rstrip(".")
        if not host or "*" in host:
            continue
        if not _is_hostname_in_scope(host, seed_domains):
            continue
        if not _is_in_scope(host, scopes):
            continue
        out.add(host)
    return sorted(out)


def _upsert_hostname_assets(db, tenant_id: int, project_id: int, hostnames, source: str, tenant_logger=None) -> int:
    """Upsert in-scope hostnames as SUBDOMAIN assets (deduped). Returns count added.

    Mirrors the crt.sh feedback loop (:func:`_query_crtsh`): scope-gated dedup-upsert.
    Used by the TLS-SAN feedback step so certificate SANs re-enter discovery instead
    of dying on the Certificate record. New assets are resolved/enriched by the normal
    pipeline on the next scan; a fresh ``last_seen`` keeps them from the stale sweep.
    """
    from app.models.database import Asset, AssetType
    from app.models.scanning import Scope

    seed_domains = _get_seed_domains(tenant_id, project_id, db)
    scopes = db.query(Scope).filter(Scope.project_id == project_id).all()
    candidates = _san_candidates_in_scope(hostnames, seed_domains, scopes)

    created = 0
    for host in candidates:
        existing = db.query(Asset.id).filter(Asset.tenant_id == tenant_id, Asset.identifier == host).first()
        if not existing:
            db.add(Asset(tenant_id=tenant_id, type=AssetType.SUBDOMAIN, identifier=host, is_active=True))
            created += 1

    if created:
        db.commit()
        if tenant_logger:
            tenant_logger.info("SAN feedback (%s): +%d in-scope subdomain assets", source, created)
    return created


def _is_ip(value: str) -> bool:
    """Check if a string is an IP address."""
    import ipaddress

    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False
