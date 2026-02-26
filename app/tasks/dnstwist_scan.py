"""
DNSTwist domain permutation / typosquatting detection task

Generates domain permutations (homoglyphs, typos, bit-flips, etc.) and checks
which ones are registered. Registered lookalike domains are stored as findings
because they may indicate phishing, brand abuse, or supply-chain attacks.
"""

import logging
import socket
from datetime import datetime, timezone
from typing import Dict, List, Optional

from app.celery_app import celery
from app.models.database import (
    Asset,
    AssetType,
    Finding,
    FindingSeverity,
    FindingStatus,
)
from app.services.dedup import compute_finding_fingerprint
from app.utils.logger import TenantLoggerAdapter

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Homoglyph mapping used by the fallback permutation generator
# ---------------------------------------------------------------------------
HOMOGLYPHS: Dict[str, List[str]] = {
    'a': ['4', '@'],
    'b': ['d', '6'],
    'c': ['k', 'q'],
    'd': ['b', 'cl'],
    'e': ['3'],
    'g': ['q', '9'],
    'i': ['1', 'l'],
    'l': ['1', 'i'],
    'o': ['0'],
    'q': ['g'],
    's': ['5', '$'],
    't': ['7'],
    'u': ['v'],
    'v': ['u'],
    'w': ['vv'],
    'z': ['2'],
}


# ---------------------------------------------------------------------------
# Celery task
# ---------------------------------------------------------------------------
@celery.task(
    name='app.tasks.dnstwist_scan.run_dnstwist',
    bind=True,
    max_retries=2,
    default_retry_delay=60,
)
def run_dnstwist(self, tenant_id: int, domain_list: Optional[List[str]] = None):
    """Run DNSTwist permutation scan for typosquatting detection.

    For each root domain belonging to the tenant, domain permutations are
    generated and checked for DNS registration.  Any registered lookalike
    domain is persisted as a Finding with source ``dnstwist``.

    Args:
        tenant_id: ID of the tenant to scan.
        domain_list: Explicit list of domains.  When ``None`` (the default),
            all active DOMAIN assets for the tenant are used.

    Returns:
        Summary dict with ``findings_created`` and ``domains_scanned`` keys.
    """
    from app.database import SessionLocal

    db = SessionLocal()
    tenant_logger = TenantLoggerAdapter(logger, {'tenant_id': tenant_id})

    try:
        # Resolve domain list from the database when not provided explicitly
        if not domain_list:
            domains = (
                db.query(Asset)
                .filter(
                    Asset.tenant_id == tenant_id,
                    Asset.type == AssetType.DOMAIN,
                    Asset.is_active == True,  # noqa: E712
                )
                .all()
            )
            domain_list = [d.identifier for d in domains]

        if not domain_list:
            tenant_logger.info("No root domains found for dnstwist scan")
            return {'findings_created': 0, 'domains_scanned': 0}

        tenant_logger.info(
            f"Starting dnstwist scan for {len(domain_list)} domain(s)"
        )

        findings_created = 0

        for domain in domain_list:
            try:
                findings_created += _scan_single_domain(
                    db, tenant_id, domain, tenant_logger
                )
            except Exception as exc:
                tenant_logger.warning(
                    f"DNSTwist scan failed for {domain}: {exc}"
                )
                continue

        db.commit()

        tenant_logger.info(
            f"DNSTwist scan complete: {findings_created} finding(s) "
            f"across {len(domain_list)} domain(s)"
        )
        return {
            'findings_created': findings_created,
            'domains_scanned': len(domain_list),
        }
    except Exception as exc:
        db.rollback()
        tenant_logger.error(
            f"DNSTwist scan failed for tenant: {exc}", exc_info=True
        )
        raise
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------
def _scan_single_domain(
    db,
    tenant_id: int,
    domain: str,
    tenant_logger,
) -> int:
    """Scan a single domain and persist findings.

    Attempts to use the ``dnstwist`` library first; falls back to a basic
    built-in permutation generator when the library is unavailable.

    Returns:
        Number of findings created.
    """
    try:
        import dnstwist as _dnstwist_lib  # noqa: F401

        return _run_dnstwist_library(db, tenant_id, domain, tenant_logger)
    except ImportError:
        tenant_logger.info(
            "dnstwist library not installed -- using fallback permutation generator"
        )
        return _run_basic_permutations(db, tenant_id, domain, tenant_logger)


def _run_dnstwist_library(
    db,
    tenant_id: int,
    domain: str,
    tenant_logger,
) -> int:
    """Run the ``dnstwist`` library for a single domain.

    Returns:
        Number of new findings created.
    """
    import dnstwist

    tenant_logger.info(f"Running dnstwist library for {domain}")

    results = dnstwist.run(domain=domain, registered=True, format='list')

    return _process_permutation_results(
        db=db,
        tenant_id=tenant_id,
        domain=domain,
        permutations=results,
        tenant_logger=tenant_logger,
    )


def _run_basic_permutations(
    db,
    tenant_id: int,
    domain: str,
    tenant_logger,
) -> int:
    """Fallback permutation generator with DNS resolution.

    Produces common typo variants (character swap, missing character, double
    character, and homoglyphs) and resolves them via ``socket.getaddrinfo``.

    Returns:
        Number of new findings created.
    """
    tenant_logger.info(f"Running basic permutation generator for {domain}")

    parts = domain.rsplit('.', 1)
    if len(parts) != 2:
        tenant_logger.warning(f"Cannot parse domain for permutations: {domain}")
        return 0

    name, tld = parts
    candidates = _generate_permutations(name, tld)

    # De-duplicate and exclude the original domain
    candidates = list({c for c in candidates if c != domain})

    tenant_logger.info(
        f"Generated {len(candidates)} permutation(s) for {domain}"
    )

    # Resolve each candidate and build dnstwist-compatible result dicts
    permutations: List[Dict] = []
    for candidate in candidates:
        dns_a = _resolve_domain(candidate)
        if dns_a:
            permutations.append({
                'fuzzer': 'basic-fallback',
                'domain': candidate,
                'dns_a': dns_a,
            })

    tenant_logger.info(
        f"Resolved {len(permutations)} registered permutation(s) for {domain}"
    )

    return _process_permutation_results(
        db=db,
        tenant_id=tenant_id,
        domain=domain,
        permutations=permutations,
        tenant_logger=tenant_logger,
    )


def _generate_permutations(name: str, tld: str) -> List[str]:
    """Generate common typo permutations for *name*.*tld*.

    Strategies:
      - Character omission  (``exmple.com``)
      - Adjacent character swap  (``examlpe.com``)
      - Character duplication  (``exxample.com``)
      - Homoglyph substitution  (``examp1e.com``)
    """
    perms: List[str] = []

    # 1. Character omission
    for i in range(len(name)):
        variant = name[:i] + name[i + 1:]
        if variant:
            perms.append(f"{variant}.{tld}")

    # 2. Adjacent character swap
    for i in range(len(name) - 1):
        chars = list(name)
        chars[i], chars[i + 1] = chars[i + 1], chars[i]
        perms.append(f"{''.join(chars)}.{tld}")

    # 3. Character duplication
    for i in range(len(name)):
        variant = name[:i] + name[i] + name[i:]
        perms.append(f"{variant}.{tld}")

    # 4. Homoglyph substitution
    for i, char in enumerate(name):
        for replacement in HOMOGLYPHS.get(char.lower(), []):
            variant = name[:i] + replacement + name[i + 1:]
            perms.append(f"{variant}.{tld}")

    return perms


def _resolve_domain(domain: str) -> List[str]:
    """Attempt to resolve *domain* to a list of IPv4 addresses.

    Returns an empty list when the domain does not resolve.
    """
    try:
        results = socket.getaddrinfo(domain, None, socket.AF_INET)
        return list({r[4][0] for r in results})
    except (socket.gaierror, OSError):
        return []


def _process_permutation_results(
    db,
    tenant_id: int,
    domain: str,
    permutations: List[Dict],
    tenant_logger,
) -> int:
    """Persist permutation results as Finding rows.

    Handles deduplication (skip if an identical finding already exists) and
    updates ``last_seen`` for previously known findings.

    Returns:
        Number of **new** findings created.
    """
    root_asset = (
        db.query(Asset)
        .filter(
            Asset.tenant_id == tenant_id,
            Asset.identifier == domain,
        )
        .first()
    )

    if not root_asset:
        tenant_logger.warning(
            f"Root asset not found for domain {domain} -- skipping findings"
        )
        return 0

    findings_created = 0
    now = datetime.now(timezone.utc)

    for perm in permutations:
        perm_domain = perm.get('domain', '')

        # Skip the original domain itself
        if perm_domain == domain:
            continue

        # Skip unregistered permutations (no DNS records at all)
        if (
            not perm.get('dns_a')
            and not perm.get('dns_aaaa')
            and not perm.get('dns_mx')
        ):
            continue

        fuzzer = perm.get('fuzzer', 'unknown')
        template_id = f'dnstwist-{fuzzer}'

        # Compute dedup fingerprint
        fp = compute_finding_fingerprint(
            tenant_id=tenant_id,
            asset_identifier=domain,
            template_id=template_id,
            matcher_name=perm_domain,
            source='dnstwist',
        )

        # Check for an existing finding by fingerprint
        existing = (
            db.query(Finding)
            .filter(Finding.fingerprint == fp)
            .first()
        )

        if existing:
            existing.last_seen = now
            existing.occurrence_count = (existing.occurrence_count or 1) + 1
            continue

        # Domains with MX records are higher risk (potential phishing e-mails)
        severity = (
            FindingSeverity.HIGH
            if perm.get('dns_mx')
            else FindingSeverity.MEDIUM
        )

        evidence = {
            'original_domain': domain,
            'permutation': perm_domain,
            'fuzzer': fuzzer,
            'dns_a': perm.get('dns_a', []),
            'dns_aaaa': perm.get('dns_aaaa', []),
            'dns_mx': perm.get('dns_mx', []),
            'dns_ns': perm.get('dns_ns', []),
        }

        finding = Finding(
            asset_id=root_asset.id,
            source='dnstwist',
            template_id=template_id,
            name=f'Typosquat domain registered: {perm_domain}',
            severity=severity,
            evidence=evidence,
            status=FindingStatus.OPEN,
            first_seen=now,
            last_seen=now,
            matcher_name=perm_domain,
            fingerprint=fp,
            occurrence_count=1,
        )
        db.add(finding)
        findings_created += 1

    return findings_created
