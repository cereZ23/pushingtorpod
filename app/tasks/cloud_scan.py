"""
Cloud Bucket/Storage Scanner - Phase 1d

Discovers and probes publicly exposed cloud storage buckets across multiple
providers: AWS S3, Google Cloud Storage, Azure Blob Storage, and DigitalOcean
Spaces.  Given root domains from the asset inventory, generates common bucket
name permutations and checks accessibility via HTTP HEAD/GET requests.

Provider detection matrix:
  AWS S3:               https://{name}.s3.amazonaws.com
  Google Cloud Storage: https://storage.googleapis.com/{name}
  Azure Blob Storage:   https://{name}.blob.core.windows.net/{name}
                        https://{name}.blob.core.windows.net/$web
  DigitalOcean Spaces:  https://{name}.{region}.digitaloceanspaces.com

Severity classification:
  CRITICAL - Public listing enabled (can enumerate files)
  HIGH     - Public read access (files accessible but listing disabled)
  MEDIUM   - Bucket exists, public access denied but name confirmed
  LOW      - Bucket exists with restrictive policy (403, no detail leak)

Findings are stored with source='cloud_scan' and
template_id='cloud-bucket-{provider}-{access_level}'.
"""

import asyncio
import logging
import re
from datetime import datetime, timezone
from typing import Any

import httpx

from app.database import SessionLocal
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
# Constants
# ---------------------------------------------------------------------------

# Maximum concurrent HTTP requests
_MAX_CONCURRENCY = 40

# HTTP timeout per request (seconds)
_REQUEST_TIMEOUT = 3.0

# Global timeout for entire cloud scan (seconds) - prevents blocking the pipeline
_GLOBAL_TIMEOUT = 180  # 3 minutes max

# Common bucket name prefixes (reduced to high-value ones)
BUCKET_PREFIXES: list[str] = [
    "backup-",
    "dev-",
    "staging-",
    "prod-",
    "assets-",
    "data-",
    "static-",
    "files-",
    "uploads-",
    "internal-",
]

# Common bucket name suffixes (reduced to high-value ones)
BUCKET_SUFFIXES: list[str] = [
    "-backup",
    "-dev",
    "-staging",
    "-prod",
    "-assets",
    "-data",
    "-public",
    "-internal",
]

# DigitalOcean Spaces regions (reduced to major ones)
DO_REGIONS: list[str] = ["nyc3", "ams3"]

# Severity enum mapping
_SEVERITY_MAP: dict[str, FindingSeverity] = {
    "critical": FindingSeverity.CRITICAL,
    "high": FindingSeverity.HIGH,
    "medium": FindingSeverity.MEDIUM,
    "low": FindingSeverity.LOW,
    "info": FindingSeverity.INFO,
}

# CVSS-like weight per severity
_CVSS_WEIGHT: dict[str, float] = {
    "critical": 9.8,
    "high": 8.0,
    "medium": 5.5,
    "low": 3.0,
}

# S3 listing response patterns (XML elements from ListBucketResult)
_S3_LISTING_PATTERN = re.compile(
    r"<ListBucketResult|<Contents>|<Key>", re.IGNORECASE
)

# GCS listing response patterns
_GCS_LISTING_PATTERN = re.compile(
    r"<ListBucketResult|<Contents>|<Key>|\"kind\":\s*\"storage#objects\"",
    re.IGNORECASE,
)

# Azure listing response patterns
_AZURE_LISTING_PATTERN = re.compile(
    r"<EnumerationResults|<Blobs>|<Blob>|<Name>", re.IGNORECASE
)


# ---------------------------------------------------------------------------
# Bucket name generation
# ---------------------------------------------------------------------------

def generate_bucket_names(domain: str) -> list[str]:
    """
    Generate common cloud bucket name permutations for a domain.

    Given 'example.com', produces:
      - Base names: example, example-com, example.com, examplecom
      - Prefix variants: backup-example, dev-example, ...
      - Suffix variants: example-backup, example-dev, ...

    Args:
        domain: Root domain string (e.g. 'example.com').

    Returns:
        De-duplicated list of candidate bucket names.
    """
    # Strip protocol/path if accidentally included
    domain = domain.strip().lower()
    if "://" in domain:
        domain = domain.split("://", 1)[1]
    domain = domain.split("/")[0]

    # Derive base variations - ALL names must contain the domain name
    # to avoid false positives on generic bucket names like "assets" or "cdn"
    parts = domain.split(".")
    name_base = parts[0] if parts else domain  # e.g. 'autistici'
    name_dash = "-".join(parts)                # e.g. 'autistici-org'
    name_concat = "".join(parts)               # e.g. 'autisticiorg'

    # Only use bases that are specific enough (>= 4 chars)
    bases = []
    for b in [name_base, name_dash, name_concat]:
        if len(b) >= 4 and b not in bases:
            bases.append(b)

    names: list[str] = []

    # Add base names (always contain the domain)
    names.extend(bases)

    # Add prefix/suffix variants using dash-form (most specific)
    for prefix in BUCKET_PREFIXES:
        names.append(f"{prefix}{name_dash}")

    for suffix in BUCKET_SUFFIXES:
        names.append(f"{name_dash}{suffix}")

    # De-duplicate preserving order
    seen: set[str] = set()
    unique: list[str] = []
    for name in names:
        if name not in seen:
            seen.add(name)
            unique.append(name)

    return unique


# ---------------------------------------------------------------------------
# Provider probe targets
# ---------------------------------------------------------------------------

def _build_s3_targets(bucket_names: list[str]) -> list[dict[str, str]]:
    """Build AWS S3 probe targets."""
    targets = []
    for name in bucket_names:
        targets.append({
            "provider": "aws-s3",
            "bucket_name": name,
            "check_url": f"https://{name}.s3.amazonaws.com",
            "list_url": f"https://{name}.s3.amazonaws.com/?list-type=2&max-keys=5",
        })
    return targets


def _build_gcs_targets(bucket_names: list[str]) -> list[dict[str, str]]:
    """Build Google Cloud Storage probe targets."""
    targets = []
    for name in bucket_names:
        targets.append({
            "provider": "gcs",
            "bucket_name": name,
            "check_url": f"https://storage.googleapis.com/{name}",
            "list_url": f"https://storage.googleapis.com/{name}",
        })
    return targets


def _build_azure_targets(bucket_names: list[str]) -> list[dict[str, str]]:
    """Build Azure Blob Storage probe targets."""
    targets = []
    for name in bucket_names:
        # Azure storage account names must be 3-24 chars, alphanumeric only
        sanitized = re.sub(r"[^a-z0-9]", "", name)
        if len(sanitized) < 3 or len(sanitized) > 24:
            continue
        targets.append({
            "provider": "azure-blob",
            "bucket_name": name,
            "check_url": f"https://{sanitized}.blob.core.windows.net/{sanitized}",
            "list_url": f"https://{sanitized}.blob.core.windows.net/{sanitized}?restype=container&comp=list&maxresults=5",
            "extra_checks": [
                f"https://{sanitized}.blob.core.windows.net/$web",
            ],
        })
    return targets


def _build_do_targets(bucket_names: list[str]) -> list[dict[str, str]]:
    """Build DigitalOcean Spaces probe targets."""
    targets = []
    for name in bucket_names:
        for region in DO_REGIONS:
            targets.append({
                "provider": "do-spaces",
                "bucket_name": name,
                "check_url": f"https://{name}.{region}.digitaloceanspaces.com",
                "list_url": f"https://{name}.{region}.digitaloceanspaces.com",
                "region": region,
            })
    return targets


# ---------------------------------------------------------------------------
# Async probing
# ---------------------------------------------------------------------------

async def _probe_bucket(
    client: httpx.AsyncClient,
    target: dict[str, str],
    semaphore: asyncio.Semaphore,
) -> dict[str, Any] | None:
    """
    Probe a single cloud bucket for existence and access level.

    Returns a finding dict if the bucket exists, None otherwise (404 / timeout).
    """
    async with semaphore:
        provider = target["provider"]
        bucket_name = target["bucket_name"]
        check_url = target["check_url"]
        list_url = target.get("list_url", check_url)

        try:
            # Step 1: HEAD request to check existence
            head_resp = await client.head(check_url, follow_redirects=True)
            status = head_resp.status_code

            if status == 404:
                return None

            # Step 2: Try GET on the list URL to check if listing is enabled
            listing_enabled = False
            public_read = False
            body_snippet = ""

            if status in (200, 301, 302):
                try:
                    get_resp = await client.get(list_url, follow_redirects=True)
                    get_status = get_resp.status_code
                    body = get_resp.text[:2000]

                    if get_status == 200:
                        # Check for listing patterns
                        if provider == "aws-s3" and _S3_LISTING_PATTERN.search(body):
                            listing_enabled = True
                        elif provider == "gcs" and _GCS_LISTING_PATTERN.search(body):
                            listing_enabled = True
                        elif provider == "azure-blob" and _AZURE_LISTING_PATTERN.search(body):
                            listing_enabled = True
                        elif provider == "do-spaces" and _S3_LISTING_PATTERN.search(body):
                            # DO Spaces uses S3-compatible API
                            listing_enabled = True
                        elif get_status == 200:
                            # 200 on the base URL but no listing pattern = public read
                            public_read = True

                        body_snippet = body[:500]

                except (httpx.TimeoutException, httpx.ConnectError):
                    pass

            # Step 3: Check extra URLs (Azure $web, etc.)
            extra_findings = []
            for extra_url in target.get("extra_checks", []):
                try:
                    extra_resp = await client.head(extra_url, follow_redirects=True)
                    if extra_resp.status_code == 200:
                        extra_findings.append({
                            "url": extra_url,
                            "status_code": extra_resp.status_code,
                        })
                except (httpx.TimeoutException, httpx.ConnectError):
                    pass

            # Determine severity and access level
            if listing_enabled:
                severity = "critical"
                access_level = "public-listing"
                description = (
                    f"Cloud bucket '{bucket_name}' on {provider} has public listing "
                    f"enabled. An attacker can enumerate all files in the bucket."
                )
            elif public_read or status == 200:
                severity = "high"
                access_level = "public-read"
                description = (
                    f"Cloud bucket '{bucket_name}' on {provider} allows public read "
                    f"access. Files in the bucket may be directly accessible."
                )
            elif status == 403:
                # 403 = bucket exists but no access. Low value finding - skip.
                return None
            elif status in (301, 302):
                # Redirect - not actionable, skip
                return None
            else:
                # Other non-404 statuses (e.g. 500) - not actionable
                return None

            result = {
                "provider": provider,
                "bucket_name": bucket_name,
                "check_url": check_url,
                "list_url": list_url,
                "http_status": status,
                "listing_enabled": listing_enabled,
                "public_read": public_read,
                "severity": severity,
                "access_level": access_level,
                "description": description,
                "body_snippet": body_snippet,
            }

            if extra_findings:
                result["extra_findings"] = extra_findings

            if target.get("region"):
                result["region"] = target["region"]

            return result

        except httpx.TimeoutException:
            return None
        except httpx.ConnectError:
            return None
        except httpx.ConnectTimeout:
            return None
        except (httpx.HTTPError, ValueError, UnicodeDecodeError) as exc:
            # Narrow catch: httpx transport errors, malformed responses, encoding issues
            logger.debug("Cloud probe error for %s: %s", target.get("bucket_name", "?"), exc)
            return None


async def _run_cloud_scan_async(
    targets: list[dict[str, str]],
) -> list[dict[str, Any]]:
    """
    Run all cloud bucket probes asynchronously with concurrency control.

    Args:
        targets: List of probe target dicts from the _build_*_targets helpers.

    Returns:
        List of finding dicts for buckets that exist.
    """
    semaphore = asyncio.Semaphore(_MAX_CONCURRENCY)

    transport = httpx.AsyncHTTPTransport(retries=0)
    limits = httpx.Limits(
        max_connections=_MAX_CONCURRENCY,
        max_keepalive_connections=10,
    )

    async with httpx.AsyncClient(
        transport=transport,
        limits=limits,
        timeout=httpx.Timeout(_REQUEST_TIMEOUT, connect=3.0),
        verify=False,  # Some cloud endpoints have cert issues with custom domains
        headers={"User-Agent": "EASM-Scanner/1.0"},
    ) as client:
        tasks = [
            _probe_bucket(client, target, semaphore)
            for target in targets
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

    findings = []
    for result in results:
        if isinstance(result, dict):
            findings.append(result)
    return findings


# ---------------------------------------------------------------------------
# Finding persistence
# ---------------------------------------------------------------------------

def _template_id_for_bucket(provider: str, access_level: str) -> str:
    """Generate a stable template_id for a cloud bucket finding."""
    return f"cloud-bucket-{provider}-{access_level}"


def _persist_findings(
    db,
    tenant_id: int,
    asset_id: int,
    findings: list[dict[str, Any]],
    scan_run_id: int | None = None,
    asset_identifier: str | None = None,
) -> dict[str, int]:
    """
    Persist cloud bucket findings to the database.

    De-duplicates by (asset_id, template_id, bucket_name) to avoid storing the
    same bucket finding multiple times across scan runs.

    Returns:
        Dict with 'created' and 'updated' counts.
    """
    created = 0
    updated = 0

    # De-duplicate within the batch: keep the highest-severity finding per bucket+provider
    seen: dict[str, dict[str, Any]] = {}
    for finding_data in findings:
        key = f"{finding_data['provider']}:{finding_data['bucket_name']}"
        if key in seen:
            # Keep the more severe finding
            severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
            existing_sev = severity_order.get(seen[key]["severity"], 0)
            new_sev = severity_order.get(finding_data["severity"], 0)
            if new_sev > existing_sev:
                seen[key] = finding_data
        else:
            seen[key] = finding_data

    for finding_data in seen.values():
        provider = finding_data["provider"]
        access_level = finding_data["access_level"]
        bucket_name = finding_data["bucket_name"]
        severity_str = finding_data["severity"]

        template_id = _template_id_for_bucket(provider, access_level)
        severity_enum = _SEVERITY_MAP.get(severity_str, FindingSeverity.MEDIUM)

        evidence = {
            "provider": provider,
            "bucket_name": bucket_name,
            "check_url": finding_data["check_url"],
            "list_url": finding_data["list_url"],
            "http_status": finding_data["http_status"],
            "listing_enabled": finding_data["listing_enabled"],
            "public_read": finding_data["public_read"],
            "access_level": access_level,
            "body_snippet": finding_data.get("body_snippet", ""),
            "source": "cloud_scan",
        }

        if finding_data.get("region"):
            evidence["region"] = finding_data["region"]
        if finding_data.get("extra_findings"):
            evidence["extra_findings"] = finding_data["extra_findings"]
        if scan_run_id:
            evidence["scan_run_id"] = scan_run_id

        # Build a unique matcher_name for dedup across runs
        matcher_name = f"{provider}:{bucket_name}"

        # Compute dedup fingerprint
        fp = compute_finding_fingerprint(
            tenant_id=tenant_id,
            asset_identifier=asset_identifier or str(asset_id),
            template_id=template_id,
            matcher_name=matcher_name,
            source="cloud_scan",
        )

        # Upsert: check for existing finding by fingerprint
        existing = (
            db.query(Finding)
            .filter(Finding.fingerprint == fp)
            .first()
        )

        if existing:
            existing.last_seen = datetime.now(timezone.utc)
            existing.evidence = evidence
            existing.severity = severity_enum
            existing.template_id = template_id
            existing.occurrence_count = (existing.occurrence_count or 1) + 1
            if existing.status == FindingStatus.FIXED:
                existing.status = FindingStatus.OPEN
            updated += 1
        else:
            finding = Finding(
                asset_id=asset_id,
                source="cloud_scan",
                template_id=template_id,
                name=finding_data["description"],
                severity=severity_enum,
                cvss_score=_CVSS_WEIGHT.get(severity_str, 5.0),
                evidence=evidence,
                first_seen=datetime.now(timezone.utc),
                last_seen=datetime.now(timezone.utc),
                status=FindingStatus.OPEN,
                matched_at=finding_data["check_url"],
                host=finding_data.get("bucket_name"),
                matcher_name=matcher_name,
                fingerprint=fp,
                occurrence_count=1,
            )
            db.add(finding)
            created += 1

    return {"created": created, "updated": updated}


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def run_cloud_bucket_scan(
    tenant_id: int,
    asset_ids: list[int],
    db=None,
    scan_run_id: int | None = None,
) -> dict[str, Any]:
    """
    Run cloud bucket/storage discovery for domain assets.

    Generates bucket name permutations from root domains and subdomains,
    then probes AWS S3, GCS, Azure Blob, and DigitalOcean Spaces for
    publicly accessible buckets.

    Args:
        tenant_id:    Tenant ID for scoping queries and logging.
        asset_ids:    List of Asset IDs to derive bucket names from.
                      Only DOMAIN and SUBDOMAIN assets produce bucket names.
        db:           Optional SQLAlchemy session. A new session is created
                      if not provided.
        scan_run_id:  Optional scan run ID for tracking in evidence.

    Returns:
        Dictionary with execution statistics.
    """
    own_session = db is None
    if own_session:
        db = SessionLocal()

    tenant_logger = TenantLoggerAdapter(logger, {"tenant_id": tenant_id})

    stats: dict[str, Any] = {
        "tenant_id": tenant_id,
        "scan_run_id": scan_run_id,
        "domains_processed": 0,
        "bucket_names_generated": 0,
        "targets_probed": 0,
        "buckets_found": 0,
        "findings_created": 0,
        "findings_updated": 0,
        "providers_checked": ["aws-s3", "gcs", "azure-blob", "do-spaces"],
        "errors": 0,
        "status": "success",
    }

    try:
        # Load domain/subdomain assets
        assets = (
            db.query(Asset)
            .filter(
                Asset.tenant_id == tenant_id,
                Asset.id.in_(asset_ids),
                Asset.is_active == True,  # noqa: E712
                Asset.type.in_([AssetType.DOMAIN, AssetType.SUBDOMAIN]),
            )
            .all()
        )

        if not assets:
            tenant_logger.info("No domain assets found for cloud bucket scanning")
            stats["status"] = "no_domain_assets"
            return stats

        stats["domains_processed"] = len(assets)

        # Generate bucket names from all domains (de-duplicated globally)
        all_bucket_names: list[str] = []
        seen_names: set[str] = set()

        for asset in assets:
            names = generate_bucket_names(asset.identifier)
            for name in names:
                if name not in seen_names:
                    seen_names.add(name)
                    all_bucket_names.append(name)

        stats["bucket_names_generated"] = len(all_bucket_names)

        if not all_bucket_names:
            tenant_logger.info("No bucket names generated from domain assets")
            stats["status"] = "no_bucket_names"
            return stats

        tenant_logger.info(
            f"Cloud bucket scan: {len(assets)} domains, "
            f"{len(all_bucket_names)} unique bucket names to probe"
        )

        # Build probe targets for all providers
        all_targets: list[dict[str, str]] = []
        all_targets.extend(_build_s3_targets(all_bucket_names))
        all_targets.extend(_build_gcs_targets(all_bucket_names))
        all_targets.extend(_build_azure_targets(all_bucket_names))
        all_targets.extend(_build_do_targets(all_bucket_names))

        stats["targets_probed"] = len(all_targets)

        tenant_logger.info(
            f"Cloud bucket scan: {len(all_targets)} total probe targets "
            f"across 4 providers"
        )

        # Run async probes with global timeout
        async def _run_with_timeout():
            try:
                return await asyncio.wait_for(
                    _run_cloud_scan_async(all_targets),
                    timeout=_GLOBAL_TIMEOUT,
                )
            except asyncio.TimeoutError:
                tenant_logger.warning(
                    f"Cloud bucket scan timed out after {_GLOBAL_TIMEOUT}s "
                    f"({len(all_targets)} targets)"
                )
                return []

        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                import concurrent.futures
                with concurrent.futures.ThreadPoolExecutor() as pool:
                    cloud_findings = pool.submit(
                        asyncio.run, _run_with_timeout()
                    ).result()
            else:
                cloud_findings = loop.run_until_complete(_run_with_timeout())
        except RuntimeError:
            cloud_findings = asyncio.run(_run_with_timeout())

        stats["buckets_found"] = len(cloud_findings)

        if cloud_findings:
            tenant_logger.info(
                f"Cloud bucket scan found {len(cloud_findings)} accessible buckets"
            )

            # Persist findings - associate with the first domain asset
            # (cloud buckets are org-level, linked to the primary domain)
            primary_asset_id = assets[0].id

            result = _persist_findings(
                db, tenant_id, primary_asset_id, cloud_findings,
                scan_run_id=scan_run_id,
                asset_identifier=assets[0].identifier,
            )
            stats["findings_created"] = result["created"]
            stats["findings_updated"] = result["updated"]

            db.commit()

            # Log severity breakdown
            severity_counts: dict[str, int] = {}
            for f in cloud_findings:
                sev = f["severity"]
                severity_counts[sev] = severity_counts.get(sev, 0) + 1

            tenant_logger.info(
                f"Cloud bucket findings breakdown: {severity_counts}"
            )
        else:
            tenant_logger.info("Cloud bucket scan: no accessible buckets found")

        tenant_logger.info(
            f"Cloud bucket scan complete: "
            f"{stats['domains_processed']} domains, "
            f"{stats['bucket_names_generated']} names, "
            f"{stats['targets_probed']} probes, "
            f"{stats['buckets_found']} found, "
            f"{stats['findings_created']} created, "
            f"{stats['findings_updated']} updated"
        )

    except Exception as exc:
        tenant_logger.error(
            f"Cloud bucket scan failed: {exc}", exc_info=True
        )
        stats["status"] = "failed"
        stats["error"] = str(exc)
        stats["errors"] += 1
        try:
            db.rollback()
        except Exception:
            logger.debug("db.rollback() failed after cloud_scan error", exc_info=True)
    finally:
        if own_session:
            db.close()

    return stats
