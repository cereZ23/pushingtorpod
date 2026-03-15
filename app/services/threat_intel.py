"""
Threat Intelligence service for EPSS and CISA KEV data.

Integrates two key threat intelligence feeds to enhance vulnerability prioritization:

EPSS (Exploit Prediction Scoring System):
    Provides a probability score (0.0-1.0) representing the likelihood that a CVE
    will be exploited in the wild within the next 30 days. Published by FIRST.org.
    API: https://api.first.org/data/v1/epss

CISA KEV (Known Exploited Vulnerabilities):
    A catalog of CVEs confirmed to be actively exploited in the wild, maintained
    by CISA. Listed CVEs carry binding operational directives for federal agencies.
    Feed: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json

Both data sources are cached in Redis with a 24-hour TTL to minimize external API
calls while maintaining reasonably fresh threat data. The service is designed to
degrade gracefully: if external APIs are unreachable, it falls back to cached data
or returns safe defaults (0.0 EPSS score, not in KEV).

Integration points:
    - RiskScoringEngine._score_findings() uses EPSS/KEV to boost finding scores
    - update_asset_risk_scores() in scanning tasks passes EPSS/KEV to scoring
    - Celery Beat runs daily refresh at 2 AM UTC
    - API endpoints allow manual refresh and per-finding lookups
"""

import json
import logging
from datetime import datetime, timezone
from typing import Optional

import httpx
import redis

from app.config import settings

logger = logging.getLogger(__name__)

# EPSS API endpoint (FIRST.org)
EPSS_API_URL = "https://api.first.org/data/v1/epss"

# CISA KEV catalog feed
KEV_CATALOG_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# Redis key prefixes and TTL
EPSS_KEY_PREFIX = "epss:"
KEV_CATALOG_KEY = "kev:catalog"
KEV_DETAILS_KEY_PREFIX = "kev:detail:"
KEV_META_LAST_REFRESH = "kev:last_refresh"
KEV_META_COUNT = "kev:count"
CACHE_TTL = 86400  # 24 hours in seconds

# EPSS API batch limit
EPSS_BATCH_SIZE = 100

# HTTP client timeout
HTTP_TIMEOUT = 30


def _get_redis_client() -> redis.Redis:
    """Create a Redis client from application settings.

    Returns:
        Configured Redis client instance.
    """
    return redis.from_url(settings.redis_url, decode_responses=True)


class ThreatIntelService:
    """Fetches and caches EPSS scores and CISA KEV data.

    This service provides the bridge between external threat intelligence feeds
    and the internal risk scoring engine. All lookups check Redis first and only
    reach out to external APIs on cache misses.

    Args:
        redis_client: Optional pre-configured Redis client. If not provided,
            one is created from application settings.
    """

    def __init__(self, redis_client: Optional[redis.Redis] = None):
        self.redis = redis_client or _get_redis_client()

    # ------------------------------------------------------------------
    # EPSS Methods
    # ------------------------------------------------------------------

    def get_epss_score(self, cve_id: str) -> float:
        """Get EPSS probability score for a single CVE.

        Checks Redis cache first, then fetches from the FIRST.org EPSS API
        on cache miss. The result is cached with a 24-hour TTL.

        Args:
            cve_id: CVE identifier (e.g. "CVE-2024-1234").

        Returns:
            EPSS probability score between 0.0 and 1.0.
            Returns 0.0 if the CVE is not found or on error.
        """
        if not cve_id:
            return 0.0

        cve_id = cve_id.upper().strip()
        cache_key = f"{EPSS_KEY_PREFIX}{cve_id}"

        # Check cache
        try:
            cached = self.redis.get(cache_key)
            if cached is not None:
                return float(cached)
        except redis.RedisError as exc:
            logger.warning("Redis read error for EPSS cache: %s", exc)

        # Cache miss - fetch from API
        try:
            with httpx.Client(timeout=HTTP_TIMEOUT) as client:
                response = client.get(EPSS_API_URL, params={"cve": cve_id})
                response.raise_for_status()

            data = response.json()
            entries = data.get("data", [])

            if entries:
                score = float(entries[0].get("epss", 0.0))
            else:
                score = 0.0

            # Cache result
            try:
                self.redis.setex(cache_key, CACHE_TTL, str(score))
            except redis.RedisError as exc:
                logger.warning("Redis write error for EPSS cache: %s", exc)

            return score

        except (httpx.HTTPError, ValueError, KeyError) as exc:
            logger.error("Failed to fetch EPSS score for %s: %s", cve_id, exc)
            return 0.0

    def get_epss_scores_bulk(self, cve_ids: list[str]) -> dict[str, float]:
        """Batch lookup of EPSS scores for multiple CVEs.

        For efficiency, this method first checks Redis for cached values and
        only fetches cache misses from the EPSS API. The API supports
        comma-separated CVE IDs (up to 100 per request).

        Args:
            cve_ids: List of CVE identifiers.

        Returns:
            Dictionary mapping CVE IDs to their EPSS scores.
            CVEs not found default to 0.0.
        """
        if not cve_ids:
            return {}

        # Normalize and deduplicate
        normalized = list({cve.upper().strip() for cve in cve_ids if cve})
        results: dict[str, float] = {}
        misses: list[str] = []

        # Check cache for all CVEs
        for cve_id in normalized:
            cache_key = f"{EPSS_KEY_PREFIX}{cve_id}"
            try:
                cached = self.redis.get(cache_key)
                if cached is not None:
                    results[cve_id] = float(cached)
                else:
                    misses.append(cve_id)
            except redis.RedisError:
                misses.append(cve_id)

        if not misses:
            return results

        logger.info(
            "EPSS bulk lookup: %d cached, %d to fetch",
            len(results),
            len(misses),
        )

        # Fetch misses in batches of EPSS_BATCH_SIZE
        for batch_start in range(0, len(misses), EPSS_BATCH_SIZE):
            batch = misses[batch_start : batch_start + EPSS_BATCH_SIZE]
            cve_param = ",".join(batch)

            try:
                with httpx.Client(timeout=HTTP_TIMEOUT) as client:
                    response = client.get(EPSS_API_URL, params={"cve": cve_param})
                    response.raise_for_status()

                data = response.json()
                entries = data.get("data", [])

                # Index returned entries by CVE ID
                fetched: dict[str, float] = {}
                for entry in entries:
                    entry_cve = entry.get("cve", "").upper()
                    entry_score = float(entry.get("epss", 0.0))
                    fetched[entry_cve] = entry_score

                # Cache all results (including 0.0 for not-found CVEs)
                pipe = self.redis.pipeline(transaction=False)
                for cve_id in batch:
                    score = fetched.get(cve_id, 0.0)
                    results[cve_id] = score
                    pipe.setex(f"{EPSS_KEY_PREFIX}{cve_id}", CACHE_TTL, str(score))

                try:
                    pipe.execute()
                except redis.RedisError as exc:
                    logger.warning("Redis pipeline error caching EPSS: %s", exc)

            except (httpx.HTTPError, ValueError, KeyError) as exc:
                logger.error("Failed to fetch EPSS batch: %s", exc)
                # Default to 0.0 for failed batch
                for cve_id in batch:
                    results.setdefault(cve_id, 0.0)

        return results

    # ------------------------------------------------------------------
    # KEV Methods
    # ------------------------------------------------------------------

    def is_in_kev(self, cve_id: str) -> bool:
        """Check if a CVE is in the CISA Known Exploited Vulnerabilities catalog.

        Uses a Redis set containing all CVE IDs from the KEV catalog.
        If the set does not exist, triggers a catalog refresh first.

        Args:
            cve_id: CVE identifier (e.g. "CVE-2024-1234").

        Returns:
            True if the CVE is in the KEV catalog, False otherwise.
        """
        if not cve_id:
            return False

        cve_id = cve_id.upper().strip()

        try:
            # Check if catalog exists in Redis
            if not self.redis.exists(KEV_CATALOG_KEY):
                logger.info("KEV catalog not in cache, refreshing...")
                self.refresh_kev_catalog()

            return bool(self.redis.sismember(KEV_CATALOG_KEY, cve_id))

        except redis.RedisError as exc:
            logger.error("Redis error checking KEV catalog: %s", exc)
            return False

    def refresh_kev_catalog(self) -> int:
        """Download and cache the full CISA KEV catalog.

        Fetches the JSON feed from CISA, extracts all CVE IDs, and stores them
        in a Redis set for fast membership lookups. Also caches individual KEV
        details (vendor, product, dates, required actions) in separate keys.

        Returns:
            Number of CVEs stored in the catalog.

        Raises:
            httpx.HTTPError: If the CISA feed is unreachable (after logging).
        """
        logger.info("Refreshing CISA KEV catalog from %s", KEV_CATALOG_URL)

        try:
            with httpx.Client(timeout=HTTP_TIMEOUT) as client:
                response = client.get(KEV_CATALOG_URL)
                response.raise_for_status()

            catalog = response.json()
            vulnerabilities = catalog.get("vulnerabilities", [])

            if not vulnerabilities:
                logger.warning("KEV catalog returned empty vulnerability list")
                return 0

            # Build set of CVE IDs and cache details
            cve_ids = []
            pipe = self.redis.pipeline(transaction=False)

            for vuln in vulnerabilities:
                cve_id = vuln.get("cveID", "").upper().strip()
                if not cve_id:
                    continue

                cve_ids.append(cve_id)

                # Cache individual vulnerability details
                detail = {
                    "cve_id": cve_id,
                    "vendor": vuln.get("vendorProject", ""),
                    "product": vuln.get("product", ""),
                    "vulnerability_name": vuln.get("vulnerabilityName", ""),
                    "date_added": vuln.get("dateAdded", ""),
                    "short_description": vuln.get("shortDescription", ""),
                    "required_action": vuln.get("requiredAction", ""),
                    "due_date": vuln.get("dueDate", ""),
                    "known_ransomware_use": vuln.get("knownRansomwareCampaignUse", "Unknown"),
                    "notes": vuln.get("notes", ""),
                }
                detail_key = f"{KEV_DETAILS_KEY_PREFIX}{cve_id}"
                pipe.setex(detail_key, CACHE_TTL, json.dumps(detail))

            # Replace the catalog set atomically
            pipe.delete(KEV_CATALOG_KEY)
            if cve_ids:
                pipe.sadd(KEV_CATALOG_KEY, *cve_ids)
                pipe.expire(KEV_CATALOG_KEY, CACHE_TTL)

            # Store metadata
            now_iso = datetime.now(timezone.utc).isoformat()
            pipe.setex(KEV_META_LAST_REFRESH, CACHE_TTL, now_iso)
            pipe.setex(KEV_META_COUNT, CACHE_TTL, str(len(cve_ids)))

            pipe.execute()

            logger.info("KEV catalog refreshed: %d vulnerabilities cached", len(cve_ids))
            return len(cve_ids)

        except httpx.HTTPError as exc:
            logger.error("Failed to fetch KEV catalog: %s", exc)
            raise
        except (redis.RedisError, ValueError, KeyError) as exc:
            logger.error("Failed to cache KEV catalog: %s", exc)
            return 0

    def get_kev_details(self, cve_id: str) -> Optional[dict]:
        """Get KEV catalog details for a specific CVE.

        Returns structured data including vendor, product, date added to KEV,
        required remediation action, and compliance due date.

        Args:
            cve_id: CVE identifier.

        Returns:
            Dictionary with KEV details, or None if the CVE is not in KEV.
        """
        if not cve_id:
            return None

        cve_id = cve_id.upper().strip()

        # Ensure catalog is loaded
        if not self.is_in_kev(cve_id):
            return None

        try:
            detail_key = f"{KEV_DETAILS_KEY_PREFIX}{cve_id}"
            cached = self.redis.get(detail_key)
            if cached:
                return json.loads(cached)
        except (redis.RedisError, json.JSONDecodeError) as exc:
            logger.warning("Failed to get KEV details for %s: %s", cve_id, exc)

        return None

    # ------------------------------------------------------------------
    # Bulk Enrichment
    # ------------------------------------------------------------------

    def enrich_findings(self, findings: list) -> list[dict]:
        """Bulk enrich findings with EPSS and KEV data.

        For each finding that has a cve_id, performs a batch EPSS lookup and
        individual KEV checks. This is the primary integration point used by
        the risk scoring engine and the enrichment Celery tasks.

        Args:
            findings: List of Finding ORM objects or dicts with at minimum
                'id' and 'cve_id' attributes/keys.

        Returns:
            List of enrichment dicts, one per finding with a CVE:
            [
                {
                    "finding_id": 42,
                    "cve_id": "CVE-2024-1234",
                    "epss_score": 0.973,
                    "epss_percentile": None,
                    "is_kev": True,
                    "kev_details": {...}
                },
                ...
            ]
        """
        if not findings:
            return []

        # Collect unique CVE IDs, mapping finding_id -> cve_id
        finding_cves: list[tuple[int, str]] = []
        unique_cves: set[str] = set()

        for finding in findings:
            # Support both ORM objects and dicts
            if isinstance(finding, dict):
                finding_id = finding.get("id")
                cve_id = finding.get("cve_id")
            else:
                finding_id = getattr(finding, "id", None)
                cve_id = getattr(finding, "cve_id", None)

            if finding_id is not None and cve_id:
                cve_upper = cve_id.upper().strip()
                finding_cves.append((finding_id, cve_upper))
                unique_cves.add(cve_upper)

        if not unique_cves:
            return []

        # Batch EPSS lookup
        epss_scores = self.get_epss_scores_bulk(list(unique_cves))

        # Build enrichment results
        enrichments = []
        for finding_id, cve_id in finding_cves:
            is_kev = self.is_in_kev(cve_id)
            kev_details = self.get_kev_details(cve_id) if is_kev else None

            enrichments.append(
                {
                    "finding_id": finding_id,
                    "cve_id": cve_id,
                    "epss_score": epss_scores.get(cve_id, 0.0),
                    "is_kev": is_kev,
                    "kev_details": kev_details,
                }
            )

        logger.info(
            "Enriched %d findings (%d unique CVEs, %d in KEV)",
            len(enrichments),
            len(unique_cves),
            sum(1 for e in enrichments if e["is_kev"]),
        )

        return enrichments

    # ------------------------------------------------------------------
    # Status / Metadata
    # ------------------------------------------------------------------

    def get_status(self) -> dict:
        """Get current threat intelligence cache status.

        Returns:
            Dictionary with last refresh timestamp, KEV count, and cache health.
        """
        status: dict = {
            "kev_last_refresh": None,
            "kev_count": 0,
            "kev_catalog_cached": False,
            "epss_cache_available": False,
        }

        try:
            last_refresh = self.redis.get(KEV_META_LAST_REFRESH)
            kev_count = self.redis.get(KEV_META_COUNT)
            kev_exists = self.redis.exists(KEV_CATALOG_KEY)

            status["kev_last_refresh"] = last_refresh
            status["kev_count"] = int(kev_count) if kev_count else 0
            status["kev_catalog_cached"] = bool(kev_exists)
            status["epss_cache_available"] = True

        except redis.RedisError as exc:
            logger.warning("Redis error getting threat intel status: %s", exc)
            status["error"] = str(exc)

        return status
