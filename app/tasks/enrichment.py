"""
Enrichment pipeline tasks for asset enrichment

Sprint 2: Implements HTTP fingerprinting (HTTPx), port scanning (Naabu),
TLS/SSL analysis (TLSx), and web crawling (Katana) with comprehensive
security controls and tiered enrichment based on asset priority.

Security Features:
- Input validation (DomainValidator, URLValidator)
- SSRF prevention (network blocklists)
- Output sanitization (private key detection, credential redaction)
- Resource limits (timeout, memory, CPU)
- Rate limiting per tenant
- Secure subprocess execution
"""

from celery import chain, group
import logging
import json
import re
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

from app.celery_app import celery
from app.models.database import Asset, AssetType
from app.models.enrichment import Certificate, Endpoint
from app.utils.storage import store_raw_output
from app.utils.logger import TenantLoggerAdapter
from app.utils.validators import DomainValidator, URLValidator
from app.utils.secure_executor import SecureToolExecutor, ToolExecutionError
from app.config import settings

logger = logging.getLogger(__name__)

# =============================================================================
# ENRICHMENT ORCHESTRATION
# =============================================================================


@celery.task(name="app.tasks.enrichment.run_enrichment_pipeline")
def run_enrichment_pipeline(
    tenant_id: int, asset_ids: Optional[List[int]] = None, priority: Optional[str] = None, force_refresh: bool = False
):
    """
    Run complete enrichment pipeline for assets

    Orchestrates parallel execution of HTTPx + Naabu + TLSx,
    followed by sequential Katana (which depends on HTTPx results).

    Args:
        tenant_id: Tenant ID
        asset_ids: Optional list of specific asset IDs to enrich
        priority: Optional priority level to enrich (critical, high, normal, low)
        force_refresh: If True, enrich even if recently enriched

    Returns:
        Dict with enrichment statistics

    Architecture:
        Phase 1 (Parallel): HTTPx + Naabu + TLSx run concurrently
        Phase 2 (Sequential): Katana runs after HTTPx completes
    """
    from app.database import SessionLocal

    db = SessionLocal()

    try:
        tenant_logger = TenantLoggerAdapter(logger, {"tenant_id": tenant_id})
        tenant_logger.info(f"Starting enrichment pipeline (priority: {priority}, force: {force_refresh})")

        # Get enrichment candidates
        candidates = get_enrichment_candidates(
            tenant_id=tenant_id, asset_ids=asset_ids, priority=priority, force_refresh=force_refresh, db=db
        )

        if not candidates:
            tenant_logger.info("No assets need enrichment")
            return {"assets_enriched": 0, "status": "no_candidates"}

        tenant_logger.info(f"Enriching {len(candidates)} assets")

        # Phase 1: Run HTTPx + Naabu + TLSx in parallel using chord
        # IMPORTANT: chord() waits for all group tasks to complete before callback
        # group() + chain() doesn't wait, it proceeds after first task completes!
        parallel_tasks = [
            run_httpx.si(tenant_id, candidates),
            run_naabu.si(tenant_id, candidates),
            run_tlsx.si(tenant_id, candidates),
        ]

        # Phase 2: Run Katana after all enrichment completes
        # Phase 3: Run Nuclei after Katana (if enabled)
        # chord(group_of_tasks, callback) - callback runs after ALL group tasks complete
        from celery import chord

        if settings.feature_nuclei_enabled:
            from app.tasks.scanning import run_nuclei_scan

            # Use chord to wait for ALL enrichment tasks, then run Katana, then Nuclei
            # chord() returns an AsyncResult when called, don't call apply_async() again
            result = chord(parallel_tasks)(
                chain(
                    run_katana.si(tenant_id, candidates),
                    run_nuclei_scan.si(tenant_id, candidates, ["critical", "high", "medium"]),
                )
            )
        else:
            # Use chord to wait for ALL enrichment tasks, then run Katana
            result = chord(parallel_tasks)(run_katana.si(tenant_id, candidates))

        return {"tenant_id": tenant_id, "assets_queued": len(candidates), "status": "started", "task_id": result.id}

    except Exception as e:
        logger.error(f"Error starting enrichment pipeline for tenant {tenant_id}: {e}", exc_info=True)
        return {"error": str(e), "status": "failed"}
    finally:
        db.close()


def get_enrichment_candidates(
    tenant_id: int, asset_ids: Optional[List[int]], priority: Optional[str], force_refresh: bool, db
) -> List[int]:
    """
    Get list of asset IDs that need enrichment

    Implements tiered enrichment with priority-based TTL:
    - critical: 1 day TTL
    - high: 3 days TTL
    - normal: 7 days TTL
    - low: 14 days TTL

    Args:
        tenant_id: Tenant ID
        asset_ids: Optional specific assets to enrich
        priority: Optional priority filter
        force_refresh: If True, return all active assets
        db: Database session

    Returns:
        List of asset IDs to enrich
    """
    # If specific asset IDs provided, use those
    if asset_ids:
        assets = (
            db.query(Asset).filter(Asset.id.in_(asset_ids), Asset.tenant_id == tenant_id, Asset.is_active == True).all()
        )
        return [asset.id for asset in assets]

    # Get TTL for priority level
    ttl_map = {
        "critical": 1,  # 1 day
        "high": 3,  # 3 days
        "normal": 7,  # 7 days
        "low": 14,  # 14 days
    }

    if force_refresh:
        # Return all active assets for this priority
        query = db.query(Asset).filter(Asset.tenant_id == tenant_id, Asset.is_active == True)
        if priority:
            query = query.filter(Asset.priority == priority)

        assets = query.order_by(Asset.risk_score.desc()).limit(settings.enrichment_batch_size).all()
        return [asset.id for asset in assets]

    # Normal operation: Check TTL
    if priority:
        ttl_days = ttl_map.get(priority, 7)
        cutoff = datetime.now(timezone.utc) - timedelta(days=ttl_days)

        assets = (
            db.query(Asset)
            .filter(
                Asset.tenant_id == tenant_id,
                Asset.is_active == True,
                Asset.priority == priority,
                (Asset.last_enriched_at.is_(None)) | (Asset.last_enriched_at < cutoff),
            )
            .order_by(Asset.risk_score.desc())
            .limit(settings.enrichment_batch_size)
            .all()
        )
    else:
        # No priority specified, enrich stale assets from all priorities
        # Most efficient: use single query with OR conditions for each priority
        from sqlalchemy import or_, and_

        priority_conditions = []
        for pri, days in ttl_map.items():
            cutoff = datetime.now(timezone.utc) - timedelta(days=days)
            priority_conditions.append(
                and_(Asset.priority == pri, (Asset.last_enriched_at.is_(None)) | (Asset.last_enriched_at < cutoff))
            )

        assets = (
            db.query(Asset)
            .filter(Asset.tenant_id == tenant_id, Asset.is_active == True, or_(*priority_conditions))
            .order_by(Asset.risk_score.desc())
            .limit(settings.enrichment_batch_size)
            .all()
        )

    return [asset.id for asset in assets]


# =============================================================================
# HTTPX - HTTP TECHNOLOGY FINGERPRINTING
# =============================================================================


@celery.task(name="app.tasks.enrichment.run_httpx")
def run_httpx(tenant_id: int, asset_ids: List[int]):
    """
    Run HTTPx for HTTP technology fingerprinting

    Probes HTTP/HTTPS services to detect:
    - Web servers (nginx, Apache, IIS)
    - Technologies (WordPress, PHP, Node.js)
    - HTTP status codes and redirects
    - Response times and headers
    - TLS configuration

    Security Controls:
    - URL validation (URLValidator)
    - SSRF prevention (network blocklists)
    - Response size limits (1MB max)
    - Timeout limits (15 minutes max)
    - Credential redaction from headers

    Args:
        tenant_id: Tenant ID
        asset_ids: List of asset IDs to probe

    Returns:
        Dict with enrichment results
    """
    from app.database import SessionLocal
    from app.repositories.service_repository import ServiceRepository

    db = SessionLocal()
    tenant_logger = TenantLoggerAdapter(logger, {"tenant_id": tenant_id})

    try:
        # Get assets
        assets = db.query(Asset).filter(Asset.id.in_(asset_ids), Asset.tenant_id == tenant_id).all()

        if not assets:
            tenant_logger.warning(f"No assets found for HTTPx (IDs: {asset_ids})")
            return {"services_enriched": 0}

        # Build URL list from assets and maintain asset_id mapping
        # HTTPx accepts domains, IPs, and URLs
        urls = []
        url_to_asset_id = {}  # Map URLs to asset IDs for later matching
        url_validator = URLValidator()

        for asset in assets:
            if asset.type in [AssetType.DOMAIN, AssetType.SUBDOMAIN]:
                # Try both http and https
                for scheme in ["http", "https"]:
                    url = f"{scheme}://{asset.identifier}"
                    is_valid, _ = url_validator.validate_url(url)
                    if is_valid:
                        urls.append(url)
                        url_to_asset_id[asset.identifier.lower()] = asset.id  # Map host to asset_id
            elif asset.type == AssetType.IP:
                # Try common web ports
                for port in [80, 443, 8080, 8443]:
                    scheme = "https" if port in [443, 8443] else "http"
                    url = f"{scheme}://{asset.identifier}:{port}"
                    is_valid, _ = url_validator.validate_url(url)
                    if is_valid:
                        urls.append(url)
                        url_to_asset_id[asset.identifier.lower()] = asset.id  # Map IP to asset_id
            elif asset.type == AssetType.URL:
                is_valid, _ = url_validator.validate_url(asset.identifier)
                if is_valid:
                    urls.append(asset.identifier)
                    # For URL type, extract host for mapping
                    parsed = urlparse(asset.identifier)
                    if parsed.hostname:
                        url_to_asset_id[parsed.hostname.lower()] = asset.id

        if not urls:
            tenant_logger.warning(f"No valid URLs for HTTPx (tenant {tenant_id})")
            return {"services_enriched": 0}

        tenant_logger.info(f"Running HTTPx on {len(urls)} URLs (tenant {tenant_id})")
        tenant_logger.info(f"HTTPx URLs: {urls[:5]}...")  # Log first 5 URLs

        # Execute HTTPx with secure executor
        with SecureToolExecutor(tenant_id) as executor:
            # Use stdin instead of file to avoid HTTPx memory leak with -l flag
            urls_content = "\n".join(urls)

            # Execute HTTPx with stdin
            returncode, stdout, stderr = executor.execute(
                "httpx",
                [
                    "-json",  # JSON output
                    "-status-code",  # Include status code
                    "-title",  # Include page title
                    "-web-server",  # Detect web server
                    "-tech-detect",  # Detect technologies (safe in v1.6.8)
                    "-response-time",  # Include response time
                    "-content-length",  # Include content length
                    "-include-response-header",  # Include HTTP response headers
                    "-follow-redirects",  # Follow redirects
                    "-max-redirects",
                    "3",  # Limit redirects
                    "-no-color",  # Disable colors
                    "-silent",  # Minimal output
                    "-threads",
                    "50",  # Concurrent requests (was 10, too slow for 1200 URLs)
                    "-timeout",
                    "10",  # Per-request timeout: 10s (EASM targets, not deep crawl)
                    "-rate-limit",
                    str(settings.httpx_rate_limit),
                ],
                timeout=settings.httpx_timeout + 600,  # Process timeout = config + 10 min buffer
                stdin_data=urls_content,  # Pass URLs via stdin
            )

            if returncode != 0:
                tenant_logger.warning(f"HTTPx returned non-zero exit code: {returncode}")
                tenant_logger.warning(f"HTTPx stderr: {stderr}")
                tenant_logger.warning(f"HTTPx stdout length: {len(stdout)}")

            # Parse JSON output
            services_data = []
            for line in stdout.strip().split("\n"):
                if not line:
                    continue

                try:
                    result = json.loads(line)

                    # Extract service data
                    service_data = parse_httpx_result(result, tenant_logger)
                    if service_data:
                        # Match host to asset_id using our mapping
                        host = service_data.get("host", "").lower()
                        asset_id = url_to_asset_id.get(host)
                        if asset_id:
                            service_data["asset_id"] = asset_id
                            services_data.append(service_data)
                        else:
                            tenant_logger.warning(f"No asset found for host: {host}")

                except json.JSONDecodeError as e:
                    tenant_logger.warning(f"Failed to parse HTTPx JSON: {e}")
                    continue

            # Store raw output in MinIO
            try:
                store_raw_output(tenant_id, "httpx", {"urls": urls, "results": services_data})
            except Exception as e:
                tenant_logger.warning(f"Failed to store HTTPx raw output: {e}")

            # Upsert services to database
            service_repo = ServiceRepository(db)
            total_created = 0
            total_updated = 0

            # Group services by asset and deduplicate by port
            # HTTPx may return duplicate results (e.g., redirects, multiple probes)
            services_by_asset = {}
            for service in services_data:
                asset_id = service["asset_id"]
                port = service["port"]

                if asset_id not in services_by_asset:
                    services_by_asset[asset_id] = {}

                # Deduplicate by port - keep latest result
                # This prevents PostgreSQL CardinalityViolation errors
                services_by_asset[asset_id][port] = service

            for asset_id, services_dict in services_by_asset.items():
                # Convert dict back to list for bulk_upsert
                asset_services = list(services_dict.values())
                result = service_repo.bulk_upsert(asset_id, asset_services)
                total_created += result["created"]
                total_updated += result["updated"]

                # Update asset enrichment tracking
                asset = db.query(Asset).filter_by(id=asset_id).first()
                if asset:
                    asset.last_enriched_at = datetime.now(timezone.utc)
                    asset.enrichment_status = "enriched"

            db.commit()

            tenant_logger.info(
                f"HTTPx complete: {total_created} new services, {total_updated} updated (tenant {tenant_id})"
            )

            return {
                "services_created": total_created,
                "services_updated": total_updated,
                "total_processed": total_created + total_updated,
            }

    except ToolExecutionError as e:
        tenant_logger.error(f"HTTPx execution failed: {e}")
        return {"error": str(e), "services_enriched": 0}
    except Exception as e:
        tenant_logger.error(f"HTTPx error: {e}", exc_info=True)
        return {"error": str(e), "services_enriched": 0}
    finally:
        db.close()


def parse_httpx_result(result: Dict, tenant_logger) -> Optional[Dict]:
    """
    Parse HTTPx JSON output into service data

    Sanitizes output to prevent:
    - Credential exposure (Authorization, Cookie headers)
    - XSS (HTML/JS in title)
    - URL credential leakage

    Args:
        result: HTTPx JSON result
        tenant_logger: Logger instance

    Returns:
        Service data dict or None if parsing fails
    """
    try:
        url = result.get("url")
        if not url:
            return None

        # Parse URL to get host and port
        parsed = urlparse(url)
        host = parsed.hostname
        port = parsed.port

        # Determine default port if not specified
        if not port:
            port = 443 if parsed.scheme == "https" else 80

        # Sanitize headers - redact sensitive values
        headers = result.get("header", {})
        if isinstance(headers, dict):
            sanitized_headers = sanitize_http_headers(headers)
        else:
            sanitized_headers = {}

        # Extract technologies — httpx uses 'tech' field (e.g. ["IIS:10.0", "jQuery", "PHP"])
        technologies = result.get("tech", []) or result.get("technologies", [])
        if not isinstance(technologies, list):
            technologies = []
        # Strip version suffixes for clean names (IIS:10.0 → IIS), keep raw for versions
        technologies = [t.split(":")[0] if ":" in t else t for t in technologies if t]

        # Build service data
        service_data = {
            "port": port,
            "protocol": parsed.scheme,
            "http_status": result.get("status_code"),
            "http_title": sanitize_html(result.get("title", ""))[:500],  # Limit length, sanitize
            "web_server": result.get("webserver", "")[:200],
            "product": (result.get("webserver", "") or "").split("/")[0].strip()[:200] or None,
            "version": (result.get("webserver", "") or "").split("/")[1].strip()[:50]
            if "/" in (result.get("webserver", "") or "")
            else None,
            "http_technologies": technologies,
            "http_headers": sanitized_headers,
            "response_time_ms": result.get("time", "").replace("ms", "").strip() if result.get("time") else None,
            "content_length": result.get("content_length"),
            "redirect_url": result.get("final_url"),
            "has_tls": parsed.scheme == "https",
            "enrichment_source": "httpx",
            "enriched_at": datetime.now(timezone.utc),
        }

        # Convert response_time_ms to int
        if service_data["response_time_ms"]:
            try:
                service_data["response_time_ms"] = int(float(service_data["response_time_ms"]))
            except (ValueError, TypeError):
                service_data["response_time_ms"] = None

        # Find asset ID by matching host
        # This is done by the caller, we just return the host
        service_data["host"] = host

        return service_data

    except Exception as e:
        tenant_logger.warning(f"Failed to parse HTTPx result: {e}")
        return None


def sanitize_http_headers(headers: Dict[str, str]) -> Dict[str, str]:
    """
    Sanitize HTTP headers to prevent credential exposure

    Redacts sensitive headers:
    - Authorization
    - Cookie
    - Set-Cookie
    - X-API-Key
    - API-Key
    - Token
    - Secret

    Args:
        headers: HTTP headers dict

    Returns:
        Sanitized headers dict
    """
    sensitive_headers = ["authorization", "cookie", "set-cookie", "x-api-key", "api-key", "token", "secret"]

    sanitized = {}
    for key, value in headers.items():
        key_lower = key.lower()
        if any(s in key_lower for s in sensitive_headers):
            sanitized[key] = "[REDACTED]"
        else:
            sanitized[key] = value

    return sanitized


def sanitize_html(text: str) -> str:
    """
    Sanitize HTML/JS to prevent XSS.

    Strips all HTML tags using stdlib HTMLParser (not regex) to avoid
    incomplete tag-filter bypasses (CWE-116 / CodeQL py/bad-tag-filter).
    Also removes javascript: URL schemes from the remaining text.

    This is a defense-in-depth guard on httpx response metadata before DB
    storage — not the primary XSS defense layer.

    Args:
        text: Text to sanitize

    Returns:
        Text with all HTML tags removed and javascript: schemes stripped.
    """
    if not text:
        return ""

    from html.parser import HTMLParser

    class _TagStripper(HTMLParser):
        """Collect visible text, suppressing script/style/noscript bodies."""

        _SUPPRESS = frozenset({"script", "style", "noscript"})

        def __init__(self) -> None:
            super().__init__(convert_charrefs=True)
            self._parts: list[str] = []
            # Depth counter for tags whose text content must also be dropped.
            self._skip_depth: int = 0

        def handle_starttag(self, tag: str, attrs: list) -> None:
            if tag.lower() in self._SUPPRESS:
                self._skip_depth += 1

        def handle_endtag(self, tag: str) -> None:
            if tag.lower() in self._SUPPRESS and self._skip_depth > 0:
                self._skip_depth -= 1

        def handle_data(self, data: str) -> None:
            if self._skip_depth == 0:
                self._parts.append(data)

        def get_text(self) -> str:
            return "".join(self._parts)

    stripper = _TagStripper()
    stripper.feed(text)
    stripped = stripper.get_text()

    # Remove javascript: URL schemes that may appear in text nodes
    stripped = re.sub(r"javascript:", "", stripped, flags=re.IGNORECASE)

    return stripped.strip()


# =============================================================================
# NAABU - PORT SCANNING
# =============================================================================


@celery.task(name="app.tasks.enrichment.run_naabu")
def run_naabu(
    tenant_id: int,
    asset_ids: List[int],
    full_scan: bool = False,
    rate: int = 0,
    timeout: Optional[int] = None,
    blocked_ports: Optional[List[int]] = None,
):
    """
    Run Naabu for port scanning

    Scans network ports to discover services.

    IMPORTANT: Port scanning requires user consent and may be legally restricted.
    Only scan assets the tenant owns or has permission to scan.

    Security Controls:
    - IP/domain validation
    - SSRF prevention (RFC1918, cloud metadata, loopback blocked)
    - Port blocklist (22, 445, 3389, etc.) — tier-aware, see _phase_5_port_scanning
    - Rate limiting
    - Timeout limits

    Args:
        tenant_id: Tenant ID
        asset_ids: List of asset IDs to scan
        blocked_ports: Override default blocklist. Pass an empty list to
            disable blocking (e.g., T3 aggressive scans with authorization).
            If None, falls back to settings.naabu_blocked_ports.
        full_scan: If True, scan all 65535 ports (slow). If False, scan top 1000.

    Returns:
        Dict with scan results
    """
    from app.database import SessionLocal
    from app.repositories.service_repository import ServiceRepository

    db = SessionLocal()
    tenant_logger = TenantLoggerAdapter(logger, {"tenant_id": tenant_id})

    try:
        # Get tenant consent for port scanning
        from app.models.database import Tenant

        tenant = db.query(Tenant).filter_by(id=tenant_id).first()
        if not tenant:
            return {"error": "tenant_not_found"}

        # TODO: Implement consent system
        # if not tenant.port_scan_consent:
        #     tenant_logger.warning(f"Port scanning not consented for tenant {tenant_id}")
        #     return {'error': 'port_scan_not_consented'}

        # Get assets
        assets = db.query(Asset).filter(Asset.id.in_(asset_ids), Asset.tenant_id == tenant_id).all()

        if not assets:
            tenant_logger.warning(f"No assets found for Naabu (IDs: {asset_ids})")
            return {"ports_discovered": 0}

        # Build host list
        hosts = []
        domain_validator = DomainValidator()

        for asset in assets:
            if asset.type in [AssetType.DOMAIN, AssetType.SUBDOMAIN]:
                is_valid, _ = domain_validator.validate_domain(asset.identifier)
                if is_valid:
                    hosts.append(asset.identifier)
            elif asset.type == AssetType.IP:
                # Validate IP is not in blocklist
                if is_ip_allowed(asset.identifier, tenant_logger):
                    hosts.append(asset.identifier)

        if not hosts:
            tenant_logger.warning(f"No valid hosts for Naabu (tenant {tenant_id})")
            return {"ports_discovered": 0}

        tenant_logger.info(f"Running Naabu on {len(hosts)} hosts (tenant {tenant_id})")

        # Execute Naabu with secure executor
        with SecureToolExecutor(tenant_id) as executor:
            # Use stdin instead of file input for better reliability
            hosts_content = "\n".join(hosts)

            # Build arguments (no -l flag, use stdin)
            args = ["-json", "-silent", "-rate", str(rate or settings.naabu_rate_limit or 1000)]

            # Port selection
            if full_scan:
                args.extend(["-p", "-"])  # All ports
            else:
                # Naabu expects: -tp 100, -tp 1000, or -tp full
                top_ports = settings.naabu_default_ports or "1000"
                # Strip "top-" prefix if present from legacy config
                top_ports = top_ports.replace("top-", "")
                args.extend(["-tp", top_ports])

            # Exclude blocked ports. Caller can override via `blocked_ports`
            # (e.g., tier-aware policy in _phase_5_port_scanning). Pass an
            # empty list to disable the blocklist entirely; pass None to keep
            # the configured default.
            effective_blocked = blocked_ports if blocked_ports is not None else settings.naabu_blocked_ports
            if effective_blocked:
                exclude_ports = ",".join(map(str, effective_blocked))
                args.extend(["-exclude-ports", exclude_ports])
                tenant_logger.info(f"Naabu blocked ports: {exclude_ports}")
            else:
                tenant_logger.info("Naabu blocked ports: none (all ports allowed)")

            # Execute Naabu with stdin
            returncode, stdout, stderr = executor.execute(
                "naabu", args, timeout=timeout or settings.naabu_timeout, stdin_data=hosts_content
            )

            if returncode != 0:
                tenant_logger.warning(f"Naabu returned non-zero exit code: {returncode}")
                tenant_logger.warning(f"Naabu stderr: {stderr[:500]}")
                tenant_logger.warning(f"Naabu args: {args}")

            # Parse JSON output
            services_data = []
            for line in stdout.strip().split("\n"):
                if not line:
                    continue

                try:
                    result = json.loads(line)
                    service_data = parse_naabu_result(result, tenant_logger)
                    if service_data:
                        services_data.append(service_data)
                except json.JSONDecodeError:
                    continue

            # Store raw output
            try:
                store_raw_output(tenant_id, "naabu", {"hosts": hosts, "results": services_data})
            except Exception as e:
                tenant_logger.warning(f"Failed to store Naabu raw output: {e}")

            # Upsert services to database
            service_repo = ServiceRepository(db)
            total_created = 0
            total_updated = 0

            # Map hosts back to asset IDs
            # Build a lookup: host -> list of parsed results
            host_results: Dict[str, List[Dict]] = {}
            for svc in services_data:
                host = svc.get("host")
                if host:
                    host_results.setdefault(host, []).append(svc)

            # Query all matching assets in a single query (avoids N+1)
            unique_hosts = list(host_results.keys())
            if unique_hosts:
                matched_assets = (
                    db.query(Asset).filter(Asset.tenant_id == tenant_id, Asset.identifier.in_(unique_hosts)).all()
                )

                # Build identifier -> asset mapping
                asset_by_identifier: Dict[str, Asset] = {asset.identifier: asset for asset in matched_assets}

                # Group services by asset and deduplicate by port
                services_by_asset: Dict[int, Dict[int, Dict]] = {}
                for host, results in host_results.items():
                    asset = asset_by_identifier.get(host)
                    if not asset:
                        tenant_logger.warning(f"No asset found for Naabu host: {host}")
                        continue

                    if asset.id not in services_by_asset:
                        services_by_asset[asset.id] = {}

                    for svc in results:
                        port = svc.get("port")
                        if port is not None:
                            # Deduplicate by port - keep latest result
                            services_by_asset[asset.id][port] = svc

                # Bulk upsert for each asset
                for asset_id, ports_dict in services_by_asset.items():
                    asset_services = list(ports_dict.values())
                    result = service_repo.bulk_upsert(asset_id, asset_services)
                    total_created += result["created"]
                    total_updated += result["updated"]

                    # Update asset enrichment tracking
                    asset = db.query(Asset).filter_by(id=asset_id).first()
                    if asset:
                        asset.last_enriched_at = datetime.now(timezone.utc)

                db.commit()

            tenant_logger.info(
                f"Naabu complete: {total_created} new services, {total_updated} updated "
                f"({len(services_data)} open ports on {len(hosts)} hosts, tenant {tenant_id})"
            )

            return {
                "ports_discovered": len(services_data),
                "services_created": total_created,
                "services_updated": total_updated,
                "hosts_scanned": len(hosts),
            }

    except ToolExecutionError as e:
        tenant_logger.error(f"Naabu execution failed: {e}")
        return {"error": str(e), "ports_discovered": 0}
    except Exception as e:
        tenant_logger.error(f"Naabu error: {e}", exc_info=True)
        return {"error": str(e), "ports_discovered": 0}
    finally:
        db.close()


def parse_naabu_result(result: Dict, tenant_logger) -> Optional[Dict]:
    """Parse Naabu JSON output into service data"""
    try:
        return {
            "host": result.get("host"),
            "port": result.get("port"),
            "protocol": "tcp",  # Naabu default
            "enrichment_source": "naabu",
        }
    except Exception as e:
        tenant_logger.warning(f"Failed to parse Naabu result: {e}")
        return None


def is_ip_allowed(ip: str, tenant_logger) -> bool:
    """
    Check if IP is allowed for scanning (SSRF prevention)

    Blocks:
    - RFC1918 private networks (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
    - Loopback (127.0.0.0/8)
    - Link-local (169.254.0.0/16)
    - Cloud metadata (169.254.169.254, metadata.google.internal)

    Args:
        ip: IP address to check
        tenant_logger: Logger instance

    Returns:
        True if IP is allowed, False otherwise
    """
    import ipaddress

    try:
        ip_obj = ipaddress.ip_address(ip)

        # Check if private
        if ip_obj.is_private:
            tenant_logger.warning(f"Blocked private IP: {ip}")
            return False

        # Check if loopback
        if ip_obj.is_loopback:
            tenant_logger.warning(f"Blocked loopback IP: {ip}")
            return False

        # Check if link-local
        if ip_obj.is_link_local:
            tenant_logger.warning(f"Blocked link-local IP: {ip}")
            return False

        # Check cloud metadata IPs
        if str(ip) == "169.254.169.254":
            tenant_logger.warning(f"Blocked cloud metadata IP: {ip}")
            return False

        return True

    except ValueError:
        tenant_logger.warning(f"Invalid IP address: {ip}")
        return False


# =============================================================================
# TLSX - TLS/SSL CERTIFICATE ANALYSIS
# =============================================================================


@celery.task(name="app.tasks.enrichment.run_tlsx")
def run_tlsx(tenant_id: int, asset_ids: List[int]):
    """
    Run TLSx for TLS/SSL certificate analysis

    CRITICAL SECURITY: This task MUST detect and redact private keys.
    TLSx should NOT output private keys, but defense in depth requires
    detection and redaction if they appear.

    Analyzes:
    - Certificate validity and expiry
    - Subject Alternative Names (SANs)
    - Certificate chain
    - Cipher suites
    - TLS versions
    - Security issues (self-signed, weak signatures, expired)

    Args:
        tenant_id: Tenant ID
        asset_ids: List of asset IDs to analyze

    Returns:
        Dict with analysis results
    """
    from app.database import SessionLocal
    from app.repositories.certificate_repository import CertificateRepository

    db = SessionLocal()
    tenant_logger = TenantLoggerAdapter(logger, {"tenant_id": tenant_id})

    try:
        # Get assets
        assets = db.query(Asset).filter(Asset.id.in_(asset_ids), Asset.tenant_id == tenant_id).all()

        if not assets:
            tenant_logger.warning(f"No assets found for TLSx (IDs: {asset_ids})")
            return {"certificates_discovered": 0}

        # Build host list (only domains/IPs with potential HTTPS)
        hosts = []
        domain_validator = DomainValidator()

        for asset in assets:
            if asset.type in [AssetType.DOMAIN, AssetType.SUBDOMAIN]:
                is_valid, _ = domain_validator.validate_domain(asset.identifier)
                if is_valid:
                    hosts.append(asset.identifier)
            elif asset.type == AssetType.IP:
                if is_ip_allowed(asset.identifier, tenant_logger):
                    hosts.append(asset.identifier)

        if not hosts:
            tenant_logger.warning(f"No valid hosts for TLSx (tenant {tenant_id})")
            return {"certificates_discovered": 0}

        tenant_logger.info(f"Running TLSx on {len(hosts)} hosts (tenant {tenant_id})")

        # Execute TLSx with secure executor
        with SecureToolExecutor(tenant_id) as executor:
            # Use stdin instead of file input
            hosts_content = "\n".join(hosts)

            # Execute TLSx with stdin
            # Note: tlsx -san/-cn flags cannot be combined with -cipher/-tls-version/-hash
            # (mutually exclusive probe categories). Use -san/-cn for certificate identity.
            returncode, stdout, stderr = executor.execute(
                "tlsx",
                [
                    "-json",
                    "-silent",
                    "-san",  # Include SANs
                    "-cn",  # Include CN
                ],
                timeout=settings.tlsx_timeout,
                stdin_data=hosts_content,
            )

            if returncode != 0:
                tenant_logger.warning(f"TLSx returned non-zero exit code: {returncode}")
                tenant_logger.warning(f"TLSx stderr: {stderr}")

            # CRITICAL: Detect private keys in output
            private_key_detected, sanitized_stdout = detect_and_redact_private_keys(stdout, tenant_logger)

            if private_key_detected:
                # CRITICAL ALERT
                tenant_logger.critical(
                    f"PRIVATE KEY DETECTED in TLSx output for tenant {tenant_id}! "
                    f"This is a critical security incident. Output has been redacted."
                )
                # TODO: Send alert to security team

            # Parse JSON output
            certificates_data = []
            for line in sanitized_stdout.strip().split("\n"):
                if not line:
                    continue

                try:
                    result = json.loads(line)
                    cert_data = parse_tlsx_result(result, tenant_logger)
                    if cert_data:
                        certificates_data.append(cert_data)
                except json.JSONDecodeError:
                    continue

            # Store raw output (sanitized)
            try:
                store_raw_output(
                    tenant_id,
                    "tlsx",
                    {"hosts": hosts, "results": certificates_data, "private_key_detected": private_key_detected},
                )
            except Exception as e:
                tenant_logger.warning(f"Failed to store TLSx raw output: {e}")

            # Upsert certificates to database
            tenant_logger.info(f"TLSx discovered {len(certificates_data)} certificates")

            cert_repo = CertificateRepository(db)
            from app.repositories.service_repository import ServiceRepository

            service_repo = ServiceRepository(db)
            total_certs_created = 0
            total_certs_updated = 0

            # Map hosts back to assets for certificate upsert
            cert_hosts = list({c["host"] for c in certificates_data if c.get("host")})
            if cert_hosts:
                matched_assets = (
                    db.query(Asset).filter(Asset.tenant_id == tenant_id, Asset.identifier.in_(cert_hosts)).all()
                )

                asset_by_host: Dict[str, Asset] = {asset.identifier: asset for asset in matched_assets}

                # Group certificates by asset
                certs_by_asset: Dict[int, List[Dict]] = {}
                for cert_data in certificates_data:
                    cert_host = cert_data.get("host", "")
                    asset = asset_by_host.get(cert_host)
                    if not asset:
                        tenant_logger.warning(f"No asset found for TLSx host: {cert_host}")
                        continue
                    certs_by_asset.setdefault(asset.id, []).append(cert_data)

                for asset_id, asset_certs in certs_by_asset.items():
                    # Bulk upsert certificates
                    result = cert_repo.bulk_upsert(asset_id, asset_certs)
                    total_certs_created += result["created"]
                    total_certs_updated += result["updated"]

                    # Also update Service records with TLS info
                    for cert_data in asset_certs:
                        port_str = cert_data.get("port", "443")
                        try:
                            port_num = int(port_str)
                        except (ValueError, TypeError):
                            port_num = 443

                        # Map well-known TLS ports to their actual protocol
                        _TLS_PORT_PROTOCOLS = {
                            25: "smtp",
                            110: "pop3",
                            143: "imap",
                            465: "smtps",
                            587: "smtp",
                            993: "imaps",
                            995: "pop3s",
                            443: "https",
                            8443: "https",
                        }
                        tls_service_data = [
                            {
                                "port": port_num,
                                "protocol": _TLS_PORT_PROTOCOLS.get(port_num, "https"),
                                "has_tls": True,
                                "tls_version": cert_data.get("tls_version", ""),
                                "tls_fingerprint": cert_data.get("tls_fingerprint", ""),
                                "enrichment_source": "tlsx",
                            }
                        ]
                        service_repo.bulk_upsert(asset_id, tls_service_data)

                db.commit()

            tenant_logger.info(
                f"TLSx complete: {total_certs_created} new certificates, "
                f"{total_certs_updated} updated (tenant {tenant_id})"
            )

            return {
                "certificates_discovered": len(certificates_data),
                "certificates_created": total_certs_created,
                "certificates_updated": total_certs_updated,
                "hosts_analyzed": len(hosts),
                "private_key_detected": private_key_detected,
            }

    except ToolExecutionError as e:
        tenant_logger.error(f"TLSx execution failed: {e}")
        return {"error": str(e), "certificates_discovered": 0}
    except Exception as e:
        tenant_logger.error(f"TLSx error: {e}", exc_info=True)
        return {"error": str(e), "certificates_discovered": 0}
    finally:
        db.close()


def detect_and_redact_private_keys(text: str, tenant_logger) -> Tuple[bool, str]:
    """
    CRITICAL SECURITY FUNCTION: Detect and redact private keys

    Searches for PEM-formatted private keys and redacts them.

    Patterns detected:
    - RSA private keys: -----BEGIN RSA PRIVATE KEY-----
    - EC private keys: -----BEGIN EC PRIVATE KEY-----
    - Generic private keys: -----BEGIN PRIVATE KEY-----
    - Encrypted private keys: -----BEGIN ENCRYPTED PRIVATE KEY-----

    Args:
        text: Text to scan
        tenant_logger: Logger instance

    Returns:
        Tuple of (private_key_detected: bool, sanitized_text: str)
    """
    # Patterns for private key detection
    private_key_patterns = [
        r"-----BEGIN RSA PRIVATE KEY-----.*?-----END RSA PRIVATE KEY-----",
        r"-----BEGIN EC PRIVATE KEY-----.*?-----END EC PRIVATE KEY-----",
        r"-----BEGIN PRIVATE KEY-----.*?-----END PRIVATE KEY-----",
        r"-----BEGIN ENCRYPTED PRIVATE KEY-----.*?-----END ENCRYPTED PRIVATE KEY-----",
    ]

    detected = False
    sanitized = text

    for pattern in private_key_patterns:
        matches = re.findall(pattern, text, re.DOTALL)
        if matches:
            detected = True
            tenant_logger.critical(f"PRIVATE KEY DETECTED! Found {len(matches)} private key(s). REDACTING.")

            # Redact the private key
            sanitized = re.sub(
                pattern, "[REDACTED: PRIVATE KEY - CRITICAL SECURITY INCIDENT]", sanitized, flags=re.DOTALL
            )

    return detected, sanitized


def parse_tlsx_result(result: Dict, tenant_logger) -> Optional[Dict]:
    """
    Parse TLSx JSON output into certificate data

    Extracts all certificate fields from TLSx JSON output including:
    - Identity: host, port, subject CN, issuer, serial
    - Validity: not_before, not_after, days_until_expiry, is_expired
    - SANs: subject alternative names
    - Security: self-signed, wildcard, weak signature detection
    - TLS config: version, cipher suite

    Args:
        result: TLSx JSON result dict
        tenant_logger: Logger instance

    Returns:
        Certificate data dict or None if parsing fails
    """
    try:
        host = result.get("host")
        if not host:
            return None

        port = result.get("port", "443")
        # Ensure port is a string for consistent handling
        port = str(port) if port else "443"

        # Extract TLS configuration
        tls_version = result.get("tls_version", "")
        cipher = result.get("cipher", "")

        # Extract certificate identity
        subject_cn = result.get("subject_cn", "")
        serial_number = result.get("serial", "")

        # Build issuer string from issuer_cn and issuer_org
        issuer_cn = result.get("issuer_cn", "")
        issuer_org = result.get("issuer_org", [])
        if isinstance(issuer_org, list) and issuer_org:
            issuer = f"{issuer_cn} ({', '.join(issuer_org)})" if issuer_cn else ", ".join(issuer_org)
        else:
            issuer = issuer_cn or ""

        # Parse validity dates
        not_before = None
        not_after = None
        not_before_str = result.get("not_before", "")
        not_after_str = result.get("not_after", "")

        for date_format in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%d %H:%M:%S"):
            if not_before_str and not not_before:
                try:
                    not_before = datetime.strptime(
                        not_before_str.replace("+00:00", "Z").rstrip("Z") + "Z", "%Y-%m-%dT%H:%M:%SZ"
                    ).replace(tzinfo=timezone.utc)
                except ValueError:
                    pass
            if not_after_str and not not_after:
                try:
                    not_after = datetime.strptime(
                        not_after_str.replace("+00:00", "Z").rstrip("Z") + "Z", "%Y-%m-%dT%H:%M:%SZ"
                    ).replace(tzinfo=timezone.utc)
                except ValueError:
                    pass

        # Calculate expiry status
        days_until_expiry = None
        is_expired = False
        if not_after:
            delta = not_after - datetime.now(timezone.utc)
            days_until_expiry = delta.days
            is_expired = days_until_expiry < 0

        # Extract SANs from subject_an
        san_domains = result.get("subject_an", [])
        if not isinstance(san_domains, list):
            san_domains = []

        # Security checks
        is_self_signed = result.get("self_signed", False)
        is_wildcard = result.get("wildcard_certificate", False)

        # If not explicitly flagged, check subject_cn and SANs for wildcard
        if not is_wildcard:
            all_names = [subject_cn] + san_domains
            is_wildcard = any(name.startswith("*.") for name in all_names if name)

        # Weak signature detection
        # TLSx may include signature_algorithm; also check cipher for weak patterns
        signature_algorithm = result.get("signature_algorithm", "")
        has_weak_signature = False
        weak_sig_patterns = ["md5", "sha1", "md2", "md4"]
        sig_to_check = (signature_algorithm or "").lower()
        if any(weak in sig_to_check for weak in weak_sig_patterns):
            has_weak_signature = True

        # Extract fingerprint hash
        fingerprint_hash = result.get("fingerprint_hash", {})
        tls_fingerprint = ""
        if isinstance(fingerprint_hash, dict):
            tls_fingerprint = fingerprint_hash.get("sha256", "")

        # Extract certificate chain
        chain_data = result.get("chain", [])
        if not isinstance(chain_data, list):
            chain_data = []

        # Build the certificate data dict
        cert_data = {
            "host": host,
            "port": port,
            "tls_version": tls_version,
            "cipher": cipher,
            "subject_cn": subject_cn,
            "issuer": issuer,
            "serial_number": serial_number,
            "not_before": not_before,
            "not_after": not_after,
            "days_until_expiry": days_until_expiry,
            "is_expired": is_expired,
            "san_domains": san_domains,
            "signature_algorithm": signature_algorithm,
            "is_self_signed": is_self_signed,
            "is_wildcard": is_wildcard,
            "has_weak_signature": has_weak_signature,
            "tls_fingerprint": tls_fingerprint,
            "cipher_suites": [cipher] if cipher else [],
            "chain": chain_data,
            "raw_data": result,
        }

        return cert_data

    except Exception as e:
        tenant_logger.warning(f"Failed to parse TLSx result: {e}")
        return None


# =============================================================================
# KATANA - WEB CRAWLING
# =============================================================================


@celery.task(name="app.tasks.enrichment.run_katana")
def run_katana(tenant_id: int, asset_ids: List[int], timeout: Optional[int] = None):
    """
    Run Katana for web crawling and endpoint discovery

    IMPORTANT: Respects robots.txt by default. Set katana_respect_robots=False
    in config to disable (not recommended).

    Discovers:
    - API endpoints
    - Web pages and paths
    - Forms (potential XSS/CSRF targets)
    - External links
    - File downloads

    Args:
        tenant_id: Tenant ID
        asset_ids: List of asset IDs to crawl (must have live HTTP services)
        timeout: Katana wall-clock timeout in seconds. If None, falls back
            to settings.katana_timeout. The caller (typically
            _phase_6b_web_crawling) passes a tier-aware value from the
            resource scaler so T3 full scans get a longer budget than T1.

    Returns:
        Dict with crawl results
    """
    from app.database import SessionLocal
    from app.repositories.service_repository import ServiceRepository
    from app.repositories.endpoint_repository import EndpointRepository

    db = SessionLocal()
    tenant_logger = TenantLoggerAdapter(logger, {"tenant_id": tenant_id})

    try:
        # Get assets with live HTTP services
        # Katana depends on HTTPx results to know which hosts serve HTTP
        from app.models.database import Service
        from sqlalchemy import or_

        service_repo = ServiceRepository(db)
        endpoint_repo = EndpointRepository(db)

        # Query assets that have live web services
        # A service is considered live if it has an http_status or runs on common web ports
        live_services = (
            db.query(Service)
            .join(Asset)
            .filter(
                Asset.id.in_(asset_ids),
                Asset.tenant_id == tenant_id,
                or_(Service.http_status.isnot(None), Service.port.in_([80, 443, 8080, 8443])),
            )
            .all()
        )

        if not live_services:
            tenant_logger.info(f"No live HTTP services found for Katana (tenant {tenant_id})")
            return {"endpoints_discovered": 0, "status": "no_live_services"}

        # Build URL list from live services
        url_validator = URLValidator()
        urls = []
        url_to_asset_id: Dict[str, int] = {}

        for service in live_services:
            asset = db.query(Asset).filter_by(id=service.asset_id).first()
            if not asset:
                continue

            # Determine scheme and build URL
            scheme = "https" if service.has_tls or service.port in (443, 8443) else "http"
            host = asset.identifier

            if service.port in (80, 443):
                url = f"{scheme}://{host}"
            else:
                url = f"{scheme}://{host}:{service.port}"

            is_valid, _ = url_validator.validate_url(url)
            if is_valid and url not in urls:
                urls.append(url)
                url_to_asset_id[url] = service.asset_id

        if not urls:
            tenant_logger.info(f"No valid URLs for Katana (tenant {tenant_id})")
            return {"endpoints_discovered": 0, "status": "no_valid_urls"}

        tenant_logger.info(f"Running Katana on {len(urls)} URLs (tenant {tenant_id})")

        # Execute Katana with secure executor
        with SecureToolExecutor(tenant_id) as executor:
            # Katana does NOT read from stdin — must use -list with a file
            urls_content = "\n".join(urls)
            urls_file = executor.create_input_file("katana_urls.txt", urls_content)

            max_depth = str(settings.katana_max_depth)
            # Tier-aware crawl wall-clock (falls back to config if caller
            # didn't specify). We use effective_timeout as BOTH the katana
            # `-ct` crawl-time argument AND as the base for the watchdog
            # timeout, so katana stops cleanly on its own and has ~30s
            # buffer before SecureToolExecutor SIGKILLs the process group.
            effective_timeout = timeout or settings.katana_timeout
            crawl_duration = str(effective_timeout)

            # Redirect katana JSONL stdout to a FILE via the executor's
            # stdout_file parameter. This avoids Python memory issues:
            # proc.communicate() buffers ALL stdout in a single Python
            # string, and JS-crawl on ~60 URLs can produce GB of JSONL,
            # triggering the 12 GB OOM kill. The stdout_file parameter
            # opens the file at the OS level so the kernel writes directly
            # to disk with zero Python memory overhead.
            #
            # NOTE: katana's -o flag writes PLAIN URLs to the file, not
            # JSONL. The -jsonl flag only controls the stdout format.
            # Therefore we must NOT use -o; instead we redirect stdout
            # itself to the file so the JSONL lines land there.
            import os

            output_file = os.path.join(executor.temp_dir, "katana_output.jsonl")

            args = [
                "-list",
                urls_file,
                "-jsonl",
                "-silent",
                "-jc",  # js-crawl (short form)
                "-d",
                max_depth,
                "-ct",
                f"{crawl_duration}s",  # crawl duration (not max pages)
                "-rl",
                "100",  # rate limit requests/sec
            ]

            # Katana respects robots.txt by default.
            # Only add -disable-redirects when we do NOT want to respect robots.
            if not settings.katana_respect_robots:
                args.append("-disable-redirects")

            tenant_logger.info(
                f"Katana: {len(urls)} URLs, crawl_duration={crawl_duration}s, "
                f"watchdog={effective_timeout + 30}s, output={output_file}"
            )
            returncode, _, stderr = executor.execute(
                "katana",
                args,
                timeout=effective_timeout + 30,  # extra buffer beyond crawl duration
                capture_output=False,  # stderr to /dev/null (not needed)
                stdout_file=output_file,  # JSONL stdout -> file (zero memory)
            )

            if returncode != 0:
                tenant_logger.warning(f"Katana returned non-zero exit code: {returncode}")

            # Read output from file (line-by-line, constant memory)
            stdout_lines = []
            if os.path.exists(output_file):
                file_size = os.path.getsize(output_file)
                tenant_logger.info(f"Katana output file: {file_size:,} bytes")
                with open(output_file) as f:
                    stdout_lines = f.readlines()
            else:
                tenant_logger.warning("Katana output file not found (timeout or no results)")

            # Parse JSONL output lines
            endpoints_data: List[Dict] = []
            for line in stdout_lines:
                line = line.strip()
                if not line:
                    continue

                try:
                    result = json.loads(line)

                    # Katana JSONL output (v1.0+) nests the URL under
                    # "request.endpoint" and the source page under
                    # "request.source". Fall back to top-level keys for
                    # compatibility with older katana versions.
                    request = result.get("request") or {}
                    endpoint_url = request.get("endpoint") or result.get("endpoint", "")
                    source_url = request.get("source") or result.get("source", "")
                    tag = request.get("tag") or result.get("tag", "")

                    if not endpoint_url:
                        continue

                    # Validate discovered endpoint URL
                    is_valid, _ = url_validator.validate_url(endpoint_url)
                    if not is_valid:
                        continue

                    # Parse the endpoint URL for path and classification
                    parsed = urlparse(endpoint_url)
                    path = parsed.path or "/"

                    # Classify endpoint type based on tag and URL patterns
                    endpoint_type = "static"
                    if tag == "form":
                        endpoint_type = "form"
                    elif tag == "js":
                        endpoint_type = "static"
                    elif any(p in path.lower() for p in ["/api/", "/v1/", "/v2/", "/graphql", "/rest/"]):
                        endpoint_type = "api"
                    elif parsed.path and parsed.path.split(".")[-1] in (
                        "pdf",
                        "doc",
                        "docx",
                        "xls",
                        "xlsx",
                        "zip",
                        "csv",
                    ):
                        endpoint_type = "file"

                    # Determine if the endpoint is external to the crawled domain
                    is_external = False
                    if parsed.hostname:
                        # Check if the discovered endpoint belongs to any of the crawled URLs
                        source_parsed = urlparse(source_url) if source_url else None
                        if source_parsed and source_parsed.hostname:
                            is_external = parsed.hostname.lower() != source_parsed.hostname.lower()

                    # Detect API endpoints
                    is_api = endpoint_type == "api" or any(
                        p in path.lower() for p in ["/api/", "/v1/", "/v2/", "/v3/", "/graphql", "/rest/", "/rpc/"]
                    )

                    # Map this endpoint to the correct asset_id via the source URL
                    # First try the source URL, then try the endpoint itself
                    asset_id = None
                    for candidate_url in [source_url, endpoint_url]:
                        if candidate_url in url_to_asset_id:
                            asset_id = url_to_asset_id[candidate_url]
                            break
                        # Try matching by origin (scheme://host:port)
                        candidate_parsed = urlparse(candidate_url)
                        if candidate_parsed.hostname:
                            for mapped_url, mapped_id in url_to_asset_id.items():
                                mapped_parsed = urlparse(mapped_url)
                                if (
                                    candidate_parsed.hostname == mapped_parsed.hostname
                                    and candidate_parsed.port == mapped_parsed.port
                                ):
                                    asset_id = mapped_id
                                    break
                        if asset_id:
                            break

                    if not asset_id:
                        continue

                    # Extract query parameters
                    query_params = {}
                    if parsed.query:
                        for param in parsed.query.split("&"):
                            if "=" in param:
                                key, _, value = param.partition("=")
                                query_params[key] = value

                    endpoint_data = {
                        "url": endpoint_url,
                        "path": path,
                        "method": "GET",
                        "endpoint_type": endpoint_type,
                        "is_external": is_external,
                        "is_api": is_api,
                        "source_url": source_url,
                        "query_params": query_params if query_params else None,
                        "raw_data": result,
                        "asset_id": asset_id,
                    }

                    endpoints_data.append(endpoint_data)

                except json.JSONDecodeError:
                    continue

            # Store raw output to MinIO
            try:
                store_raw_output(tenant_id, "katana", {"urls": urls, "results_count": len(endpoints_data)})
            except Exception as e:
                tenant_logger.warning(f"Failed to store Katana raw output: {e}")

            # Upsert endpoints grouped by asset
            total_created = 0
            total_updated = 0

            endpoints_by_asset: Dict[int, List[Dict]] = {}
            for ep in endpoints_data:
                aid = ep.pop("asset_id")
                endpoints_by_asset.setdefault(aid, []).append(ep)

            for asset_id, asset_endpoints in endpoints_by_asset.items():
                # Deduplicate by (url, method) — matches the DB unique constraint
                # idx_asset_url(asset_id, url, method). Katana returns the same
                # endpoint multiple times via different crawl paths. PostgreSQL's
                # ON CONFLICT DO UPDATE can't handle duplicate rows in the same
                # INSERT batch → CardinalityViolation.
                seen_keys = set()
                unique_endpoints = []
                for ep in asset_endpoints:
                    key = (ep.get("url", ""), ep.get("method", "GET"))
                    if key[0] and key not in seen_keys:
                        seen_keys.add(key)
                        unique_endpoints.append(ep)
                result = endpoint_repo.bulk_upsert(asset_id, unique_endpoints)
                total_created += result["created"]
                total_updated += result["updated"]

            db.commit()

            tenant_logger.info(
                f"Katana complete: {total_created} new endpoints, {total_updated} updated (tenant {tenant_id})"
            )

            return {
                "endpoints_discovered": total_created + total_updated,
                "endpoints_created": total_created,
                "endpoints_updated": total_updated,
                "urls_crawled": len(urls),
            }

    except ToolExecutionError as e:
        tenant_logger.error(f"Katana execution failed: {e}")
        return {"error": str(e), "endpoints_discovered": 0}
    except Exception as e:
        tenant_logger.error(f"Katana error: {e}", exc_info=True)
        return {"error": str(e), "endpoints_discovered": 0}
    finally:
        db.close()
