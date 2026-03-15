"""
CDN/WAF Detection and Service Fingerprinting tasks.

Phase 5b: cdncheck — detects CDN, WAF, and cloud providers (all tiers)
Phase 5c: fingerprintx — precise service fingerprinting on open ports (Tier 2+)
"""

import json
import logging

from app.config import settings
from app.utils.secure_executor import SecureToolExecutor, ToolExecutionError
from app.utils.storage import store_raw_output

logger = logging.getLogger(__name__)


def run_cdncheck(hosts: list[str], tenant_id: int) -> dict[str, dict]:
    """Check if hosts are behind CDN/WAF/cloud providers.

    Uses cdncheck to identify CDN, WAF, and cloud provider fronting
    via DNS-based lookups. This is a read-only, non-intrusive check
    safe for all tiers.

    Args:
        hosts: List of IPs or hostnames to check.
        tenant_id: Tenant ID for isolation.

    Returns:
        Dict mapping host -> {cdn: bool, cdn_name: str, waf: bool,
        waf_name: str, cloud: str}.
    """
    if not hosts:
        logger.info("No hosts to check for CDN/WAF (tenant %d)", tenant_id)
        return {}

    try:
        with SecureToolExecutor(tenant_id) as executor:
            input_content = "\n".join(hosts)
            input_file = executor.create_input_file("hosts.txt", input_content)
            output_file = "cdncheck_output.json"

            logger.info(
                "Running cdncheck for %d hosts (tenant %d)",
                len(hosts),
                tenant_id,
            )

            returncode, stdout, stderr = executor.execute(
                "cdncheck",
                ["-i", input_file, "-jsonl", "-resp", "-o", output_file],
                timeout=settings.cdncheck_timeout,
            )

            if returncode != 0:
                logger.warning("cdncheck warning (tenant %d): %s", tenant_id, stderr)

            output_content = executor.read_output_file(output_file)
            results: dict[str, dict] = {}

            for line in output_content.split("\n"):
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                    host = entry.get("input", entry.get("host", ""))
                    if not host:
                        continue

                    results[host] = {
                        "cdn": entry.get("cdn", False),
                        "cdn_name": entry.get("cdn_name", ""),
                        "waf": entry.get("waf", False),
                        "waf_name": entry.get("waf_name", ""),
                        "cloud": entry.get("cloud", ""),
                    }
                except json.JSONDecodeError:
                    continue

            logger.info(
                "cdncheck: %d/%d hosts checked, %d CDN, %d WAF detected (tenant %d)",
                len(results),
                len(hosts),
                sum(1 for r in results.values() if r["cdn"]),
                sum(1 for r in results.values() if r["waf"]),
                tenant_id,
            )

            try:
                store_raw_output(
                    tenant_id,
                    "cdncheck",
                    {
                        "hosts_checked": len(results),
                        "cdn_detected": sum(1 for r in results.values() if r["cdn"]),
                        "waf_detected": sum(1 for r in results.values() if r["waf"]),
                    },
                )
            except Exception as exc:
                logger.warning("Failed to store cdncheck raw output (tenant %d): %s", tenant_id, exc)

            return results

    except ToolExecutionError as exc:
        logger.error("cdncheck execution failed (tenant %d): %s", tenant_id, exc)
        return {}


def run_fingerprintx(targets: list[str], tenant_id: int) -> list[dict]:
    """Fingerprint services on open ports with protocol-level detection.

    Uses fingerprintx to perform active service fingerprinting on
    host:port targets discovered by naabu. Provides more accurate
    service identification than port-based heuristics.

    Args:
        targets: List of 'host:port' strings from naabu results.
        tenant_id: Tenant ID for isolation.

    Returns:
        List of dicts with keys: host, port, protocol, service,
        version, tls, metadata.
    """
    if not targets:
        logger.info("No targets to fingerprint (tenant %d)", tenant_id)
        return []

    BATCH_SIZE = 200
    all_results: list[dict] = []

    logger.info(
        "Running fingerprintx for %d targets in batches of %d (tenant %d)",
        len(targets),
        BATCH_SIZE,
        tenant_id,
    )

    for batch_idx in range(0, len(targets), BATCH_SIZE):
        batch = targets[batch_idx : batch_idx + BATCH_SIZE]
        batch_num = batch_idx // BATCH_SIZE + 1
        total_batches = (len(targets) + BATCH_SIZE - 1) // BATCH_SIZE

        try:
            with SecureToolExecutor(tenant_id) as executor:
                input_content = "\n".join(batch)
                input_file = executor.create_input_file("targets.txt", input_content)
                output_file = "fingerprintx_output.json"

                logger.info(
                    "fingerprintx batch %d/%d: %d targets (tenant %d)",
                    batch_num,
                    total_batches,
                    len(batch),
                    tenant_id,
                )

                returncode, stdout, stderr = executor.execute(
                    "fingerprintx",
                    ["-l", input_file, "--json", "--fast", "-w", "750", "-o", output_file],
                    timeout=settings.fingerprintx_timeout,
                )

                if returncode != 0:
                    logger.warning("fingerprintx warning batch %d (tenant %d): %s", batch_num, tenant_id, stderr)

                output_content = executor.read_output_file(output_file)

                for line in output_content.split("\n"):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                        all_results.append(
                            {
                                "host": entry.get("host", entry.get("ip", "")),
                                "port": entry.get("port", 0),
                                "protocol": entry.get("protocol", ""),
                                "service": entry.get("service", ""),
                                "version": entry.get("version", ""),
                                "tls": entry.get("tls", False),
                                "metadata": entry.get("metadata", {}),
                            }
                        )
                    except json.JSONDecodeError:
                        continue

        except ToolExecutionError as exc:
            logger.error("fingerprintx batch %d failed (tenant %d): %s", batch_num, tenant_id, exc)
            continue

    logger.info(
        "fingerprintx identified %d services from %d targets (tenant %d)",
        len(all_results),
        len(targets),
        tenant_id,
    )

    try:
        store_raw_output(
            tenant_id,
            "fingerprintx",
            {
                "targets_scanned": len(targets),
                "services_identified": len(all_results),
            },
        )
    except Exception as exc:
        logger.warning("Failed to store fingerprintx raw output (tenant %d): %s", tenant_id, exc)

    return all_results
