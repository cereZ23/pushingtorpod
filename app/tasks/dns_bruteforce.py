"""
DNS Permutation & Bruteforce tasks using alterx + puredns.

Phase 2 of the scan pipeline:
- alterx: generates permutations of discovered subdomains
- puredns: resolves and validates candidates with wildcard filtering

Both tools require Tier 2+ scan profile.
"""

import logging
import shutil
from pathlib import Path
from typing import Optional

from app.config import settings
from app.utils.secure_executor import SecureToolExecutor, ToolExecutionError
from app.utils.storage import store_raw_output
from app.utils.validators import DomainValidator

logger = logging.getLogger(__name__)


def run_alterx(domains: list[str], tenant_id: int) -> list[str]:
    """Generate permutations of discovered subdomains using alterx.

    Args:
        domains: List of known subdomains to permute.
        tenant_id: Tenant ID for isolation.

    Returns:
        List of permutation candidate hostnames.
    """
    if not domains:
        logger.info("No domains to permute for tenant %d", tenant_id)
        return []

    validator = DomainValidator()
    validated = [d.strip().lower() for d in domains if validator.validate_domain(d)[0]]

    if not validated:
        logger.warning("No valid domains after validation for alterx (tenant %d)", tenant_id)
        return []

    try:
        with SecureToolExecutor(tenant_id) as executor:
            input_content = "\n".join(validated)
            input_file = executor.create_input_file("subdomains.txt", input_content)
            output_file = "permutations.txt"

            logger.info(
                "Running alterx for %d subdomains (tenant %d)",
                len(validated),
                tenant_id,
            )

            returncode, stdout, stderr = executor.execute(
                "alterx",
                ["-l", input_file, "-silent", "-o", output_file],
                timeout=settings.alterx_timeout,
            )

            if returncode != 0:
                logger.warning("alterx warning (tenant %d): %s", tenant_id, stderr)

            output_content = executor.read_output_file(output_file)
            candidates = [line.strip() for line in output_content.split("\n") if line.strip()]

            # Cap candidates to avoid spending excessive time in puredns.
            # 268k candidates at 300/s = ~15 min just for DNS queries;
            # 50k keeps it under 3 min with high coverage.
            MAX_CANDIDATES = 50000
            if len(candidates) > MAX_CANDIDATES:
                logger.info(
                    "alterx generated %d candidates, capping to %d (tenant %d)",
                    len(candidates),
                    MAX_CANDIDATES,
                    tenant_id,
                )
                candidates = candidates[:MAX_CANDIDATES]

            logger.info(
                "alterx generated %d permutation candidates (tenant %d)",
                len(candidates),
                tenant_id,
            )

            try:
                store_raw_output(
                    tenant_id,
                    "alterx",
                    {
                        "input_count": len(validated),
                        "candidates_count": len(candidates),
                    },
                )
            except Exception as exc:
                logger.warning("Failed to store alterx raw output (tenant %d): %s", tenant_id, exc)

            return candidates

    except ToolExecutionError as exc:
        logger.error("alterx execution failed (tenant %d): %s", tenant_id, exc)
        return []


def run_puredns(
    candidates: list[str],
    tenant_id: int,
    rate: int = 50,
    wordlist_path: Optional[str] = None,
) -> list[str]:
    """Resolve and validate subdomain candidates with wildcard filtering.

    Uses puredns to mass-resolve candidate hostnames, automatically
    filtering out wildcard DNS responses.

    Args:
        candidates: Hostnames to validate (from alterx or wordlist).
        tenant_id: Tenant ID for isolation.
        rate: DNS queries per second.
        wordlist_path: Optional path to wordlist for bruteforce mode.

    Returns:
        List of validated, resolvable subdomains.
    """
    if not candidates:
        logger.info("No candidates to resolve for tenant %d", tenant_id)
        return []

    resolvers_path = settings.puredns_resolvers_path

    try:
        with SecureToolExecutor(tenant_id) as executor:
            input_content = "\n".join(candidates)
            input_file = executor.create_input_file("candidates.txt", input_content)
            output_file = "resolved.txt"

            # Copy resolvers file into temp dir so SecureToolExecutor allows access
            local_resolvers = "resolvers.txt"
            src_resolvers = Path(resolvers_path)
            if src_resolvers.is_file():
                dst_resolvers = Path(executor.temp_dir) / local_resolvers
                shutil.copy2(str(src_resolvers), str(dst_resolvers))
            else:
                logger.warning(
                    "Resolvers file not found at %s, puredns will use defaults (tenant %d)",
                    resolvers_path,
                    tenant_id,
                )
                local_resolvers = None

            logger.info(
                "Running puredns resolve for %d candidates (tenant %d, rate=%d)",
                len(candidates),
                tenant_id,
                rate,
            )

            args = [
                "resolve",
                input_file,
                "--rate-limit",
                str(rate),
                "-q",
                "-w",
                output_file,
            ]
            if local_resolvers:
                args.extend(["-r", local_resolvers])

            returncode, stdout, stderr = executor.execute(
                "puredns",
                args,
                timeout=settings.puredns_timeout,
            )

            if returncode != 0:
                logger.warning("puredns warning (tenant %d): %s", tenant_id, stderr)

            output_content = executor.read_output_file(output_file)
            resolved = [line.strip() for line in output_content.split("\n") if line.strip()]

            logger.info(
                "puredns validated %d / %d candidates (tenant %d)",
                len(resolved),
                len(candidates),
                tenant_id,
            )

            try:
                store_raw_output(
                    tenant_id,
                    "puredns",
                    {
                        "input_count": len(candidates),
                        "resolved_count": len(resolved),
                        "rate": rate,
                    },
                )
            except Exception as exc:
                logger.warning("Failed to store puredns raw output (tenant %d): %s", tenant_id, exc)

            return resolved

    except ToolExecutionError as exc:
        logger.error("puredns execution failed (tenant %d): %s", tenant_id, exc)
        return []
