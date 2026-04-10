"""
CPU/RAM-aware resource scaler for scan tool configuration.

Detects available system resources and computes optimal concurrency,
rate limits, and timeouts for each scan tool. Replaces hardcoded
values that were too conservative for capable servers.

Usage:
    from app.services.resource_scaler import get_scan_params
    params = get_scan_params(scan_tier=1)
    # params.naabu_rate, params.nuclei_concurrency, etc.
"""

import logging
import os
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class ScanParams:
    """Computed scan parameters based on system resources and tier."""

    # Naabu (port scan)
    naabu_rate: int
    naabu_timeout: int

    # Nuclei (vuln scan)
    nuclei_concurrency: int
    nuclei_rate_limit: int
    nuclei_timeout: int

    # HTTPx (HTTP probe)
    httpx_timeout: int

    # Fingerprintx (service ID)
    fingerprintx_timeout: int

    # Katana (crawl)
    katana_timeout: int

    # Sensitive paths
    sensitive_paths_limit: int

    # System info (for logging)
    cpu_count: int
    ram_gb: float


def _detect_resources() -> tuple[int, float]:
    """Detect available CPU cores and RAM in GB."""
    cpu = os.cpu_count() or 2
    try:
        with open("/proc/meminfo") as f:
            for line in f:
                if line.startswith("MemAvailable:"):
                    ram_kb = int(line.split()[1])
                    return cpu, ram_kb / (1024 * 1024)
    except (FileNotFoundError, ValueError):
        pass

    # Fallback: use total memory via os
    try:
        import psutil

        return cpu, psutil.virtual_memory().available / (1024**3)
    except ImportError:
        pass

    # Conservative fallback
    return cpu, 4.0


def get_scan_params(scan_tier: int = 1) -> ScanParams:
    """Compute optimal scan parameters based on CPU, RAM, and tier.

    Scaling philosophy:
    - More CPU → higher concurrency & rate limits
    - More RAM → higher concurrency (each tool instance uses ~100-300MB)
    - Higher tier → more aggressive settings within resource bounds

    Base assumptions (2 CPU, 4GB RAM):
        naabu_rate=200, nuclei_concurrency=15, nuclei_rate=100

    Each additional CPU core adds ~50% to rates.
    Each additional GB of RAM allows ~5 more concurrent tasks.
    """
    cpu, ram_gb = _detect_resources()

    # CPU multiplier: 2 cores = 1.0x, 4 cores = 2.0x, 8 cores = 3.0x
    cpu_mult = max(1.0, cpu / 2.0)

    # RAM multiplier: 4GB = 1.0x, 8GB = 1.5x, 16GB = 2.0x
    ram_mult = max(1.0, min(3.0, ram_gb / 4.0))

    # Combined resource factor (geometric mean biased toward CPU)
    resource_factor = cpu_mult * 0.7 + ram_mult * 0.3

    # Tier multiplier: higher tier = more aggressive
    tier_mult = {1: 1.0, 2: 1.5, 3: 2.0}.get(scan_tier, 1.0)

    combined = resource_factor * tier_mult

    params = ScanParams(
        # Naabu: base rate scales with CPU and tier. Tier 3 uses a higher base
        # rate (1000 vs 200) because it must cover all 65535 ports per target,
        # otherwise a full-port scan of a large tenant never finishes in time.
        naabu_rate=int(min((1000 if scan_tier == 3 else 200) * cpu_mult * tier_mult, 10000)),
        # Timeouts per tier:
        #   T1 (top-100)  →  5 min (small hostnames list, ~15k probes)
        #   T2 (top-1000) → 15 min (~150k probes)
        #   T3 (full)     → 2.5 h  (up to ~10M probes; kept below pipeline group
        #                           timeout & celery task time_limit)
        naabu_timeout={1: 300, 2: 900, 3: 9000}.get(scan_tier, 900),
        # Nuclei: base 15 concurrent, scale with both CPU and RAM
        nuclei_concurrency=int(min(15 * combined, 100)),
        nuclei_rate_limit=int(min(100 * combined, 1000)),
        nuclei_timeout={1: 300, 2: 600, 3: 1200}.get(scan_tier, 600),
        # HTTPx: timeout based on tier (not resource-dependent)
        httpx_timeout={1: 300, 2: 600, 3: 600}.get(scan_tier, 600),
        # Fingerprintx: fixed short timeout — it's fast per target
        fingerprintx_timeout={1: 60, 2: 120, 3: 300}.get(scan_tier, 120),
        # Katana: crawl depth/time based on tier
        katana_timeout={1: 120, 2: 300, 3: 300}.get(scan_tier, 300),
        # Sensitive paths: limit count for Tier 1
        sensitive_paths_limit={1: 50, 2: 0, 3: 0}.get(scan_tier, 0),  # 0 = no limit
        cpu_count=cpu,
        ram_gb=round(ram_gb, 1),
    )

    logger.info(
        "Resource scaler: cpu=%d, ram=%.1fGB, tier=%d → "
        "naabu_rate=%d, nuclei_concurrency=%d, nuclei_rate=%d, "
        "fpx_timeout=%ds, sensitive_paths=%s",
        cpu,
        ram_gb,
        scan_tier,
        params.naabu_rate,
        params.nuclei_concurrency,
        params.nuclei_rate_limit,
        params.fingerprintx_timeout,
        params.sensitive_paths_limit or "unlimited",
    )

    return params
