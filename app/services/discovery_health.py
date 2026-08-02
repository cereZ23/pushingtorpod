"""Discovery-health guard (auto-close pre-condition).

The pipeline auto-closes findings that were "not seen this run". That is only
safe if discovery actually worked this run — a broken/partial discovery makes
every asset look "gone", which would flip real open findings to FIXED
(fabricated remediation). This module computes a structured discovery-health
verdict that the auto-close (and, later, incremental scanning) must consult.

Design contract:
  - ``compute_discovery_health`` is PURE (no DB / no persistence) → trivially
    testable; the caller gathers inputs and persists the result.
  - Explicit failures (FAILED/PARTIAL discovery) short-circuit BEFORE the
    ">N% assets missing" heuristic — you don't wait for a 50% drop when the
    phase already failed.
  - No comparable baseline (first run, changed scope) is NOT suspicious.
  - Result is structured with a stable ``reason_code`` (never parse strings),
    and always carries the raw counts so a policy can later combine ratio +
    absolute without changing the signal.
  - Fail-closed downstream: absent / unhealthy / degraded → DO NOT auto-close.
"""

from __future__ import annotations

import enum
import hashlib
import json
from dataclasses import asdict, dataclass
from typing import Optional


class ReasonCode(str, enum.Enum):
    OK = "ok"
    NO_COMPARABLE_BASELINE = "no_comparable_baseline"
    DISCOVERY_FAILED = "discovery_failed"
    DISCOVERY_PARTIAL = "discovery_partial"
    EMPTY_OUTPUT = "empty_output"
    ASSET_DROP_THRESHOLD = "asset_drop_threshold"


@dataclass
class DiscoveryHealth:
    healthy: bool
    degraded: bool
    reason_code: str
    reason: str
    comparison_performed: bool
    previous_count: Optional[int]
    observed_count: int
    missing_count: int
    missing_ratio: float
    baseline_scan_run_id: Optional[int]

    def to_dict(self) -> dict:
        return asdict(self)


def discovery_scope_hash(seeds, scope_rules, discovery_config: Optional[dict] = None) -> str:
    """Stable hash of what defines the discovery *scope*.

    Two runs are only comparable for the asset-drop heuristic if this matches —
    changing seeds / include-exclude rules / discovery config legitimately changes
    the observed set and must NOT read as a degraded discovery.
    """
    payload = {
        "seeds": sorted(str(s) for s in (seeds or [])),
        "scopes": sorted(str(s) for s in (scope_rules or [])),
        "config": discovery_config or {},
    }
    blob = json.dumps(payload, sort_keys=True, default=str)
    return hashlib.sha256(blob.encode()).hexdigest()[:16]


def compute_discovery_health(
    *,
    discovery_phase_status: Optional[str],
    baseline_available: bool,
    previous_count: Optional[int],
    observed_count: int,
    baseline_scan_run_id: Optional[int] = None,
    drop_ratio_threshold: float = 0.5,
) -> DiscoveryHealth:
    """Pure verdict. See module docstring for the precedence contract."""

    def make(healthy, degraded, code: ReasonCode, reason, comparison, missing=0, ratio=0.0) -> DiscoveryHealth:
        return DiscoveryHealth(
            healthy=healthy,
            degraded=degraded,
            reason_code=code.value,
            reason=reason,
            comparison_performed=comparison,
            previous_count=previous_count,
            observed_count=observed_count,
            missing_count=missing,
            missing_ratio=ratio,
            baseline_scan_run_id=baseline_scan_run_id,
        )

    status = (discovery_phase_status or "").upper()

    # 1-2. Explicit failure precedes the heuristic.
    if status == "FAILED":
        return make(False, True, ReasonCode.DISCOVERY_FAILED, "discovery phase FAILED", False)
    if status == "PARTIAL":
        return make(False, True, ReasonCode.DISCOVERY_PARTIAL, "discovery phase PARTIAL", False)

    # 3. No comparable baseline → not suspicious (first run / changed scope).
    if not baseline_available or previous_count is None:
        return make(True, False, ReasonCode.NO_COMPARABLE_BASELINE, "no comparable baseline run", False)

    # 4. Unexpected empty output when the baseline had assets.
    if observed_count == 0 and previous_count > 0:
        return make(
            False,
            True,
            ReasonCode.EMPTY_OUTPUT,
            f"0 assets observed vs {previous_count} in baseline",
            True,
            missing=previous_count,
            ratio=1.0,
        )

    # 5. Large drop vs baseline.
    missing = max(previous_count - observed_count, 0)
    ratio = round(missing / previous_count, 4) if previous_count > 0 else 0.0
    if ratio > drop_ratio_threshold:
        return make(
            False,
            True,
            ReasonCode.ASSET_DROP_THRESHOLD,
            f"{missing}/{previous_count} previously observed assets are missing",
            True,
            missing=missing,
            ratio=ratio,
        )

    # 6. Healthy.
    return make(True, False, ReasonCode.OK, "discovery healthy", True, missing=missing, ratio=ratio)
