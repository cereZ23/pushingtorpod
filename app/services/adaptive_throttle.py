"""Adaptive throttling for scan pipeline.

Detects HTTP 429 (Too Many Requests) and other rate-limiting signals,
then automatically reduces scan rates for subsequent phases.

Usage in pipeline phases:
    throttle = get_throttle(tenant_id, scan_run_id)
    effective_rate = throttle.get_rate(base_rate)   # returns reduced rate if throttled
    throttle.report_429(host)                        # report a 429 response
    throttle.report_timeout(host)                    # report a connection timeout
"""

from __future__ import annotations

import logging
import time
from collections import defaultdict
from dataclasses import dataclass, field
from threading import Lock

logger = logging.getLogger(__name__)

# How much to reduce rate on each 429 detection (multiplicative)
_BACKOFF_FACTOR = 0.5
# Minimum rate floor (never go below this)
_MIN_RATE = 10
# Number of 429s before triggering throttle
_THROTTLE_THRESHOLD = 3
# How many consecutive clean phases before restoring rate
_RECOVERY_PHASES = 2


@dataclass
class ThrottleState:
    """Per-scan throttle state tracking 429s and adjusting rates."""

    tenant_id: int
    scan_run_id: int
    _lock: Lock = field(default_factory=Lock, repr=False)
    _429_counts: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    _timeout_counts: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    _total_429s: int = 0
    _total_timeouts: int = 0
    _rate_multiplier: float = 1.0
    _throttled_since: float | None = None
    _clean_phases: int = 0

    def report_429(self, host: str = "unknown") -> None:
        """Report an HTTP 429 response."""
        with self._lock:
            self._429_counts[host] += 1
            self._total_429s += 1
            self._clean_phases = 0

            if self._total_429s >= _THROTTLE_THRESHOLD and self._rate_multiplier > _BACKOFF_FACTOR:
                old = self._rate_multiplier
                self._rate_multiplier = max(self._rate_multiplier * _BACKOFF_FACTOR, 0.1)
                self._throttled_since = time.time()
                logger.warning(
                    "Adaptive throttle: %d 429s detected (tenant %d, run %d). Rate multiplier %.2f -> %.2f",
                    self._total_429s,
                    self.tenant_id,
                    self.scan_run_id,
                    old,
                    self._rate_multiplier,
                )

    def report_timeout(self, host: str = "unknown") -> None:
        """Report a connection timeout (potential sign of being blocked)."""
        with self._lock:
            self._timeout_counts[host] += 1
            self._total_timeouts += 1

    def report_phase_clean(self) -> None:
        """Report that a phase completed without 429s — may recover rate."""
        with self._lock:
            if self._rate_multiplier < 1.0:
                self._clean_phases += 1
                if self._clean_phases >= _RECOVERY_PHASES:
                    old = self._rate_multiplier
                    self._rate_multiplier = min(self._rate_multiplier / _BACKOFF_FACTOR, 1.0)
                    self._clean_phases = 0
                    logger.info(
                        "Adaptive throttle: %d clean phases, recovering rate %.2f -> %.2f (tenant %d, run %d)",
                        _RECOVERY_PHASES,
                        old,
                        self._rate_multiplier,
                        self.tenant_id,
                        self.scan_run_id,
                    )

    def get_rate(self, base_rate: int) -> int:
        """Get effective rate after applying throttle multiplier."""
        with self._lock:
            effective = max(int(base_rate * self._rate_multiplier), _MIN_RATE)
            if self._rate_multiplier < 1.0:
                logger.info(
                    "Adaptive throttle: base_rate=%d, effective=%d (multiplier=%.2f)",
                    base_rate,
                    effective,
                    self._rate_multiplier,
                )
            return effective

    def get_delay(self, base_delay: float = 0.0) -> float:
        """Get effective delay between requests. Increases when throttled."""
        with self._lock:
            if self._rate_multiplier >= 1.0:
                return base_delay
            # Add delay inversely proportional to multiplier
            added = (1.0 / self._rate_multiplier - 1.0) * 0.5
            return base_delay + added

    @property
    def is_throttled(self) -> bool:
        return self._rate_multiplier < 1.0

    @property
    def total_429s(self) -> int:
        return self._total_429s

    @property
    def rate_multiplier(self) -> float:
        return self._rate_multiplier

    def summary(self) -> dict:
        """Return throttle state summary for scan stats."""
        return {
            "total_429s": self._total_429s,
            "total_timeouts": self._total_timeouts,
            "rate_multiplier": round(self._rate_multiplier, 2),
            "is_throttled": self.is_throttled,
            "hosts_429": dict(self._429_counts),
        }


# Global registry of active throttle states (one per scan run)
_active_throttles: dict[tuple[int, int], ThrottleState] = {}
_registry_lock = Lock()


def get_throttle(tenant_id: int, scan_run_id: int) -> ThrottleState:
    """Get or create throttle state for a scan run."""
    key = (tenant_id, scan_run_id)
    with _registry_lock:
        if key not in _active_throttles:
            _active_throttles[key] = ThrottleState(
                tenant_id=tenant_id,
                scan_run_id=scan_run_id,
            )
        return _active_throttles[key]


def cleanup_throttle(tenant_id: int, scan_run_id: int) -> dict | None:
    """Remove throttle state after scan completes. Returns summary."""
    key = (tenant_id, scan_run_id)
    with _registry_lock:
        state = _active_throttles.pop(key, None)
    if state:
        return state.summary()
    return None
