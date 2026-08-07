"""Single source of truth for a scan run's trigger provenance.

``scan_runs.triggered_by`` used to hold BOTH the provenance (manual/scheduler/...) AND ad-hoc
diagnostic labels (e.g. "t2-cutover-verify"), so the UI couldn't render an honest provenance badge.
It is now split:

* ``trigger_type``  — the provenance, decided SERVER-SIDE from the code path, one of
  {manual, scheduled, api, retest}. This is the ONLY field the UI/authorization logic should read.
* ``trigger_label`` — an optional, descriptive, normalized free string. Purely informational: it
  NEVER decides the type and is never used for any logic.

``triggered_by`` is kept for backward compatibility and is written HERE ONLY (via :func:`apply_trigger`)
so the three fields can never diverge. Legacy custom values (no recognizable provenance) map to
``trigger_type = None`` — never guessed into "manual".
"""

from __future__ import annotations

from typing import Optional

# The valid provenance values (mirrors the DB CHECK on scan_runs.trigger_type).
TRIGGER_TYPES = frozenset({"manual", "scheduled", "api", "retest"})

# Back-compat string written into the legacy ``triggered_by`` for each type when no label is given.
# "scheduled" maps to the historical "scheduler" so old readers/queries keep matching.
_LEGACY_TRIGGERED_BY = {
    "manual": "manual",
    "scheduled": "scheduler",
    "api": "api",
    "retest": "retest",
}

_MAX_LABEL_LEN = 100


def normalize_trigger_label(label: Optional[str]) -> Optional[str]:
    """Trim, collapse to a bounded single-line string, or None. Never used for logic — display only."""
    if not label or not isinstance(label, str):
        return None
    cleaned = " ".join(label.split())  # collapse whitespace / strip newlines
    cleaned = cleaned[:_MAX_LABEL_LEN].strip()
    return cleaned or None


def apply_trigger(scan_run, trigger_type: str, trigger_label: Optional[str] = None) -> None:
    """Set trigger_type + trigger_label + the legacy triggered_by on a ScanRun, consistently.

    Raises ValueError for an unknown ``trigger_type`` so a bad server-side decision fails loudly
    rather than persisting an invalid/None provenance for a NEW run.
    """
    if trigger_type not in TRIGGER_TYPES:
        raise ValueError(f"unknown trigger_type: {trigger_type!r}")
    label = normalize_trigger_label(trigger_label)
    scan_run.trigger_type = trigger_type
    scan_run.trigger_label = label
    # Legacy field: the descriptive label if present (old behaviour put custom labels here), else the
    # canonical legacy provenance string.
    scan_run.triggered_by = label or _LEGACY_TRIGGERED_BY[trigger_type]


__all__ = ["TRIGGER_TYPES", "normalize_trigger_label", "apply_trigger"]
