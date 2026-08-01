"""Nuclei detection canary — assert a known target still yields a known finding.

"nuclei runs" is easy to see (findings appear); "nuclei still DETECTS what it
should" is not — templates can break, the fuzzing set can be missing, coverage can
truncate silently. The canary runs nuclei against a fixed target whose vulnerability
is known and asserts the expected template id fires. If it stops firing, engine
health goes red — a real regression signal instead of guessing from thin results.

`evaluate_canary` is pure so it's unit-testable without running nuclei.
"""

from __future__ import annotations

# status values
OK = "ok"  # every expected template fired
DEGRADED = "degraded"  # some expected fired, some missing
FAILING = "failing"  # none of the expected templates fired (engine likely broken)
UNKNOWN = "unknown"  # nothing to assert


def evaluate_canary(found_template_ids, expected_template_ids) -> dict:
    """Compare the template ids nuclei reported against what we expect.

    Returns {status, expected, matched, missing}.
    """
    found = {str(t) for t in (found_template_ids or [])}
    expected = [str(t) for t in (expected_template_ids or [])]
    matched = [t for t in expected if t in found]
    missing = [t for t in expected if t not in found]

    if not expected:
        status = UNKNOWN
    elif not missing:
        status = OK
    elif matched:
        status = DEGRADED
    else:
        status = FAILING

    return {"status": status, "expected": expected, "matched": matched, "missing": missing}
