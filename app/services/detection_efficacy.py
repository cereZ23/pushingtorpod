"""Detection-efficacy harness.

Complements the canary validator (which checks known findings on *live* scans)
with a fixture-driven evaluation: run each detection control against curated
known-positive and known-negative inputs and measure precision / recall. This
is CI-runnable and catches the "a change silently broke a detection" regression
class — you stop discovering it from a client.

A ``GoldenCase`` describes an input that a control SHOULD (or should NOT) fire
on, plus any module-level functions to mock (e.g. network/DNS helpers) so the
case is deterministic and offline.
"""

from __future__ import annotations

from contextlib import ExitStack
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional
from unittest.mock import patch


@dataclass
class GoldenCase:
    control_id: str
    name: str
    build_input: Callable[[], tuple]  # -> (asset, services, certificates)
    expect_finding: bool
    # dotted path -> value. Exceptions/callables become side_effect, else return_value.
    mocks: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ControlEfficacy:
    control_id: str
    tp: int = 0  # expected + fired
    fp: int = 0  # not expected + fired
    fn: int = 0  # expected + not fired
    tn: int = 0  # not expected + not fired

    @property
    def recall(self) -> float:
        denom = self.tp + self.fn
        return self.tp / denom if denom else 1.0

    @property
    def precision(self) -> float:
        denom = self.tp + self.fp
        return self.tp / denom if denom else 1.0

    def as_dict(self) -> dict:
        return {
            "control_id": self.control_id,
            "tp": self.tp,
            "fp": self.fp,
            "fn": self.fn,
            "tn": self.tn,
            "recall": round(self.recall, 4),
            "precision": round(self.precision, 4),
        }


def _is_exceptionish(value: Any) -> bool:
    return isinstance(value, BaseException) or (isinstance(value, type) and issubclass(value, BaseException))


def _run_case(case: GoldenCase, check_fn: Callable) -> bool:
    """Run a control's check function under the case's mocks; return whether it fired."""
    with ExitStack() as stack:
        for path, value in case.mocks.items():
            mock = stack.enter_context(patch(path))
            if _is_exceptionish(value) or callable(value):
                mock.side_effect = value
            else:
                mock.return_value = value
        asset, services, certificates = case.build_input()
        findings = check_fn(asset, services, certificates, None)
    return bool(findings)


def evaluate(cases: List[GoldenCase], controls: Optional[dict] = None) -> Dict[str, ControlEfficacy]:
    """Evaluate golden cases, returning per-control efficacy (tp/fp/fn/tn)."""
    if controls is None:
        from app.tasks.misconfig import get_registered_controls

        controls = get_registered_controls()

    results: Dict[str, ControlEfficacy] = {}
    for case in cases:
        control = controls.get(case.control_id)
        if not control:
            continue
        fired = _run_case(case, control["check_fn"])
        eff = results.setdefault(case.control_id, ControlEfficacy(case.control_id))
        if case.expect_finding and fired:
            eff.tp += 1
        elif case.expect_finding and not fired:
            eff.fn += 1
        elif not case.expect_finding and fired:
            eff.fp += 1
        else:
            eff.tn += 1
    return results


def summarize(results: Dict[str, ControlEfficacy]) -> dict:
    """Aggregate per-control efficacy into an overall precision/recall report."""
    overall = ControlEfficacy("__overall__")
    for eff in results.values():
        overall.tp += eff.tp
        overall.fp += eff.fp
        overall.fn += eff.fn
        overall.tn += eff.tn
    return {
        "overall": overall.as_dict(),
        "per_control": {cid: eff.as_dict() for cid, eff in sorted(results.items())},
        "missed": [cid for cid, eff in results.items() if eff.fn > 0],
        "false_positives": [cid for cid, eff in results.items() if eff.fp > 0],
    }
