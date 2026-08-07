"""Canonical endpoint-verification vocabulary (UI-1 PR 1a): precedence, batch reason mapping,
state rules, snapshot shape. Pure module — no DB.
"""

from __future__ import annotations

from types import SimpleNamespace

from app.services.endpoint_verification import (
    LIMITATION_PRECEDENCE,
    VALID_LIMITATIONS,
    batch_limitation_reason,
    build_snapshot,
    ranked_limitations,
    resolve_limitation,
)


def _ev(**kw):
    base = dict(
        launched=True,
        exit_code=0,
        timed_out=False,
        budget_expired=False,
        truncated=False,
        drift=False,
        parse_incomplete=False,
        unresponsive_targets=0,
    )
    base.update(kw)
    return SimpleNamespace(**base)


def test_precedence_most_severe_wins():
    assert resolve_limitation(["unresponsive_origins", "timeout"]) == "timeout"
    assert resolve_limitation(["insufficient_budget", "output_truncated"]) == "output_truncated"
    assert resolve_limitation(["output_truncated", "execution_error", "timeout"]) == "execution_error"
    assert resolve_limitation([]) is None
    assert resolve_limitation(["not_a_reason"]) is None


def test_ranked_limitations_dedup_ordered_enum_only():
    r = ranked_limitations(["unresponsive_origins", "timeout", "unresponsive_origins", "garbage"])
    assert r == ["timeout", "unresponsive_origins"]
    assert all(x in VALID_LIMITATIONS for x in r)


def test_batch_reason_mapping_by_severity():
    assert batch_limitation_reason(_ev(exit_code=1)) == "execution_error"
    assert batch_limitation_reason(_ev(drift=True)) == "catalog_drift"
    assert batch_limitation_reason(_ev(parse_incomplete=True)) == "parser_incomplete"
    assert batch_limitation_reason(_ev(timed_out=True)) == "timeout"
    # truncated alone → output_truncated, NOT unresponsive, NOT unknown
    assert batch_limitation_reason(_ev(truncated=True)) == "output_truncated"
    assert batch_limitation_reason(_ev(budget_expired=True)) == "insufficient_budget"
    assert batch_limitation_reason(_ev(unresponsive_targets=5)) == "unresponsive_origins"
    # timeout + truncated → timeout (more specific)
    assert batch_limitation_reason(_ev(timed_out=True, truncated=True)) == "timeout"
    # clean batch → None
    assert batch_limitation_reason(_ev()) is None


def _snap(**kw):
    base = dict(
        enabled=True,
        no_targets=False,
        structural_failed=False,
        pass_status="partial",
        execution_complete=True,
        phase_non_degrading=True,
        coverage_authorizing=False,
        counts={"selected": 60, "covered": 57, "partial": 3, "failed": 0, "skipped": 0},
        batch_reasons=["unresponsive_origins"],
    )
    base.update(kw)
    return build_snapshot(**base)


def test_state_disabled():
    assert _snap(enabled=False, pass_status="skipped", batch_reasons=[])["state"] == "disabled"


def test_state_no_targets():
    s = _snap(no_targets=True, pass_status="skipped", batch_reasons=[], counts={"selected": 0})
    assert s["state"] == "no_targets"


def test_state_complete():
    s = _snap(
        pass_status="completed",
        batch_reasons=[],
        counts={"selected": 60, "covered": 60, "partial": 0, "failed": 0, "skipped": 0},
    )
    assert s["state"] == "complete" and s["limitation"] is None


def test_state_limited_only_for_unresponsive():
    s = _snap(pass_status="partial", batch_reasons=["unresponsive_origins"])
    assert s["state"] == "limited"
    assert s["limitation"] == "unresponsive_origins"
    assert s["execution_complete"] is True


def test_state_incomplete_for_budget_timeout_truncated():
    for reason in ("timeout", "output_truncated", "insufficient_budget", "parser_incomplete"):
        s = _snap(pass_status="partial", batch_reasons=[reason])
        assert s["state"] == "incomplete", reason
        assert s["limitation"] == reason


def test_state_failed_structural():
    s = _snap(structural_failed=True, pass_status="skipped", batch_reasons=["configuration_error"])
    assert s["state"] == "failed"


def test_batch_precedence_out_of_evidence_wins():
    # writer/attribution/cleanup are invisible to batch_limitation_reason; they are folded in via
    # resolve_limitation with the evidence reason. Most-severe wins.
    assert resolve_limitation(["writer_error", "timeout"]) == "writer_error"
    assert resolve_limitation(["parser_incomplete", "unresponsive_origins"]) == "parser_incomplete"
    assert resolve_limitation(["execution_error", "writer_error", "timeout"]) == "execution_error"
    # a clean batch contributes no reason
    assert resolve_limitation([]) is None


def test_hardening_count_sum_mismatch_is_data_inconsistent():
    # selected != covered+partial+failed+skipped → never complete; headline = data_inconsistent
    s = _snap(
        pass_status="completed",
        batch_reasons=[],
        counts={"selected": 60, "covered": 10, "partial": 0, "failed": 0, "skipped": 0},
    )
    assert s["state"] == "incomplete"
    assert s["limitation"] == "data_inconsistent"
    assert s["limitations"][0] == "data_inconsistent"


def test_hardening_negative_count_is_data_inconsistent():
    s = _snap(
        pass_status="completed",
        batch_reasons=[],
        counts={"selected": 5, "covered": -1, "partial": 0, "failed": 0, "skipped": 0},
    )
    assert s["state"] == "incomplete" and s["limitation"] == "data_inconsistent"


def test_hardening_bool_count_is_data_inconsistent():
    # bool is an int subclass — must NOT masquerade as a count of 1/0
    s = _snap(
        pass_status="completed",
        batch_reasons=[],
        counts={"selected": True, "covered": True, "partial": 0, "failed": 0, "skipped": 0},
    )
    assert s["state"] == "incomplete" and s["limitation"] == "data_inconsistent"


def test_hardening_complete_with_reasons_downgrades_to_incomplete():
    # counts coherent but pass claims completed while a real reason is present → incomplete, keep reason
    s = _snap(
        pass_status="completed",
        batch_reasons=["timeout"],
        counts={"selected": 60, "covered": 60, "partial": 0, "failed": 0, "skipped": 0},
    )
    assert s["state"] == "incomplete"
    assert s["limitation"] == "timeout"


def test_reasonless_incomplete_is_unknown_never_null():
    # partial run, execution not complete, NO attributable batch reason → incomplete must still carry
    # a reason (unknown), never a null limitation.
    s = _snap(pass_status="partial", execution_complete=False, batch_reasons=[])
    assert s["state"] == "incomplete"
    assert s["limitation"] == "unknown"
    assert not (s["state"] == "incomplete" and s["limitation"] is None)


def test_no_targets_carries_numeric_context():
    s = build_snapshot(
        enabled=True,
        no_targets=True,
        structural_failed=False,
        pass_status="skipped",
        execution_complete=False,
        phase_non_degrading=True,
        coverage_authorizing=False,
        counts={"selected": 0, "covered": 0, "partial": 0, "failed": 0, "skipped": 0},
        batch_reasons=[],
        detail={"candidate_count": 12, "out_of_scope_dropped": 12, "template_count": 40},
    )
    assert s["state"] == "no_targets"
    assert s["candidate_count"] == 12
    assert s["out_of_scope_dropped"] == 12
    assert s["template_count"] == 40


def test_snapshot_shape_and_schema_version():
    s = _snap()
    assert s["schema_version"] == 1
    for k in (
        "enabled",
        "execution_complete",
        "phase_non_degrading",
        "coverage_authorizing",
        "state",
        "limitation",
        "limitations",
        "selected",
        "covered",
        "partial",
        "failed",
        "skipped",
    ):
        assert k in s
    assert s["limitations"] == ["unresponsive_origins"]
