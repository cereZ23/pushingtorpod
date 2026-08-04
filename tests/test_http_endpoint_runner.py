"""Concrete Nuclei runner (Sprint 3, step 3b-2) — CLI args + positive-proof parser.

Pure: no DB, no subprocess (the exec is injected). Verifies the command uses only the staged dir,
interactsh -ni/-iserver, no undeclared capability flags, and that the -stats/-jsonl parser yields
POSITIVE PROOF only when the output unambiguously confirms it (else the batch degrades to PARTIAL).
"""

from __future__ import annotations

import subprocess

import pytest

from app.services.scanning.http_endpoint_runner import (
    EndpointRunnerError,
    EndpointRunnerTimeout,
    NucleiEndpointRunner,
    build_nuclei_args,
    parse_nuclei_batch_output,
)

_FLAGS_OFF = {"code": "false", "headless": "false", "dast": "false", "self_contained": "false", "interactsh": "false"}


def _args(**over):
    base = dict(
        target_file="/tmp/http_endpoint_targets_x/targets.txt",
        template_dir="/tmp/http_endpoint_templates_y",
        interactsh_server=None,
        relevant_flags=_FLAGS_OFF,
        severity=["critical", "high"],
        exclude_tags=["fuzz"],
        rate_limit=150,
        concurrency=25,
        request_timeout=10,
        max_host_errors=30,
    )
    base.update(over)
    return build_nuclei_args(**base)


# --- CLI args -------------------------------------------------------------------------------------


def test_args_use_staged_dir_and_target_file():
    a = _args()
    assert a[a.index("-l") + 1] == "/tmp/http_endpoint_targets_x/targets.txt"
    assert a[a.index("-t") + 1] == "/tmp/http_endpoint_templates_y"  # staged dir, NOT stock roots
    for flag in ("-jsonl", "-no-color", "-duc", "-stats", "-si", "-no-httpx"):
        assert flag in a


def test_interactsh_ni_when_no_server():
    a = _args(interactsh_server=None)
    assert "-ni" in a and "-iserver" not in a


def test_interactsh_iserver_when_configured():
    a = _args(interactsh_server="oast.internal")
    assert "-iserver" in a and a[a.index("-iserver") + 1] == "oast.internal"
    assert "-ni" not in a


def test_no_capability_flag_when_disabled():
    a = _args()
    for flag in ("-code", "-headless", "-dast", "-esc"):
        assert flag not in a


def test_capability_flag_added_only_when_enabled():
    # proves the gate is real: enabling dast in relevant_flags adds -dast, others stay off
    a = _args(relevant_flags={**_FLAGS_OFF, "dast": "true"})
    assert "-dast" in a
    assert "-code" not in a and "-headless" not in a and "-esc" not in a


# --- parser: positive proof -----------------------------------------------------------------------

_COMPLETE_ERR = (
    "[INF] Templates loaded for current scan: 219\n"
    "[INF] Targets loaded for current scan: 5\n"
    "[INF] | Templates: 219 | Hosts: 5 | Requests: 1095/1095 (100%) | Matched: 0 | Errors: 0\n"
)


def test_complete_run_yields_all_positive_proofs():
    ev = parse_nuclei_batch_output(0, "", _COMPLETE_ERR, expected_targets=5, expected_templates=219)
    assert ev.launched and ev.exit_code == 0
    assert ev.templates_loaded == 219 and ev.targets_loaded == 5 and ev.completion_percent == 100
    assert ev.catalog_verified and ev.targets_completed and ev.output_complete
    assert ev.unresponsive_targets == 0 and not ev.parse_incomplete


def test_templates_mismatch_fails_catalog_verified():
    ev = parse_nuclei_batch_output(0, "", _COMPLETE_ERR, expected_targets=5, expected_templates=218)
    assert ev.catalog_verified is False  # 219 loaded != 218 expected


def test_targets_mismatch_fails_targets_completed():
    ev = parse_nuclei_batch_output(0, "", _COMPLETE_ERR, expected_targets=6, expected_templates=219)
    assert ev.targets_completed is False  # 5 loaded != 6 expected


def test_missing_completion_line_is_not_complete():
    err = "[INF] Templates loaded for current scan: 219\n[INF] Targets loaded for current scan: 5\n"
    ev = parse_nuclei_batch_output(0, "", err, expected_targets=5, expected_templates=219)
    assert ev.completion_percent is None
    assert ev.targets_completed is False and ev.output_complete is False


def test_malformed_jsonl_sets_parse_incomplete():
    stdout = '{"template-id":"ep-a","url":"https://h/x","info":{"name":"n","severity":"high"}}\n{ broken\n'
    ev = parse_nuclei_batch_output(0, stdout, _COMPLETE_ERR, expected_targets=5, expected_templates=219)
    assert ev.parse_incomplete is True
    assert ev.output_complete is False  # a broken result line ⇒ not fully processed
    assert len(ev.findings) == 1


def test_unresponsive_line_counts():
    err = _COMPLETE_ERR + "[WRN] Found 3 unresponsive hosts\n"
    ev = parse_nuclei_batch_output(0, "", err, expected_targets=5, expected_templates=219)
    assert ev.unresponsive_targets == 3
    assert ev.targets_completed is False  # any unresponsive ⇒ not complete


def test_findings_keep_input_target():
    stdout = '{"template-id":"ep-a","url":"https://h/admin","matcher-name":"m","info":{"name":"n","severity":"high"}}\n'
    ev = parse_nuclei_batch_output(0, stdout, _COMPLETE_ERR, expected_targets=5, expected_templates=219)
    f = ev.findings[0]
    assert f["target"] == "https://h/admin"  # kept for attribution
    assert f["template_id"] == "ep-a" and f["severity"] == "high" and f["matcher_name"] == "m"


def test_nonzero_exit_not_output_complete():
    ev = parse_nuclei_batch_output(2, "", _COMPLETE_ERR, expected_targets=5, expected_templates=219)
    assert ev.output_complete is False


# --- run_batch: exec injection --------------------------------------------------------------------


def _runner(exec_fn):
    return NucleiEndpointRunner(severity=["high"], exclude_tags=[], exec_fn=exec_fn)


def _call(runner, **over):
    base = dict(
        tenant_id=1,
        target_file="/tmp/t/targets.txt",
        template_dir="/tmp/tpl",
        expected_targets=5,
        expected_templates=219,
        timeout_seconds=120,
        interactsh_server=None,
        relevant_flags=_FLAGS_OFF,
    )
    base.update(over)
    return runner.run_batch(**base)


def test_run_batch_returns_evidence_from_exec():
    seen = {}

    def fake_exec(args, timeout):
        seen["args"] = args
        seen["timeout"] = timeout
        return 0, "", _COMPLETE_ERR

    ev = _call(_runner(fake_exec))
    assert ev.launched and ev.catalog_verified and ev.targets_completed
    assert "-ni" in seen["args"] and seen["timeout"] == 120


def test_run_batch_timeout_raises_typed():
    def fake_exec(args, timeout):
        raise subprocess.TimeoutExpired(cmd="nuclei", timeout=timeout)

    with pytest.raises(EndpointRunnerTimeout):
        _call(_runner(fake_exec))


def test_run_batch_generic_error_raises_runner_error():
    def fake_exec(args, timeout):
        raise OSError("nuclei not found")

    with pytest.raises(EndpointRunnerError):
        _call(_runner(fake_exec))
