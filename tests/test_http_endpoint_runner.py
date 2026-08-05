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
_FLAGS_INTERACTSH = {**_FLAGS_OFF, "interactsh": "true"}

# The REAL Nuclei -stats JSON record (numeric values as STRINGS), as observed in Curci prod logs.
_REAL_STATS_99 = '{"duration":"0:01:12","hosts":"21","percent":"99","requests":"8851","templates":"284","total":"8904"}'
_REAL_STATS_100 = (
    '{"duration":"0:01:20","hosts":"21","percent":"100","requests":"8904","templates":"284","total":"8904"}'
)
# Observed at T2: nuclei's `total` is an estimate; the actual `requests` count overshoots it slightly
# (here requests 8907 > total 8904) while percent is 100. That is still a COMPLETE run.
_REAL_STATS_100_OVERSHOOT = (
    '{"duration":"0:01:20","hosts":"21","percent":"100","requests":"8907","templates":"284","total":"8904"}'
)


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
    a = _args(interactsh_server="oast.internal", relevant_flags=_FLAGS_INTERACTSH)
    assert "-iserver" in a and a[a.index("-iserver") + 1] == "oast.internal"
    assert "-ni" not in a
    assert "-itoken" not in a  # no empty -itoken (it can invalidate the config)


def test_interactsh_server_flag_mismatch_raises():
    # server present but manifest interactsh=false → CLI would diverge → error BEFORE any subprocess
    with pytest.raises(EndpointRunnerError):
        _args(interactsh_server="oast.internal", relevant_flags=_FLAGS_OFF)
    # flag=true but no server → also a mismatch
    with pytest.raises(EndpointRunnerError):
        _args(interactsh_server=None, relevant_flags=_FLAGS_INTERACTSH)


def test_non_canonical_capability_value_raises():
    with pytest.raises(EndpointRunnerError):
        _args(relevant_flags={**_FLAGS_OFF, "dast": "yes"})


def test_unknown_capability_key_raises():
    with pytest.raises(EndpointRunnerError):
        _args(relevant_flags={**_FLAGS_OFF, "bogus": "false"})


def test_missing_capability_raises():
    incomplete = {"code": "false", "headless": "false", "dast": "false", "interactsh": "false"}  # no self_contained
    with pytest.raises(EndpointRunnerError):
        _args(relevant_flags=incomplete)


@pytest.mark.parametrize(
    "kw", [{"rate_limit": 0}, {"concurrency": -1}, {"request_timeout": 0}, {"max_host_errors": -5}]
)
def test_nonpositive_knobs_raise(kw):
    with pytest.raises(EndpointRunnerError):
        _args(**kw)


def test_blank_interactsh_server_is_ni():
    # whitespace/blank server → normalised to no server → -ni, and consistent with interactsh=false
    a = _args(interactsh_server="   ", relevant_flags=_FLAGS_OFF)
    assert "-ni" in a and "-iserver" not in a


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
    ev = parse_nuclei_batch_output(
        0, "", err, expected_targets=5, expected_templates=219, expected_authority=("h", 443)
    )
    assert ev.unresponsive_events == 3
    assert ev.unresponsive_targets == 0  # numeric summary alone cannot identify an input origin
    assert ev.unresponsive_attribution_complete is False
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


# --- parser: REAL Nuclei JSON stats format --------------------------------------------------------


def test_real_json_stats_extracted_and_not_a_finding():
    # the JSON stats record is on stdout; it must be parsed as stats, NOT counted as a finding.
    ev = parse_nuclei_batch_output(0, _REAL_STATS_100 + "\n", "", expected_targets=21, expected_templates=284)
    assert ev.findings == ()  # a stats record is NOT a finding
    assert ev.templates_loaded == 284 and ev.targets_loaded == 21 and ev.completion_percent == 100
    assert ev.requests_done == 8904 and ev.requests_total == 8904  # exposed for the per-batch diagnostic
    assert ev.catalog_verified and ev.targets_completed and ev.output_complete


# --- completion: nuclei may overshoot the estimated `total` (observed at T2) --------------------


def test_overshoot_at_100_is_complete():
    # 8907/8904 at 100% (like T2's 1497/1494) — an overshoot is still a COMPLETE run.
    ev = parse_nuclei_batch_output(0, _REAL_STATS_100_OVERSHOOT + "\n", "", expected_targets=21, expected_templates=284)
    assert ev.completion_percent == 100 and ev.requests_done == 8907 and ev.requests_total == 8904
    assert ev.targets_completed and ev.catalog_verified and ev.output_complete


def test_done_equals_total_still_complete():
    # T1 format (done == total) is unchanged by the >= relaxation.
    ev = parse_nuclei_batch_output(0, _REAL_STATS_100 + "\n", "", expected_targets=21, expected_templates=284)
    assert ev.targets_completed


def test_requests_below_total_is_incomplete_even_at_100():
    short = '{"hosts":"21","percent":"100","requests":"8903","templates":"284","total":"8904"}'
    ev = parse_nuclei_batch_output(0, short + "\n", "", expected_targets=21, expected_templates=284)
    assert ev.targets_completed is False  # done < total ⇒ a dropped request ⇒ NOT complete


def test_total_zero_or_absent_is_incomplete():
    zero = '{"hosts":"21","percent":"100","requests":"0","templates":"284","total":"0"}'
    ev = parse_nuclei_batch_output(0, zero + "\n", "", expected_targets=21, expected_templates=284)
    assert ev.targets_completed is False  # total 0 ⇒ requests_total > 0 fails ⇒ NOT complete


def test_overshoot_with_catalog_mismatch_is_not_covered():
    # Completion side is fine, but the catalog proof fails ⇒ can never be COVERED.
    ev = parse_nuclei_batch_output(0, _REAL_STATS_100_OVERSHOOT + "\n", "", expected_targets=21, expected_templates=999)
    assert ev.catalog_verified is False
    assert ev.targets_completed  # only the templates-loaded proof is missing


def test_overshoot_with_unresponsive_is_partial():
    err = _REAL_STATS_100_OVERSHOOT + "\nSkipped h.example.it:443 from target list as found unresponsive permanently\n"
    ev = parse_nuclei_batch_output(
        0, "", err, expected_targets=21, expected_templates=284, expected_authority=("h.example.it", 443)
    )
    assert ev.unresponsive_targets >= 1  # attributed to the batch origin
    assert ev.targets_completed is False  # any unresponsive origin ⇒ PARTIAL despite the overshoot


def test_real_json_stats_on_stderr_also_parsed():
    ev = parse_nuclei_batch_output(0, "", _REAL_STATS_100, expected_targets=21, expected_templates=284)
    assert ev.completion_percent == 100 and ev.templates_loaded == 284 and ev.targets_loaded == 21


def test_percent_99_is_not_complete():
    ev = parse_nuclei_batch_output(0, _REAL_STATS_99 + "\n", "", expected_targets=21, expected_templates=284)
    assert ev.completion_percent == 99
    assert ev.catalog_verified is True  # templates match...
    assert ev.targets_completed is False and ev.output_complete is False  # ...but 99% ≠ complete


def test_real_unresponsive_line_counts_and_blocks_completion():
    err = _REAL_STATS_100 + "\nSkipped link.example.it:443 from target list as found unresponsive permanently\n"
    ev = parse_nuclei_batch_output(
        0,
        "",
        err,
        expected_targets=21,
        expected_templates=284,
        expected_authority=("link.example.it", 443),
    )
    assert ev.unresponsive_events == 1
    assert ev.unresponsive_targets == 1  # exactly one, not double-counted
    assert ev.unresponsive_attribution_complete is True
    assert ev.targets_completed is False


def test_repeated_unresponsive_lines_are_one_unique_expected_origin():
    line = "Skipped link.example.it:443 from target list as found unresponsive permanently\n"
    ev = parse_nuclei_batch_output(
        0,
        "",
        _REAL_STATS_100 + "\n" + line + line,
        expected_targets=1,
        expected_templates=284,
        expected_authority=("link.example.it", 443),
    )
    assert ev.unresponsive_events == 2
    assert ev.unresponsive_targets == 1
    assert ev.unresponsive_attribution_complete is True


def test_foreign_unresponsive_origin_is_ambiguous_not_attributed():
    err = _REAL_STATS_100 + "\nSkipped other.example.it:443 from target list as found unresponsive permanently\n"
    ev = parse_nuclei_batch_output(
        0,
        "",
        err,
        expected_targets=1,
        expected_templates=284,
        expected_authority=("link.example.it", 443),
    )
    assert ev.unresponsive_events == 1 and ev.unresponsive_targets == 0
    assert ev.unresponsive_attribution_complete is False
    assert ev.targets_completed is False


def test_input_target_wins_over_constructed_url():
    stdout = (
        '{"template-id":"ep-a","input":"https://h/admin","url":"https://h/admin/probe","info":{"severity":"high"}}\n'
    )
    ev = parse_nuclei_batch_output(0, stdout, _REAL_STATS_100, expected_targets=21, expected_templates=284)
    assert ev.findings[0]["target"] == "https://h/admin"  # original input, not the template URL


def test_real_nuclei_result_prefers_matched_at_over_bare_host_and_malformed_url():
    stdout = (
        '{"template-id":"easm-probe","host":"easm-probe","url":"/http://easm-probe/probe",'
        '"matched-at":"http://easm-probe/probe","info":{"severity":"high"}}\n'
    )
    ev = parse_nuclei_batch_output(0, stdout, _REAL_STATS_100, expected_targets=21, expected_templates=284)
    assert ev.findings[0]["target"] == "http://easm-probe/probe"


def test_finding_without_absolute_http_target_fails_closed():
    stdout = (
        '{"template-id":"easm-probe","host":"easm-probe","url":"/http://easm-probe/probe","info":{"severity":"high"}}\n'
    )
    ev = parse_nuclei_batch_output(0, stdout, _REAL_STATS_100, expected_targets=21, expected_templates=284)
    assert ev.findings[0]["target"] is None


def test_unknown_json_object_sets_parse_incomplete():
    # a JSON object with no template-id and not a stats record → unknown → parse incomplete, not a finding
    stdout = '{"foo":"bar","baz":1}\n'
    ev = parse_nuclei_batch_output(0, stdout, _REAL_STATS_100, expected_targets=21, expected_templates=284)
    assert ev.parse_incomplete is True
    assert ev.findings == ()
    assert ev.output_complete is False


def test_100_percent_but_requests_lt_total_is_not_complete():
    # every request must be accounted for: 100% with requests != total (a dropped request) ⇒ NOT complete
    stats = '{"percent":"100","requests":"8903","total":"8904","hosts":"21","templates":"284"}'
    ev = parse_nuclei_batch_output(0, stats + "\n", "", expected_targets=21, expected_templates=284)
    assert ev.completion_percent == 100
    assert ev.targets_completed is False and ev.output_complete is False


def test_partial_stats_keyset_is_not_stats():
    # only "percent" (not the full key set) → not a stats record → unknown JSON → parse incomplete
    ev = parse_nuclei_batch_output(0, '{"percent":"100"}\n', "", expected_targets=21, expected_templates=284)
    assert ev.parse_incomplete is True and ev.findings == ()
    assert ev.completion_percent is None


def test_finding_with_stray_percent_stays_a_finding():
    # a finding carrying stat keys must stay a finding (template-id is checked first)
    stdout = (
        '{"template-id":"ep-a","input":"https://h/x","percent":"100","requests":"1","total":"1",'
        '"hosts":"1","templates":"1","info":{"severity":"high"}}\n'
    )
    ev = parse_nuclei_batch_output(0, stdout, _REAL_STATS_100, expected_targets=21, expected_templates=284)
    assert len(ev.findings) == 1 and ev.findings[0]["template_id"] == "ep-a"


def test_truncated_json_on_stderr_blocks_completion():
    # a truncated stats JSON on stderr marks the parse incomplete — the text fallback must NOT authorise
    err = "Requests: 1/1 (100%)\n{ truncated json\n"
    ev = parse_nuclei_batch_output(0, "", err, expected_targets=21, expected_templates=284)
    assert ev.parse_incomplete is True
    assert ev.output_complete is False  # would wrongly be True if stderr incompleteness were ignored


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
        expected_authority=("h", 443),
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


def test_run_batch_rejects_nonpositive_timeout():
    calls = []
    runner = _runner(lambda a, t: calls.append(1) or (0, "", _COMPLETE_ERR))
    with pytest.raises(EndpointRunnerError):
        _call(runner, timeout_seconds=0)
    assert calls == []  # exec never invoked
