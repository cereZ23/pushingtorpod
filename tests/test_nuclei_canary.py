"""Nuclei detection-canary evaluator: ok/degraded/failing logic."""

from app.services.scanning.nuclei_canary import evaluate_canary


def test_ok_when_all_expected_found():
    r = evaluate_canary(["reflected-xss", "ftp-detect"], ["reflected-xss"])
    assert r["status"] == "ok"
    assert r["matched"] == ["reflected-xss"]
    assert r["missing"] == []


def test_failing_when_none_found():
    r = evaluate_canary(["ftp-detect", "imap-detect"], ["reflected-xss"])
    assert r["status"] == "failing"
    assert r["missing"] == ["reflected-xss"]
    assert r["matched"] == []


def test_degraded_when_partial():
    r = evaluate_canary(["reflected-xss"], ["reflected-xss", "sqli-error-based"])
    assert r["status"] == "degraded"
    assert r["matched"] == ["reflected-xss"]
    assert r["missing"] == ["sqli-error-based"]


def test_unknown_when_nothing_expected():
    assert evaluate_canary(["x"], [])["status"] == "unknown"


def test_empty_found_is_failing():
    assert evaluate_canary([], ["reflected-xss"])["status"] == "failing"
