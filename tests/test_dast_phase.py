"""DAST phase: target selection + gating (pure, safety-critical)."""

from app.tasks.pipeline_phases.dast import select_dast_targets, dast_skip_reason


def test_select_keeps_param_urls_and_dedups_by_shape():
    urls = [
        "http://h/item?id=1",
        "http://h/item?id=2",  # same shape as above -> collapsed
        "http://h/search?q=a",
        "http://h/about",  # no query -> dropped
        "http://h/x",  # no '?' -> dropped
    ]
    out = select_dast_targets(urls, cap=100)
    assert len(out) == 2
    assert any("item?id" in u for u in out)
    assert any("search?q" in u for u in out)


def test_cap_limits_targets():
    urls = [f"http://h/p{i}?a=1" for i in range(10)]  # 10 distinct shapes
    assert len(select_dast_targets(urls, cap=3)) == 3


def test_empty_and_paramless():
    assert select_dast_targets([], 10) == []
    assert select_dast_targets(["http://h/no-params", "http://h/"], 10) == []


def test_gate():
    assert dast_skip_reason(3, True, True) is None
    assert dast_skip_reason(2, True, True) == "tier_below_3"
    assert dast_skip_reason(3, False, True) == "dast_disabled"
    assert dast_skip_reason(3, True, False) == "no_scan_authorization"
