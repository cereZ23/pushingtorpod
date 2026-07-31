"""TLS SAN → asset feedback: scope filtering.

The risky part is the scope gate — certificate SANs on shared hosting can list
OTHER organizations' domains (the myrights.itsright.it box also serves
mail.professionistamilano.it and uppercloud.it). Those must never become the
tenant's assets. _san_candidates_in_scope is pure, so we test it directly.
"""

from types import SimpleNamespace

from app.tasks.pipeline_helpers import _san_candidates_in_scope

SEEDS = {"itsright.it"}


def test_keeps_in_scope_drops_thirdparty_and_wildcards():
    sans = [
        "myrights.itsright.it",
        "vpn.itsright.it",
        "*.itsright.it",  # wildcard -> dropped (no specific host)
        "mail.professionistamilano.it",  # co-tenant on shared cert -> excluded
        "uppercloud.it",  # co-tenant -> excluded
        "",  # empty -> skipped
        "ITSRIGHT.IT",  # apex, case-insensitive -> kept, normalized
    ]
    out = _san_candidates_in_scope(sans, SEEDS, [])
    assert out == ["itsright.it", "myrights.itsright.it", "vpn.itsright.it"]


def test_exclude_scope_rule_wins():
    scopes = [SimpleNamespace(rule_type="exclude", match_type="domain", pattern="vpn.itsright.it")]
    out = _san_candidates_in_scope(["vpn.itsright.it", "app.itsright.it"], SEEDS, scopes)
    assert out == ["app.itsright.it"]


def test_dedup_and_trailing_dot():
    out = _san_candidates_in_scope(["app.itsright.it.", "app.itsright.it"], SEEDS, [])
    assert out == ["app.itsright.it"]


def test_empty_input():
    assert _san_candidates_in_scope(None, SEEDS, []) == []
    assert _san_candidates_in_scope([], SEEDS, []) == []
