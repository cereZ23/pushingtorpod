"""Scan-policy manifest — pure canonicalisation + deterministic hash (Step 2A).

No DB, no filesystem. ``template_revision`` is an INPUT. These tests lock the
determinism contract that the coverage ledger will rely on to prove a detector was
part of a pass's selected+executed template set.
"""

from __future__ import annotations

import pytest

from app.services.scan_policy import (
    SCHEMA_VERSION,
    ScanPolicyManifest,
    build_scan_policy_manifest,
)


def _m(**kw) -> ScanPolicyManifest:
    base = dict(
        nuclei_version="3.3.1",
        template_revision="rev-abc",
        phase="9",
        pass_name="http_stock",
        tier=1,
        severity=["critical", "high"],
        template_roots=["http/cves", "http/exposures"],
        exclude_tags=["fuzz", "dos"],
        relevant_flags={"dast": "false"},
    )
    base.update(kw)
    return build_scan_policy_manifest(**base)


# --- determinism -------------------------------------------------------------


def test_same_inputs_same_hash():
    assert _m().policy_hash == _m().policy_hash


def test_hash_is_full_sha256_hex():
    h = _m().policy_hash
    assert len(h) == 64  # full SHA-256, not truncated — durable PK/FK/audit identity
    assert all(c in "0123456789abcdef" for c in h)


# --- order independence ------------------------------------------------------


def test_severity_order_independent():
    assert _m(severity=["critical", "high"]).policy_hash == _m(severity=["high", "critical"]).policy_hash


def test_template_roots_order_independent():
    a = _m(template_roots=["http/cves", "http/exposures"]).policy_hash
    b = _m(template_roots=["http/exposures", "http/cves"]).policy_hash
    assert a == b


def test_exclude_tags_order_independent():
    assert _m(exclude_tags=["fuzz", "dos"]).policy_hash == _m(exclude_tags=["dos", "fuzz"]).policy_hash


def test_flags_order_independent():
    a = _m(relevant_flags={"dast": "false", "no-httpx": "true"}).policy_hash
    b = _m(relevant_flags={"no-httpx": "true", "dast": "false"}).policy_hash
    assert a == b


# --- normalisation -----------------------------------------------------------


def test_whitespace_is_stripped():
    assert _m(severity=[" high ", "critical"]).policy_hash == _m(severity=["high", "critical"]).policy_hash


def test_tags_and_severity_are_casefolded():
    assert _m(severity=["HIGH", "Critical"]).policy_hash == _m(severity=["high", "critical"]).policy_hash
    assert _m(exclude_tags=["FUZZ", "DOS"]).policy_hash == _m(exclude_tags=["fuzz", "dos"]).policy_hash


def test_template_root_trailing_slash_ignored():
    assert _m(template_roots=["http/cves/", "http/exposures"]).policy_hash == _m().policy_hash


def test_duplicates_collapse():
    assert _m(severity=["high", "high", "critical"]).policy_hash == _m(severity=["high", "critical"]).policy_hash
    assert _m(template_roots=["http/cves", "http/cves"]).policy_hash == _m(template_roots=["http/cves"]).policy_hash


def test_empty_entries_dropped():
    assert _m(exclude_tags=["fuzz", "", "  ", "dos"]).policy_hash == _m(exclude_tags=["fuzz", "dos"]).policy_hash


def test_template_roots_case_is_significant():
    # Filesystem paths are case-sensitive — do NOT casefold them.
    assert _m(template_roots=["http/CVES"]).policy_hash != _m(template_roots=["http/cves"]).policy_hash


# --- every identity-bearing field changes the hash --------------------------


def test_each_field_changes_the_hash():
    base = _m().policy_hash
    assert _m(nuclei_version="3.4.0").policy_hash != base
    assert _m(template_revision="rev-xyz").policy_hash != base
    assert _m(phase="8").policy_hash != base
    assert _m(pass_name="custom_http").policy_hash != base
    assert _m(tier=3).policy_hash != base
    assert _m(severity=["critical"]).policy_hash != base
    assert _m(template_roots=["http/cves"]).policy_hash != base
    assert _m(exclude_tags=["fuzz"]).policy_hash != base
    assert _m(relevant_flags={"dast": "true"}).policy_hash != base


def test_schema_version_changes_the_hash():
    a = _m().policy_hash
    b = build_scan_policy_manifest(
        nuclei_version="3.3.1",
        template_revision="rev-abc",
        phase="9",
        pass_name="http_stock",
        tier=1,
        severity=["critical", "high"],
        template_roots=["http/cves", "http/exposures"],
        exclude_tags=["fuzz", "dos"],
        relevant_flags={"dast": "false"},
        schema_version="99",
    ).policy_hash
    assert a != b


# --- template_revision is a first-class discriminator (drift → re-scan) ------


def test_template_revision_drift_changes_identity():
    """Same policy, new template content revision → new policy_hash → forces re-scan."""
    v1 = _m(template_revision="sha-v1").policy_hash
    v2 = _m(template_revision="sha-v2").policy_hash
    assert v1 != v2


# --- empties / edges ---------------------------------------------------------


def test_missing_lists_default_to_empty():
    m = build_scan_policy_manifest(
        nuclei_version="3.3.1",
        template_revision="rev-abc",
        phase="9",
        pass_name="dns_network",
        tier=1,
    )
    assert m.severity == () and m.template_roots == () and m.exclude_tags == ()
    assert m.relevant_flags == ()
    assert isinstance(m.policy_hash, str) and len(m.policy_hash) == 64


def test_default_schema_version():
    assert _m().schema_version == SCHEMA_VERSION


def test_tier_coerced_to_int():
    assert _m(tier="2").policy_hash == _m(tier=2).policy_hash


def test_canonical_exposes_normalised_fields():
    c = _m(severity=["HIGH", "critical"], template_roots=["http/cves/"]).canonical()
    assert c["severity"] == ["critical", "high"]
    assert c["template_roots"] == ["http/cves"]
    assert c["schema_version"] == SCHEMA_VERSION


# --- hardening: required inputs are validated (no half-defined identity) ------


@pytest.mark.parametrize("blank", ["", "   ", None])
def test_empty_required_scalars_raise(blank):
    for field_name in ("nuclei_version", "template_revision", "phase"):
        with pytest.raises(ValueError):
            _m(**{field_name: blank})


def test_none_does_not_become_the_string_none():
    # A None required input must ERROR, never silently become "None".
    with pytest.raises(ValueError):
        _m(nuclei_version=None)
    with pytest.raises(ValueError):
        _m(template_revision=None)


def test_unknown_pass_raises():
    with pytest.raises(ValueError):
        _m(pass_name="cve")  # the old wrong name — not a recognised pass
    with pytest.raises(ValueError):
        _m(pass_name="")


def test_known_passes_are_accepted():
    for p in ("custom_http", "http_stock", "cdn_ssl_takeover", "dns_network", "misconfig", "dast"):
        assert len(_m(pass_name=p).policy_hash) == 64


def test_invalid_tier_raises():
    for bad in (0, 4, 99, -1, "x", None):
        with pytest.raises(ValueError):
            _m(tier=bad)


def test_allowed_tiers_accepted():
    for t in (1, 2, 3):
        assert _m(tier=t).policy_hash


# --- hardening: valid by construction (direct ctor cannot bypass canon) -------


def test_direct_constructor_is_canonicalised():
    a = ScanPolicyManifest(
        nuclei_version="3.3.1",
        template_revision="rev-abc",
        phase="9",
        pass_name="http_stock",
        tier=1,
        severity=("high", "critical"),
    )
    b = ScanPolicyManifest(
        nuclei_version="3.3.1",
        template_revision="rev-abc",
        phase="9",
        pass_name="http_stock",
        tier=1,
        severity=("critical", "high"),
    )
    assert a.policy_hash == b.policy_hash
    assert a.severity == ("critical", "high")  # stored form is normalised


def test_direct_constructor_matches_factory():
    # Same identity as _m() but with lists in different order/case → same hash.
    direct = ScanPolicyManifest(
        nuclei_version="3.3.1",
        template_revision="rev-abc",
        phase="9",
        pass_name="http_stock",
        tier=1,
        severity=("HIGH", "critical"),
        template_roots=("http/exposures", "http/cves/"),
        exclude_tags=("DOS", "fuzz"),
        relevant_flags={"dast": False},
    )
    assert direct.policy_hash == _m().policy_hash


def test_direct_constructor_validates():
    with pytest.raises(ValueError):
        ScanPolicyManifest(
            nuclei_version="", template_revision="r", phase="9", pass_name="http_stock", tier=1
        )
    with pytest.raises(ValueError):
        ScanPolicyManifest(
            nuclei_version="3.3.1", template_revision="r", phase="9", pass_name="bogus", tier=1
        )


# --- hardening: boolean-ish flags are canonical ------------------------------


def test_boolean_and_string_flags_are_equivalent():
    base = _m(relevant_flags={"dast": True}).policy_hash
    assert _m(relevant_flags={"dast": "true"}).policy_hash == base
    assert _m(relevant_flags={"dast": "TRUE"}).policy_hash == base
    assert _m(relevant_flags={"dast": "True"}).policy_hash == base


def test_false_variants_are_equivalent_and_differ_from_true():
    f = _m(relevant_flags={"dast": False}).policy_hash
    assert _m(relevant_flags={"dast": "false"}).policy_hash == f
    assert _m(relevant_flags={"dast": "FALSE"}).policy_hash == f
    assert f != _m(relevant_flags={"dast": True}).policy_hash


def test_numeric_flags_normalise_int_and_str():
    assert _m(relevant_flags={"rl": 10}).policy_hash == _m(relevant_flags={"rl": "10"}).policy_hash


def test_none_flag_values_are_dropped():
    assert _m(relevant_flags={"dast": None}).policy_hash == _m(relevant_flags={}).policy_hash
    # a None-valued flag must not change identity vs. the flag being absent
    assert _m(relevant_flags={"dast": "true", "x": None}).policy_hash == _m(relevant_flags={"dast": "true"}).policy_hash


def test_flag_keys_are_trimmed():
    assert _m(relevant_flags={" dast ": "true"}).policy_hash == _m(relevant_flags={"dast": "true"}).policy_hash
