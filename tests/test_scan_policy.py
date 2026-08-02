"""Scan-policy manifest — pure, engine-generic canonicalisation + deterministic hash (Step 2A).

No DB, no filesystem. ``rule_revision`` is an INPUT. These tests lock the determinism
contract the coverage ledger relies on to prove a detector was part of a pass's
selected+executed rule set — across BOTH engines (nuclei and builtin_misconfig).
"""

from __future__ import annotations

import pytest

from app.services.scan_policy import (
    ENGINE_BUILTIN_MISCONFIG,
    ENGINE_NUCLEI,
    SCHEMA_VERSION,
    ScanPolicyManifest,
    build_misconfig_policy_manifest,
    build_nuclei_policy_manifest,
    build_scan_policy_manifest,
    expected_phase,
)


def _m(**kw) -> ScanPolicyManifest:
    """A valid nuclei http_stock manifest (phase 9). Override any field via kwargs."""
    base = dict(
        engine_name=ENGINE_NUCLEI,
        engine_version="3.3.1",
        rule_revision="rev-abc",
        phase="9",
        pass_name="http_stock",
        tier=1,
        severity=["critical", "high"],
        rule_roots=["http/cves", "http/exposures"],
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


def test_rule_roots_order_independent():
    a = _m(rule_roots=["http/cves", "http/exposures"]).policy_hash
    b = _m(rule_roots=["http/exposures", "http/cves"]).policy_hash
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


def test_rule_root_trailing_slash_ignored():
    assert _m(rule_roots=["http/cves/", "http/exposures"]).policy_hash == _m().policy_hash


def test_duplicates_collapse():
    assert _m(severity=["high", "high", "critical"]).policy_hash == _m(severity=["high", "critical"]).policy_hash
    assert _m(rule_roots=["http/cves", "http/cves"]).policy_hash == _m(rule_roots=["http/cves"]).policy_hash


def test_empty_entries_dropped():
    assert _m(exclude_tags=["fuzz", "", "  ", "dos"]).policy_hash == _m(exclude_tags=["fuzz", "dos"]).policy_hash


def test_rule_roots_case_is_significant():
    # Filesystem paths / control namespaces are case-sensitive — do NOT casefold.
    assert _m(rule_roots=["http/CVES"]).policy_hash != _m(rule_roots=["http/cves"]).policy_hash


# --- every identity-bearing field changes the hash --------------------------


def test_each_field_changes_the_hash():
    base = _m().policy_hash
    assert _m(engine_version="3.4.0").policy_hash != base
    assert _m(rule_revision="rev-xyz").policy_hash != base
    assert _m(pass_name="custom_http").policy_hash != base  # different pass (same phase 9)
    assert _m(tier=3).policy_hash != base
    assert _m(severity=["critical"]).policy_hash != base
    assert _m(rule_roots=["http/cves"]).policy_hash != base
    assert _m(exclude_tags=["fuzz"]).policy_hash != base
    assert _m(relevant_flags={"dast": "true"}).policy_hash != base


def test_schema_version_changes_the_hash():
    a = _m().policy_hash
    b = _m(schema_version="99").policy_hash
    assert a != b


def test_rule_revision_drift_changes_identity():
    """Same policy, new rule content revision → new policy_hash → forces re-scan."""
    assert _m(rule_revision="sha-v1").policy_hash != _m(rule_revision="sha-v2").policy_hash


# --- hardening: required inputs are validated (no half-defined identity) ------


@pytest.mark.parametrize("blank", ["", "   ", None])
def test_empty_required_scalars_raise(blank):
    for field_name in ("engine_version", "rule_revision", "engine_name"):
        with pytest.raises(ValueError):
            _m(**{field_name: blank})


def test_none_does_not_become_the_string_none():
    with pytest.raises(ValueError):
        _m(engine_version=None)
    with pytest.raises(ValueError):
        _m(rule_revision=None)


def test_unknown_pass_raises():
    with pytest.raises(ValueError):
        _m(pass_name="cve")  # the old wrong name — not a recognised pass
    with pytest.raises(ValueError):
        _m(pass_name="")


def test_unknown_engine_raises():
    with pytest.raises(ValueError):
        _m(engine_name="metasploit")


def test_invalid_tier_raises():
    for bad in (0, 4, 99, -1, "x", None):
        with pytest.raises(ValueError):
            _m(tier=bad)


def test_allowed_tiers_accepted():
    for t in (1, 2, 3):
        assert _m(tier=t).policy_hash


# --- engine/phase binding: no semantically-false identity --------------------


def test_pass_binds_phase():
    # misconfig runs in phase 8 — forcing phase 9 is rejected (the review's example).
    with pytest.raises(ValueError):
        build_scan_policy_manifest(
            engine_name=ENGINE_BUILTIN_MISCONFIG,
            engine_version="app-1.0",
            rule_revision="ctrl-rev",
            pass_name="misconfig",
            phase="9",  # wrong — misconfig is phase 8
            tier=1,
        )


def test_pass_binds_engine():
    # misconfig runs on builtin engine — forcing nuclei is rejected.
    with pytest.raises(ValueError):
        build_scan_policy_manifest(
            engine_name=ENGINE_NUCLEI,  # wrong — misconfig is builtin
            engine_version="3.3.1",
            rule_revision="rev",
            pass_name="misconfig",
            phase="8",
            tier=1,
        )


def test_nuclei_pass_cannot_claim_builtin_engine():
    with pytest.raises(ValueError):
        build_scan_policy_manifest(
            engine_name=ENGINE_BUILTIN_MISCONFIG,  # wrong — http_stock is nuclei
            engine_version="app-1.0",
            rule_revision="rev",
            pass_name="http_stock",
            phase="9",
            tier=1,
        )


def test_phase_is_derived_when_omitted():
    assert _m(phase=None).phase == "9"
    assert build_misconfig_policy_manifest(app_version="app-1.0", rule_revision="r", tier=1).phase == "8"


def test_expected_phase_map():
    assert expected_phase("http_stock") == "9"
    assert expected_phase("misconfig") == "8"
    assert expected_phase("dast") == "9d"
    assert expected_phase("nope") is None


# --- engine-specific factories ----------------------------------------------


def test_nuclei_factory_sets_engine_fields():
    m = build_nuclei_policy_manifest(
        nuclei_version="3.3.1", template_revision="tpl-rev", pass_name="http_stock", tier=1
    )
    assert m.engine_name == ENGINE_NUCLEI
    assert m.engine_version == "3.3.1"
    assert m.rule_revision == "tpl-rev"
    assert m.phase == "9"


def test_misconfig_factory_sets_engine_fields():
    m = build_misconfig_policy_manifest(app_version="app-1.2.3", rule_revision="ctrl-hash", tier=1)
    assert m.engine_name == ENGINE_BUILTIN_MISCONFIG
    assert m.engine_version == "app-1.2.3"
    assert m.rule_revision == "ctrl-hash"
    assert m.pass_name == "misconfig"
    assert m.phase == "8"


def test_misconfig_and_nuclei_identities_are_distinct():
    n = build_nuclei_policy_manifest(nuclei_version="v", template_revision="r", pass_name="http_stock", tier=1)
    mc = build_misconfig_policy_manifest(app_version="v", rule_revision="r", tier=1)
    assert n.policy_hash != mc.policy_hash


def test_misconfig_rule_revision_drift_changes_identity():
    """Changing the active misconfig control set → new identity → re-scan (the whole point)."""
    a = build_misconfig_policy_manifest(app_version="app-1", rule_revision="controls-v1", tier=1).policy_hash
    b = build_misconfig_policy_manifest(app_version="app-1", rule_revision="controls-v2", tier=1).policy_hash
    assert a != b


# --- valid by construction (direct ctor cannot bypass canon/validation) ------


def test_direct_constructor_is_canonicalised():
    a = ScanPolicyManifest(
        engine_name=ENGINE_NUCLEI,
        engine_version="3.3.1",
        rule_revision="rev-abc",
        phase="9",
        pass_name="http_stock",
        tier=1,
        severity=("high", "critical"),
    )
    b = ScanPolicyManifest(
        engine_name=ENGINE_NUCLEI,
        engine_version="3.3.1",
        rule_revision="rev-abc",
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
        engine_name="NUCLEI",  # engine name is case-insensitive
        engine_version="3.3.1",
        rule_revision="rev-abc",
        phase="9",
        pass_name="http_stock",
        tier=1,
        severity=("HIGH", "critical"),
        rule_roots=("http/exposures", "http/cves/"),
        exclude_tags=("DOS", "fuzz"),
        relevant_flags={"dast": False},
    )
    assert direct.policy_hash == _m().policy_hash


def test_direct_constructor_validates():
    with pytest.raises(ValueError):
        ScanPolicyManifest(
            engine_name=ENGINE_NUCLEI,
            engine_version="",
            rule_revision="r",
            phase="9",
            pass_name="http_stock",
            tier=1,
        )
    with pytest.raises(ValueError):
        ScanPolicyManifest(
            engine_name=ENGINE_NUCLEI,
            engine_version="3.3.1",
            rule_revision="r",
            phase="9",
            pass_name="bogus",
            tier=1,
        )


# --- boolean-ish flags are canonical -----------------------------------------


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
    assert _m(relevant_flags={"dast": "true", "x": None}).policy_hash == _m(relevant_flags={"dast": "true"}).policy_hash


def test_flag_keys_are_trimmed():
    assert _m(relevant_flags={" dast ": "true"}).policy_hash == _m(relevant_flags={"dast": "true"}).policy_hash


# --- empties / edges ---------------------------------------------------------


def test_missing_lists_default_to_empty():
    m = build_scan_policy_manifest(
        engine_name=ENGINE_NUCLEI,
        engine_version="3.3.1",
        rule_revision="rev-abc",
        pass_name="dns_network",
        tier=1,
    )
    assert m.severity == () and m.rule_roots == () and m.exclude_tags == ()
    assert m.relevant_flags == ()
    assert isinstance(m.policy_hash, str) and len(m.policy_hash) == 64


def test_default_schema_version():
    assert _m().schema_version == SCHEMA_VERSION


def test_tier_coerced_to_int():
    assert _m(tier="2").policy_hash == _m(tier=2).policy_hash


def test_canonical_exposes_normalised_fields():
    c = _m(severity=["HIGH", "critical"], rule_roots=["http/cves/"]).canonical()
    assert c["severity"] == ["critical", "high"]
    assert c["rule_roots"] == ["http/cves"]
    assert c["engine_name"] == ENGINE_NUCLEI
    assert c["schema_version"] == SCHEMA_VERSION
