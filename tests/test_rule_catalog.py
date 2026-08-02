"""Detector applicability catalog — pure, DB-free (Step 2C).

Property under test: given a ScanPolicyManifest and the rule content already resolved
by 2B, deterministically decide whether a detector_id was applicable to that policy.
YAML parsing is injected (here ``json.loads`` over JSON-encoded templates).
"""

from __future__ import annotations

import json

import pytest

from app.services.rule_catalog import (
    ApplicableRuleSet,
    RuleCatalogError,
    enumerate_misconfig_applicable_rules,
    enumerate_nuclei_applicable_rules,
    enumerate_nuclei_from_snapshot,
)
from app.services.rule_revision import (
    compute_misconfig_rule_revision,
    compute_rule_revision,
    content_digest,
    resolve_nuclei_rule_snapshot,
)
from app.services.scan_policy import build_misconfig_policy_manifest, build_nuclei_policy_manifest


# --- helpers -----------------------------------------------------------------


def _tpl(detector_id, severity="high", tags=None, *, with_id=True):
    doc = {"info": {"severity": severity}}
    if with_id:
        doc["id"] = detector_id
    if tags is not None:
        doc["info"]["tags"] = tags
    return json.dumps(doc).encode()


def _revision(files):
    return compute_rule_revision([(rel, content_digest(data)) for rel, data in files])


def _nuclei_manifest(files, *, severity=("critical", "high"), exclude_tags=("fuzz",)):
    return build_nuclei_policy_manifest(
        nuclei_version="3.3.1",
        template_revision=_revision(files),  # manifest carries 2B's digest as identity
        pass_name="http_stock",
        tier=1,
        severity=list(severity),
        template_roots=["http/cves"],
        exclude_tags=list(exclude_tags),
    )


def _enum(files, **mkw):
    manifest = _nuclei_manifest(files, **mkw)
    return enumerate_nuclei_applicable_rules(manifest, files, parse_yaml=json.loads)


# --- Nuclei: inclusion / filtering -------------------------------------------


def test_template_included_by_id():
    files = [("http/cves/a.yaml", _tpl("CVE-A", "high", "cve"))]
    rs = _enum(files)
    assert isinstance(rs, ApplicableRuleSet)
    assert rs.contains("CVE-A")
    (rule,) = rs.rules
    assert rule.engine_name == "nuclei"
    assert rule.relative_path == "http/cves/a.yaml"
    assert rule.severity == "high"
    assert rule.tags == ("cve",)
    assert len(rule.content_digest) == 64


def test_severity_below_whitelist_is_excluded():
    files = [
        ("http/cves/a.yaml", _tpl("CVE-HIGH", "high", "cve")),
        ("http/cves/b.yaml", _tpl("CVE-LOW", "low", "cve")),
    ]
    rs = _enum(files)  # whitelist {critical, high}
    assert rs.contains("CVE-HIGH")
    assert not rs.contains("CVE-LOW")  # in the resolved set, but not applicable


def test_empty_severity_whitelist_includes_all():
    files = [("http/cves/a.yaml", _tpl("CVE-LOW", "low", "cve"))]
    rs = _enum(files, severity=())
    assert rs.contains("CVE-LOW")


def test_missing_severity_is_fail_closed():
    # nuclei requires info.severity — a fail-closed catalog rejects a template without it
    files = [
        ("http/cves/a.yaml", _tpl("CVE-HIGH", "high", "cve")),
        ("http/cves/b.yaml", json.dumps({"id": "NO-SEV", "info": {"tags": "cve"}}).encode()),
    ]
    manifest = _nuclei_manifest(files)
    with pytest.raises(RuleCatalogError):
        enumerate_nuclei_applicable_rules(manifest, files, parse_yaml=json.loads)


def test_integer_id_is_fail_closed():
    # an id must be a real string, not an int coerced implicitly
    files = [("http/cves/a.yaml", json.dumps({"id": 123, "info": {"severity": "high"}}).encode())]
    manifest = _nuclei_manifest(files)
    with pytest.raises(RuleCatalogError):
        enumerate_nuclei_applicable_rules(manifest, files, parse_yaml=json.loads)


def test_exclude_tag_applied():
    files = [
        ("http/cves/a.yaml", _tpl("CVE-CLEAN", "high", "cve")),
        ("http/cves/b.yaml", _tpl("CVE-FUZZ", "high", ["cve", "fuzz"])),
    ]
    rs = _enum(files)  # exclude {fuzz}
    assert rs.contains("CVE-CLEAN")
    assert not rs.contains("CVE-FUZZ")


def test_tags_as_comma_string_and_list_equivalent():
    a = _enum([("http/cves/a.yaml", _tpl("X", "high", "cve,rce"))])
    b = _enum([("http/cves/a.yaml", _tpl("X", "high", ["rce", "cve"]))])
    assert a.rules[0].tags == b.rules[0].tags == ("cve", "rce")


def test_file_order_is_irrelevant():
    files = [
        ("http/cves/a.yaml", _tpl("CVE-A", "high", "cve")),
        ("http/cves/b.yaml", _tpl("CVE-B", "critical", "cve")),
    ]
    manifest = _nuclei_manifest(files)
    a = enumerate_nuclei_applicable_rules(manifest, files, parse_yaml=json.loads)
    b = enumerate_nuclei_applicable_rules(manifest, list(reversed(files)), parse_yaml=json.loads)
    assert a == b  # frozen dataclass, rules sorted by detector_id


def test_same_catalog_is_deterministic():
    files = [("http/cves/a.yaml", _tpl("CVE-A", "high", "cve"))]
    assert _enum(files) == _enum(files)


def test_unknown_detector_is_not_contained():
    rs = _enum([("http/cves/a.yaml", _tpl("CVE-A", "high", "cve"))])
    assert not rs.contains("CVE-NOPE")


# --- Nuclei: fail-closed -----------------------------------------------------


def test_invalid_yaml_is_fail_closed():
    files = [("http/cves/a.yaml", b"{ not valid json/yaml")]
    manifest = build_nuclei_policy_manifest(
        nuclei_version="3.3.1", template_revision="x", pass_name="http_stock", tier=1
    )
    with pytest.raises(RuleCatalogError):
        enumerate_nuclei_applicable_rules(manifest, files, parse_yaml=json.loads)


def test_missing_id_is_fail_closed():
    files = [("http/cves/a.yaml", _tpl("ignored", "high", "cve", with_id=False))]
    manifest = _nuclei_manifest(files)
    with pytest.raises(RuleCatalogError):
        enumerate_nuclei_applicable_rules(manifest, files, parse_yaml=json.loads)


def test_duplicate_detector_id_is_fail_closed():
    files = [
        ("http/cves/a.yaml", _tpl("DUP", "high", "cve")),
        ("http/cves/b.yaml", _tpl("DUP", "critical", "cve")),
    ]
    manifest = _nuclei_manifest(files)
    with pytest.raises(RuleCatalogError):
        enumerate_nuclei_applicable_rules(manifest, files, parse_yaml=json.loads)


def test_uninterpretable_severity_is_fail_closed():
    files = [("http/cves/a.yaml", json.dumps({"id": "X", "info": {"severity": ["high"]}}).encode())]
    manifest = _nuclei_manifest(files)
    with pytest.raises(RuleCatalogError):
        enumerate_nuclei_applicable_rules(manifest, files, parse_yaml=json.loads)


def test_content_change_disagreeing_with_revision_is_fail_closed():
    files = [("http/cves/a.yaml", _tpl("CVE-A", "high", "cve"))]
    manifest = _nuclei_manifest(files)  # rule_revision pinned to the original bytes
    tampered = [("http/cves/a.yaml", _tpl("CVE-A", "high", "cve,extra"))]  # different bytes
    with pytest.raises(RuleCatalogError):
        enumerate_nuclei_applicable_rules(manifest, tampered, parse_yaml=json.loads)


def test_zero_applicable_is_fail_closed():
    # every template excluded by tag → empty applicable set → error
    files = [("http/cves/a.yaml", _tpl("CVE-FUZZ", "high", "fuzz"))]
    manifest = _nuclei_manifest(files)
    with pytest.raises(RuleCatalogError):
        enumerate_nuclei_applicable_rules(manifest, files, parse_yaml=json.loads)


def test_misconfig_policy_rejected_by_nuclei_enumerator():
    files = [("http/cves/a.yaml", _tpl("CVE-A", "high", "cve"))]
    mc = build_misconfig_policy_manifest(app_version="app-1", rule_revision="x", tier=1)
    with pytest.raises(RuleCatalogError):
        enumerate_nuclei_applicable_rules(mc, files, parse_yaml=json.loads)


# --- misconfig ---------------------------------------------------------------


def _mc_manifest(active_controls):
    # revision over the full active controls (id + severity + tags + config)
    rev = compute_misconfig_rule_revision(active_controls)
    return build_misconfig_policy_manifest(app_version="app-1", rule_revision=rev, tier=1)


def test_misconfig_enabled_included_disabled_excluded():
    controls = [
        {"id": "HDR-001", "enabled": True, "severity": "medium", "config": {"x": 1}},
        {"id": "HDR-002", "enabled": False},
    ]
    manifest = _mc_manifest([controls[0]])  # revision over the active control only
    rs = enumerate_misconfig_applicable_rules(manifest, controls)
    assert rs.contains("HDR-001")
    assert not rs.contains("HDR-002")
    assert rs.rules[0].engine_name == "builtin_misconfig"
    assert rs.rules[0].severity == "medium"


def test_misconfig_detector_id_is_control_id():
    controls = [{"id": "HDR-001", "enabled": True, "config": {}}]
    manifest = _mc_manifest(controls)
    rs = enumerate_misconfig_applicable_rules(manifest, controls)
    assert rs.rules[0].detector_id == "HDR-001"


def test_misconfig_duplicate_active_id_is_fail_closed():
    controls = [
        {"id": "HDR-001", "enabled": True, "config": {}},
        {"id": "HDR-001", "enabled": True, "config": {}},
    ]
    manifest = _mc_manifest([controls[0]])
    with pytest.raises(RuleCatalogError):
        enumerate_misconfig_applicable_rules(manifest, controls)


def test_misconfig_empty_id_is_fail_closed():
    controls = [{"id": "  ", "enabled": True, "config": {}}]
    manifest = build_misconfig_policy_manifest(app_version="app-1", rule_revision="x", tier=1)
    with pytest.raises(RuleCatalogError):
        enumerate_misconfig_applicable_rules(manifest, controls)


def test_misconfig_no_active_controls_is_fail_closed():
    controls = [{"id": "HDR-001", "enabled": False}]
    manifest = build_misconfig_policy_manifest(app_version="app-1", rule_revision="x", tier=1)
    with pytest.raises(RuleCatalogError):
        enumerate_misconfig_applicable_rules(manifest, controls)


def test_misconfig_revision_disagreement_is_fail_closed():
    controls = [{"id": "HDR-001", "enabled": True, "config": {"x": 1}}]
    # manifest revision computed over a DIFFERENT config → disagreement
    bad = build_misconfig_policy_manifest(
        app_version="app-1",
        rule_revision=compute_misconfig_rule_revision([{"id": "HDR-001", "config": {"x": 999}}]),
        tier=1,
    )
    with pytest.raises(RuleCatalogError):
        enumerate_misconfig_applicable_rules(bad, controls)


def test_nuclei_policy_rejected_by_misconfig_enumerator():
    controls = [{"id": "HDR-001", "enabled": True, "config": {}}]
    nuclei = build_nuclei_policy_manifest(nuclei_version="3.3.1", template_revision="x", pass_name="http_stock", tier=1)
    with pytest.raises(RuleCatalogError):
        enumerate_misconfig_applicable_rules(nuclei, controls)


def test_misconfig_deterministic():
    controls = [{"id": "HDR-001", "enabled": True, "config": {"x": 1}}]
    manifest = _mc_manifest(controls)
    assert enumerate_misconfig_applicable_rules(manifest, controls) == enumerate_misconfig_applicable_rules(
        manifest, controls
    )


def test_misconfig_severity_is_part_of_identity():
    # a manifest pinned to severity "medium" must NOT accept the same control at "high"
    c_med = [{"id": "HDR-001", "enabled": True, "severity": "medium", "config": {}}]
    c_high = [{"id": "HDR-001", "enabled": True, "severity": "high", "config": {}}]
    manifest_med = _mc_manifest(c_med)
    assert enumerate_misconfig_applicable_rules(manifest_med, c_med).contains("HDR-001")
    with pytest.raises(RuleCatalogError):
        enumerate_misconfig_applicable_rules(manifest_med, c_high)


def test_misconfig_tags_are_part_of_identity():
    c1 = [{"id": "HDR-001", "enabled": True, "tags": ["headers"], "config": {}}]
    c2 = [{"id": "HDR-001", "enabled": True, "tags": ["headers", "http"], "config": {}}]
    manifest = _mc_manifest(c1)
    with pytest.raises(RuleCatalogError):
        enumerate_misconfig_applicable_rules(manifest, c2)


# --- real YAML parser + single-read snapshot ---------------------------------


def test_nuclei_enumeration_with_real_yaml_safe_load():
    yaml = pytest.importorskip("yaml")
    tpl = b"id: CVE-REAL\ninfo:\n  severity: high\n  tags: cve,rce\n"
    files = [("http/cves/real.yaml", tpl)]
    manifest = _nuclei_manifest(files)
    rs = enumerate_nuclei_applicable_rules(manifest, files, parse_yaml=yaml.safe_load)
    assert rs.contains("CVE-REAL")
    assert rs.rules[0].tags == ("cve", "rce")


def test_enumerate_from_snapshot_single_read(tmp_path):
    (tmp_path / "http/cves").mkdir(parents=True)
    (tmp_path / "http/cves/a.yaml").write_bytes(_tpl("CVE-A", "high", "cve"))
    (tmp_path / "http/cves/b.yaml").write_bytes(_tpl("CVE-B", "critical", "cve"))
    snap = resolve_nuclei_rule_snapshot(str(tmp_path), ["http/cves"])
    manifest = build_nuclei_policy_manifest(
        nuclei_version="3.3.1",
        template_revision=snap.revision.digest,  # manifest identity == the snapshot's revision
        pass_name="http_stock",
        tier=1,
        severity=["critical", "high"],
        template_roots=["http/cves"],
    )
    rs = enumerate_nuclei_from_snapshot(manifest, snap, parse_yaml=json.loads)
    assert rs.contains("CVE-A") and rs.contains("CVE-B")
