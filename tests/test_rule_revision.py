"""Rule-revision resolver — pure content digest + fail-closed filesystem I/O (Step 2B).

The version runner and (where useful) ``read_bytes`` are injected; the filesystem
tests use a real ``tmp_path`` so symlink / escape / unreadable semantics are exercised
for real. Locks the change-visible, order-independent, fail-closed contract.
"""

from __future__ import annotations

import os

import pytest

from app.services.rule_revision import (
    CompletedCommand,
    RuleResolutionError,
    RuleRevision,
    compute_misconfig_rule_revision,
    compute_rule_revision,
    content_digest,
    parse_nuclei_version,
    resolve_nuclei_rule_revision,
    resolve_nuclei_version,
)

# --- content digest ----------------------------------------------------------


def test_content_digest_is_full_sha256():
    d = content_digest(b"template body")
    assert len(d) == 64 and all(c in "0123456789abcdef" for c in d)


def test_content_digest_changes_with_bytes():
    assert content_digest(b"a") != content_digest(b"b")


# --- compute_rule_revision (pure) --------------------------------------------


def _entries(*pairs):
    return [(p, content_digest(b)) for p, b in pairs]


def test_rule_revision_deterministic():
    e = _entries(("http/cves/a.yaml", b"A"), ("http/cves/b.yaml", b"B"))
    assert compute_rule_revision(e) == compute_rule_revision(e)


def test_rule_revision_order_independent():
    a = _entries(("x.yaml", b"1"), ("y.yaml", b"2"))
    b = _entries(("y.yaml", b"2"), ("x.yaml", b"1"))
    assert compute_rule_revision(a) == compute_rule_revision(b)


def test_rule_revision_changes_with_content():
    assert compute_rule_revision(_entries(("x.yaml", b"1"))) != compute_rule_revision(_entries(("x.yaml", b"2")))


def test_rule_revision_changes_with_path():
    assert compute_rule_revision(_entries(("x.yaml", b"1"))) != compute_rule_revision(_entries(("y.yaml", b"1")))


def test_rule_revision_path_normalised():
    assert compute_rule_revision(_entries(("./http/a.yaml", b"A"))) == compute_rule_revision(_entries(("http/a.yaml", b"A")))


def test_rule_revision_empty_is_fail_closed():
    with pytest.raises(RuleResolutionError):
        compute_rule_revision([])


def test_rule_revision_is_versioned_full_sha256():
    assert len(compute_rule_revision(_entries(("a.yaml", b"A")))) == 64


def test_adding_a_file_changes_revision():
    one = _entries(("a.yaml", b"A"))
    two = _entries(("a.yaml", b"A"), ("b.yaml", b"B"))
    assert compute_rule_revision(one) != compute_rule_revision(two)


# --- misconfig revision (pure) -----------------------------------------------


def test_misconfig_revision_order_independent():
    a = compute_misconfig_rule_revision([{"id": "c2", "config": {"x": 1}}, {"id": "c1"}])
    b = compute_misconfig_rule_revision([{"id": "c1"}, {"id": "c2", "config": {"x": 1}}])
    assert a == b


def test_misconfig_revision_config_key_order_independent():
    a = compute_misconfig_rule_revision([{"id": "c1", "config": {"a": 1, "b": 2}}])
    b = compute_misconfig_rule_revision([{"id": "c1", "config": {"b": 2, "a": 1}}])
    assert a == b


def test_misconfig_revision_accepts_pairs():
    a = compute_misconfig_rule_revision([("c1", {"x": 1})])
    b = compute_misconfig_rule_revision([{"id": "c1", "config": {"x": 1}}])
    assert a == b


def test_misconfig_revision_changes_when_control_toggled():
    a = compute_misconfig_rule_revision([{"id": "c1"}, {"id": "c2"}])
    b = compute_misconfig_rule_revision([{"id": "c1"}])
    assert a != b


def test_misconfig_revision_changes_with_config():
    a = compute_misconfig_rule_revision([{"id": "c1", "config": {"threshold": 5}}])
    b = compute_misconfig_rule_revision([{"id": "c1", "config": {"threshold": 9}}])
    assert a != b


def test_misconfig_revision_rejects_duplicate_ids():
    with pytest.raises(RuleResolutionError):
        compute_misconfig_rule_revision([{"id": "c1"}, {"id": "c1"}])


def test_misconfig_revision_rejects_empty_id():
    with pytest.raises(RuleResolutionError):
        compute_misconfig_rule_revision([{"id": "  "}])


def test_misconfig_revision_empty_controls_is_fail_closed():
    with pytest.raises(RuleResolutionError):
        compute_misconfig_rule_revision([])


# --- filesystem resolver (real tmp_path) -------------------------------------


def _tree(base):
    (base / "http/cves/sub").mkdir(parents=True)
    (base / "http/exposures").mkdir(parents=True)
    (base / "http/cves/CVE-1.yaml").write_bytes(b"one")
    (base / "http/cves/sub/CVE-2.yaml").write_bytes(b"two")
    (base / "http/exposures/panel.yml").write_bytes(b"three")
    (base / "http/exposures/README.md").write_bytes(b"ignore me")


def test_resolver_happy_path(tmp_path):
    _tree(tmp_path)
    rr = resolve_nuclei_rule_revision(str(tmp_path), ["http/cves", "http/exposures"])
    assert isinstance(rr, RuleRevision)
    assert rr.rule_count == 3  # README.md excluded, .yml included
    assert rr.total_bytes == len(b"one") + len(b"two") + len(b"three")
    assert rr.relative_paths == (
        "http/cves/CVE-1.yaml",
        "http/cves/sub/CVE-2.yaml",
        "http/exposures/panel.yml",
    )
    assert len(rr.digest) == 64


def test_resolver_only_selected_roots(tmp_path):
    _tree(tmp_path)
    rr = resolve_nuclei_rule_revision(str(tmp_path), ["http/cves"])
    assert all(p.startswith("http/cves/") for p in rr.relative_paths)
    assert rr.rule_count == 2


def test_resolver_root_order_does_not_change_digest(tmp_path):
    _tree(tmp_path)
    a = resolve_nuclei_rule_revision(str(tmp_path), ["http/cves", "http/exposures"]).digest
    b = resolve_nuclei_rule_revision(str(tmp_path), ["http/exposures", "http/cves"]).digest
    assert a == b


def test_resolver_one_byte_edit_moves_digest(tmp_path):
    _tree(tmp_path)
    before = resolve_nuclei_rule_revision(str(tmp_path), ["http/exposures"]).digest
    (tmp_path / "http/exposures/panel.yml").write_bytes(b"threeX")
    assert resolve_nuclei_rule_revision(str(tmp_path), ["http/exposures"]).digest != before


def test_resolver_rename_moves_digest(tmp_path):
    _tree(tmp_path)
    before = resolve_nuclei_rule_revision(str(tmp_path), ["http/exposures"]).digest
    os.rename(tmp_path / "http/exposures/panel.yml", tmp_path / "http/exposures/panel2.yml")
    assert resolve_nuclei_rule_revision(str(tmp_path), ["http/exposures"]).digest != before


def test_resolver_removal_moves_digest(tmp_path):
    _tree(tmp_path)
    before = resolve_nuclei_rule_revision(str(tmp_path), ["http/cves"]).digest
    os.remove(tmp_path / "http/cves/sub/CVE-2.yaml")
    assert resolve_nuclei_rule_revision(str(tmp_path), ["http/cves"]).digest != before


def test_resolver_missing_base_is_fail_closed(tmp_path):
    with pytest.raises(RuleResolutionError):
        resolve_nuclei_rule_revision(str(tmp_path / "nope"), ["http/cves"])


def test_resolver_missing_root_is_fail_closed(tmp_path):
    _tree(tmp_path)
    with pytest.raises(RuleResolutionError):
        resolve_nuclei_rule_revision(str(tmp_path), ["http/does-not-exist"])


def test_resolver_empty_selection_is_fail_closed(tmp_path):
    (tmp_path / "http/cves").mkdir(parents=True)  # dir exists but no rule files
    with pytest.raises(RuleResolutionError):
        resolve_nuclei_rule_revision(str(tmp_path), ["http/cves"])


def test_resolver_root_escaping_base_is_fail_closed(tmp_path):
    _tree(tmp_path)
    with pytest.raises(RuleResolutionError):
        resolve_nuclei_rule_revision(str(tmp_path / "http"), ["../.."])


def test_resolver_unreadable_file_is_fail_closed(tmp_path):
    _tree(tmp_path)

    def boom(path):
        raise PermissionError("nope")

    with pytest.raises(RuleResolutionError):
        resolve_nuclei_rule_revision(str(tmp_path), ["http/cves"], read_bytes=boom)


def test_resolver_symlink_inside_base_is_allowed(tmp_path):
    _tree(tmp_path)
    # a symlink to a file that stays under base_dir is fine; its logical path counts
    os.symlink(tmp_path / "http/cves/CVE-1.yaml", tmp_path / "http/exposures/alias.yaml")
    rr = resolve_nuclei_rule_revision(str(tmp_path), ["http/exposures"])
    assert "http/exposures/alias.yaml" in rr.relative_paths


def test_resolver_symlink_escaping_base_is_fail_closed(tmp_path):
    _tree(tmp_path)
    outside = tmp_path.parent / "outside-secret.yaml"
    outside.write_bytes(b"secret")
    os.symlink(outside, tmp_path / "http/exposures/leak.yaml")
    with pytest.raises(RuleResolutionError):
        resolve_nuclei_rule_revision(str(tmp_path), ["http/exposures"])


def test_resolver_ambiguous_paths_same_file_is_fail_closed(tmp_path):
    _tree(tmp_path)
    # two distinct logical paths (real file + symlink alias) resolving to one file
    os.symlink(tmp_path / "http/cves/CVE-1.yaml", tmp_path / "http/cves/alias.yaml")
    with pytest.raises(RuleResolutionError):
        resolve_nuclei_rule_revision(str(tmp_path), ["http/cves"])


def test_resolver_overlapping_roots_same_logical_path_deduped(tmp_path):
    _tree(tmp_path)
    # "" (whole base) and "http/cves" both surface http/cves/* at the SAME logical
    # path — counted once, not treated as ambiguous.
    rr = resolve_nuclei_rule_revision(str(tmp_path), ["", "http/cves"])
    assert rr.relative_paths.count("http/cves/CVE-1.yaml") == 1


# --- engine version resolver (injected runner) -------------------------------


def test_parse_nuclei_version_from_inf_line():
    assert parse_nuclei_version("[INF] Nuclei Engine Version: v3.3.1") == "3.3.1"


def test_parse_nuclei_version_plain_semver():
    assert parse_nuclei_version("3.3.1") == "3.3.1"


def test_parse_nuclei_version_strips_leading_v():
    assert parse_nuclei_version("v3.3.1") == "3.3.1"  # v3.3.1 and 3.3.1 must not diverge


def test_parse_nuclei_version_strips_ansi():
    assert parse_nuclei_version("\x1b[36m[INF]\x1b[0m Nuclei Engine Version: v3.3.1\x1b[0m") == "3.3.1"


def test_parse_nuclei_version_with_prerelease():
    assert parse_nuclei_version("v3.4.0-dev") == "3.4.0-dev"


def test_parse_nuclei_version_unparseable_is_fail_closed():
    with pytest.raises(RuleResolutionError):
        parse_nuclei_version("no version here")


def test_resolve_version_from_stdout():
    assert resolve_nuclei_version(lambda argv: CompletedCommand(0, stdout="v3.3.1")) == "3.3.1"


def test_resolve_version_from_stderr():
    # nuclei prints its banner to stderr
    assert resolve_nuclei_version(lambda argv: CompletedCommand(0, stderr="[INF] Nuclei Engine Version: v3.3.1")) == "3.3.1"


def test_resolve_version_nonzero_exit_is_fail_closed():
    with pytest.raises(RuleResolutionError):
        resolve_nuclei_version(lambda argv: CompletedCommand(1, stderr="v3.3.1"))


def test_resolve_version_runner_failure_is_fail_closed():
    def boom(argv):
        raise FileNotFoundError("nuclei: command not found")

    with pytest.raises(RuleResolutionError):
        resolve_nuclei_version(boom)


def test_resolve_version_empty_output_is_fail_closed():
    with pytest.raises(RuleResolutionError):
        resolve_nuclei_version(lambda argv: CompletedCommand(0, stdout="", stderr=""))
