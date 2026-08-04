"""http_endpoint dedicated policy + catalog + disjunction (Sprint 3, step 2).

Pins the approved contract: the endpoint catalog is the CLASSIFIED endpoint_sensitive subset of the
stock applicable set (never hardcoded); host_only + unknown are excluded; catalog_digest AND
classifier_version participate in policy_hash; disjointness with custom_http is enforced fail-closed
with detector-ids only; determinism regardless of input order. No Nuclei / coverage / provenance.
"""

from __future__ import annotations

import json
from collections import namedtuple

import pytest

from app.services.endpoint_policy import (
    EndpointDisjunctionError,
    build_http_endpoint_policy_bundle,
)
from app.services.endpoint_template_classifier import CLASSIFIER_VERSION
from app.services.rule_catalog import RuleCatalogError, catalog_digest_for_rules
from app.services.rule_revision import compute_rule_revision, content_digest
from app.services.scan_policy import PASS_HTTP_ENDPOINT, build_nuclei_policy_manifest

_File = namedtuple("_File", "relative_path content")
_Rev = namedtuple("_Rev", "digest")
_Snap = namedtuple("_Snap", "revision files")

NUCLEI_VERSION = "3.3.1"
ROOTS = ["http/cves"]
SEVERITY = ["critical", "high"]


def _yaml(data: bytes):
    # Templates are authored as JSON (a subset of YAML) so the test needs no PyYAML.
    return json.loads(data)


def _tmpl(**doc) -> bytes:
    return json.dumps(doc).encode()


# Fixtures: endpoint_sensitive = bare {{BaseURL}}; host_only = appended path or dns; unknown = opaque.
def _endpoint(id_, sev="high"):
    return _tmpl(id=id_, info={"severity": sev, "tags": ["cve"]}, http=[{"method": "GET", "path": ["{{BaseURL}}"]}])


def _host_only_appended(id_, sev="high"):
    return _tmpl(
        id=id_, info={"severity": sev, "tags": ["cve"]}, http=[{"method": "GET", "path": ["{{BaseURL}}/admin"]}]
    )


def _host_only_dns(id_, sev="high"):
    return _tmpl(id=id_, info={"severity": sev, "tags": ["dns"]}, dns=[{"name": "{{FQDN}}", "type": "A"}])


def _unknown_opaque(id_, sev="high"):
    return _tmpl(id=id_, info={"severity": sev, "tags": ["cve"]}, code={"engine": ["py"]})


def _snapshot(files):
    entries = [(rel, content_digest(data)) for rel, data in files]
    rev = compute_rule_revision(entries)
    return _Snap(revision=_Rev(digest=rev), files=[_File(rel, data) for rel, data in files])


def _build(files, *, custom_ids=()):
    return build_http_endpoint_policy_bundle(
        snapshot=_snapshot(files),
        tier=1,
        severity=SEVERITY,
        exclude_tags=[],
        relevant_flags={"interactsh": "false"},
        custom_detector_ids=custom_ids,
        parse_yaml=_yaml,
        nuclei_version=NUCLEI_VERSION,
        template_roots=ROOTS,
    )


_MIXED = [
    ("http/cves/ep-a.yaml", _endpoint("ep-a")),
    ("http/cves/ep-b.yaml", _endpoint("ep-b")),
    ("http/cves/host-append.yaml", _host_only_appended("host-append")),
    ("http/cves/host-dns.yaml", _host_only_dns("host-dns")),
    ("http/cves/opaque.yaml", _unknown_opaque("opaque")),
]


# --- selection: only endpoint_sensitive -----------------------------------------------------------


def test_bundle_keeps_only_endpoint_sensitive():
    b = _build(_MIXED)
    ids = [r.detector_id for r in b.ruleset.rules]
    assert ids == ["ep-a", "ep-b"]  # host_only (append/dns) + unknown (opaque) excluded
    assert b.selected_template_paths == ("http/cves/ep-a.yaml", "http/cves/ep-b.yaml")


def test_selected_paths_match_ruleset_exactly():
    # Invariant: declared catalog == the exact set Sprint 3 will hand to Nuclei.
    b = _build(_MIXED)
    assert set(b.selected_template_paths) == {r.relative_path for r in b.ruleset.rules}
    assert b.ruleset.policy_hash == b.manifest.policy_hash


def test_no_endpoint_sensitive_is_failclosed():
    files = [
        ("http/cves/host-append.yaml", _host_only_appended("h1")),
        ("http/cves/host-dns.yaml", _host_only_dns("h2")),
    ]
    with pytest.raises(RuleCatalogError):
        _build(files)


# --- identity: catalog_digest + classifier_version in policy_hash ---------------------------------


def test_catalog_digest_and_classifier_version_are_in_policy_hash():
    b = _build(_MIXED)
    assert b.classifier_version == CLASSIFIER_VERSION
    assert b.manifest.catalog_digest == b.catalog_digest
    assert b.manifest.classifier_version == CLASSIFIER_VERSION

    # A manifest with the SAME roots/severity/tags/revision but WITHOUT the refinements hashes
    # differently → the refinements genuinely participate in the identity.
    plain = build_nuclei_policy_manifest(
        nuclei_version=NUCLEI_VERSION,
        template_revision=b.manifest.rule_revision,
        pass_name=PASS_HTTP_ENDPOINT,
        tier=1,
        severity=SEVERITY,
        template_roots=ROOTS,
        exclude_tags=[],
        relevant_flags={"interactsh": "false"},
    )
    assert plain.policy_hash != b.manifest.policy_hash


def test_classifier_version_change_changes_policy_hash():
    b = _build(_MIXED)
    bumped = build_nuclei_policy_manifest(
        nuclei_version=NUCLEI_VERSION,
        template_revision=b.manifest.rule_revision,
        pass_name=PASS_HTTP_ENDPOINT,
        tier=1,
        severity=SEVERITY,
        template_roots=ROOTS,
        exclude_tags=[],
        relevant_flags={"interactsh": "false"},
        catalog_digest=b.catalog_digest,
        classifier_version=CLASSIFIER_VERSION + 1,  # a classifier change
    )
    assert bumped.policy_hash != b.manifest.policy_hash


def test_catalog_digest_change_changes_policy_hash():
    b = _build(_MIXED)
    other = build_nuclei_policy_manifest(
        nuclei_version=NUCLEI_VERSION,
        template_revision=b.manifest.rule_revision,
        pass_name=PASS_HTTP_ENDPOINT,
        tier=1,
        severity=SEVERITY,
        template_roots=ROOTS,
        exclude_tags=[],
        relevant_flags={"interactsh": "false"},
        catalog_digest="0" * 64,  # different catalog
        classifier_version=CLASSIFIER_VERSION,
    )
    assert other.policy_hash != b.manifest.policy_hash


# --- determinism ----------------------------------------------------------------------------------


def test_bundle_is_order_independent():
    b1 = _build(_MIXED)
    b2 = _build(list(reversed(_MIXED)))
    assert b1.manifest.policy_hash == b2.manifest.policy_hash
    assert b1.catalog_digest == b2.catalog_digest
    assert b1.selected_template_paths == b2.selected_template_paths


def test_catalog_digest_is_deterministic_and_value_only():
    b = _build(_MIXED)
    # recompute from the ruleset in a different order → identical (the ONE canonical digest)
    assert catalog_digest_for_rules(list(reversed(b.ruleset.rules))) == b.catalog_digest


# --- disjunction with custom_http -----------------------------------------------------------------


def test_disjoint_custom_ids_ok():
    b = _build(_MIXED, custom_ids=["custom-x", "custom-y"])
    assert [r.detector_id for r in b.ruleset.rules] == ["ep-a", "ep-b"]


def test_overlap_with_custom_is_failclosed_ids_only():
    with pytest.raises(EndpointDisjunctionError) as exc:
        _build(_MIXED, custom_ids=["custom-x", "ep-b"])  # ep-b is in the endpoint set
    msg = str(exc.value)
    assert "ep-b" in msg
    # no URL / path leaked in the error
    assert "{{BaseURL}}" not in msg and "http://" not in msg and "https://" not in msg


# --- duplicate detector id --------------------------------------------------------------------------


def test_duplicate_detector_id_is_error():
    files = [
        ("http/cves/dup-1.yaml", _endpoint("same-id")),
        ("http/cves/dup-2.yaml", _endpoint("same-id")),  # same id, different path
    ]
    with pytest.raises(RuleCatalogError):
        _build(files)


# --- observational persistence (policy + catalog only; no coverage / no pass run) -----------------


def test_persist_endpoint_bundle_roundtrip(db_session):
    from app.models.coverage import ScanPolicy, ScanPolicyCatalog, ScanPolicyTemplate
    from app.repositories.coverage_repository import CoverageRepository
    from app.services.endpoint_policy import persist_endpoint_policy_bundle

    b = _build(_MIXED)
    repo = CoverageRepository(db_session)
    ph = persist_endpoint_policy_bundle(repo, b)
    assert ph == b.manifest.policy_hash  # persist_policy accepts the refined manifest

    row = db_session.query(ScanPolicy).filter_by(policy_hash=ph).one()
    # the stored row mirrors the FULL manifest — the refinements are persisted, not just hashed
    assert row.catalog_digest == b.catalog_digest
    assert row.classifier_version == CLASSIFIER_VERSION

    tmpl_ids = {t.detector_id for t in db_session.query(ScanPolicyTemplate).filter_by(policy_hash=ph)}
    assert tmpl_ids == {"ep-a", "ep-b"}  # only the endpoint_sensitive catalog is persisted
    assert db_session.query(ScanPolicyCatalog).filter_by(policy_hash=ph).count() == 1

    # The manifest-embedded catalog_digest EXACTLY equals what the repo stamps + reads back — ONE
    # canonical digest, no drift between the identity and the catalog table.
    assert b.catalog_digest == repo.catalog_build(ph)[1]
    assert b.catalog_digest == repo.catalog_fingerprint(ph)[1]

    # idempotent
    assert persist_endpoint_policy_bundle(repo, b) == ph
