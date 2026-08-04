"""Dedicated ``http_endpoint`` scan-policy + applicable-detector catalog (Sprint 3, step 2).

The http_endpoint pass scans crawled endpoints with a REDUCED template set: the ``endpoint_sensitive``
subset of the stock catalog, DERIVED by classifying each applicable template (never a hardcoded
list). This module builds that policy identity + catalog as a PURE bundle and enforces disjointness
with the ``custom_http`` pass. It does NOT run Nuclei, write coverage, or touch provenance — that is
Sprint 3 step 3+.

Identity correctness (the load-bearing point): the applicable set is NOT fully determined by
roots + severity + tags + revision — it also depends on the CLASSIFIER. So both the derived
``catalog_digest`` and the ``classifier_version`` participate in ``policy_hash`` (via explicit
manifest fields). A classifier change therefore yields a NEW policy identity instead of silently
altering the catalog under the old one.

Construction order (per the approved contract):
  1. enumerate the stock applicable templates (with the capability gate);
  2. classify each template;
  3. keep ONLY ``endpoint_sensitive`` (drop host_only + unknown);
  4. compute ``catalog_digest`` over ordered (detector_id, relative_path, content_digest) tuples;
  5. verify disjointness vs custom_http's applicable detector ids (overlap → fail-closed);
  6. build the final manifest, folding catalog_digest + classifier_version into the identity;
  7. verify the final ruleset is non-empty.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Callable, Iterable, Sequence

from app.services.endpoint_template_classifier import (
    CLASSIFIER_VERSION,
    ENDPOINT_SENSITIVE,
    classify_nuclei_template,
)
from app.services.rule_catalog import (
    ApplicableRule,
    ApplicableRuleSet,
    RuleCatalogError,
    enumerate_nuclei_from_snapshot,
)
from app.services.scan_policy import PASS_HTTP_ENDPOINT, ScanPolicyManifest, build_nuclei_policy_manifest


class EndpointDisjunctionError(RuleCatalogError):
    """Raised when http_endpoint and custom_http would share a detector id.

    Carries ONLY the offending detector ids (never a URL or template body).
    """


@dataclass(frozen=True)
class EndpointPolicyBundle:
    """The complete, auditable http_endpoint policy artefact — everything the pass needs, and the
    declared catalog that the future execution must match exactly."""

    manifest: ScanPolicyManifest
    ruleset: ApplicableRuleSet
    selected_template_paths: tuple[str, ...]  # EXACT set Sprint 3 will hand to Nuclei
    catalog_digest: str
    classifier_version: int


def endpoint_catalog_digest(rules: Iterable[ApplicableRule]) -> str:
    """Deterministic digest of the endpoint catalog over ordered (detector_id, relative_path,
    content_digest) tuples. Order-independent (sorted) and value-only — no URL, no template body."""
    payload = json.dumps(
        sorted([r.detector_id, r.relative_path, r.content_digest] for r in rules),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def build_http_endpoint_policy_bundle(
    *,
    snapshot,
    tier: int,
    severity,
    exclude_tags,
    relevant_flags,
    custom_detector_ids: Iterable[str],
    parse_yaml: Callable[[bytes], object],
    nuclei_version: str,
    template_roots: Sequence[str],
) -> EndpointPolicyBundle:
    """Build the http_endpoint policy + catalog bundle (PURE; no DB / Nuclei / coverage).

    Args:
        snapshot: the resolved stock rule snapshot (``ResolvedRuleSnapshot`` — the SAME files whose
            revision anchors the manifest); the endpoint set is a classified subset of it.
        tier / severity / exclude_tags / relevant_flags: the pass's policy inputs (as any nuclei pass).
        custom_detector_ids: the applicable detector ids of the custom_http pass, for the disjunction
            check. The caller enumerates them (custom_http owns its own policy/catalog).
        parse_yaml: injected YAML parser (no import-time dependency here).
        nuclei_version / template_roots: engine version + stock roots for the manifest identity.

    Returns:
        An :class:`EndpointPolicyBundle`.

    Raises:
        EndpointDisjunctionError: any detector id is shared with custom_http.
        RuleCatalogError: no endpoint_sensitive template survives, or a duplicate id appears.
    """
    # 1. Enumerate the stock applicable set. A PRELIMINARY manifest (no catalog_digest yet — it is
    #    derived from THIS enumeration) drives it; only its rule_revision + severity/tags/flags matter.
    prelim = build_nuclei_policy_manifest(
        nuclei_version=nuclei_version,
        template_revision=snapshot.revision.digest,
        pass_name=PASS_HTTP_ENDPOINT,
        tier=tier,
        severity=severity,
        template_roots=template_roots,
        exclude_tags=exclude_tags,
        relevant_flags=relevant_flags,
    )
    applicable = enumerate_nuclei_from_snapshot(prelim, snapshot, parse_yaml=parse_yaml)

    # 2 + 3. Classify each applicable template; keep ONLY endpoint_sensitive (host_only + unknown out).
    by_path = {f.relative_path: f.content for f in snapshot.files}
    endpoint_rules: list[ApplicableRule] = []
    for rule in applicable.rules:
        data = by_path.get(rule.relative_path)
        if data is None:
            raise RuleCatalogError(f"endpoint policy: applicable rule {rule.detector_id!r} missing from snapshot")
        try:
            doc = parse_yaml(bytes(data))
        except Exception as exc:  # already parsed once in enumerate; be defensive
            raise RuleCatalogError(f"endpoint policy: invalid YAML in {rule.relative_path!r}: {exc}") from exc
        if classify_nuclei_template(doc).category == ENDPOINT_SENSITIVE:
            endpoint_rules.append(rule)

    if not endpoint_rules:
        raise RuleCatalogError("endpoint policy: no endpoint_sensitive detectors (fail-closed)")

    # Duplicate detector id → error (enumerate guards the full set; re-assert for the reduced set).
    ids = [r.detector_id for r in endpoint_rules]
    if len(ids) != len(set(ids)):
        dupes = sorted({i for i in ids if ids.count(i) > 1})
        raise RuleCatalogError(f"endpoint policy: duplicate detector id(s) {dupes}")

    # 4. catalog_digest over the reduced set.
    catalog_digest = endpoint_catalog_digest(endpoint_rules)

    # 5. Disjunction with custom_http — fail-closed, ids only (never a URL).
    overlap = sorted(set(ids) & {str(c).strip() for c in custom_detector_ids})
    if overlap:
        raise EndpointDisjunctionError(
            f"http_endpoint and custom_http must have disjoint detector ids; shared: {overlap}"
        )

    # 6. Final manifest — catalog_digest + classifier_version fold into policy_hash so a classifier
    #    change (which can move templates between categories) yields a distinct identity.
    manifest = build_nuclei_policy_manifest(
        nuclei_version=nuclei_version,
        template_revision=snapshot.revision.digest,
        pass_name=PASS_HTTP_ENDPOINT,
        tier=tier,
        severity=severity,
        template_roots=template_roots,
        exclude_tags=exclude_tags,
        relevant_flags=relevant_flags,
        catalog_digest=catalog_digest,
        classifier_version=CLASSIFIER_VERSION,
    )

    # 7. Non-empty ruleset (guaranteed above), re-keyed to the FINAL policy_hash.
    ruleset = ApplicableRuleSet(
        policy_hash=manifest.policy_hash,
        rules=tuple(sorted(endpoint_rules, key=lambda r: r.detector_id)),
    )
    selected_template_paths = tuple(sorted(r.relative_path for r in endpoint_rules))

    return EndpointPolicyBundle(
        manifest=manifest,
        ruleset=ruleset,
        selected_template_paths=selected_template_paths,
        catalog_digest=catalog_digest,
        classifier_version=CLASSIFIER_VERSION,
    )


def persist_endpoint_policy_bundle(repo, bundle: EndpointPolicyBundle) -> str:
    """Persist the bundle's policy + catalog into the coverage ledger (OBSERVATIONAL — no coverage
    row, no pass run). Returns the policy_hash. Idempotent via the repository's insert-if-absent +
    catalog fingerprint. Kept separate from the builder so the identity logic stays pure/testable."""
    repo.persist_policy(bundle.manifest)
    repo.persist_catalog(bundle.ruleset)
    return bundle.manifest.policy_hash
