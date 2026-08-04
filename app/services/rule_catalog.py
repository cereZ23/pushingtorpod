"""Detector applicability catalog — which detectors a policy actually runs.

Step 2B ([[rule_revision]]) proves *content identity* (did the rule bytes change?).
This module proves a different property: given a manifest ([[scan_policy]]) and the
real rule content, is a specific ``detector_id`` (a nuclei template id, or a misconfig
control id) *applicable* to that policy — i.e. selected AND not filtered out?

That is exactly what a per-detector auto-close needs: a finding may be closed only if
its detector was provably in the pass's applicable set for a healthy scan.

Pure and DB-free. YAML parsing is injected. Severity/tags normalisation and the
misconfig canonical structure are SHARED with 2B (imported), so the catalog can never
disagree with the revision/identity. Fail-closed: an invalid template, a
missing/duplicate id, an uninterpretable severity/tags field, a content digest that
disagrees with 2B, or an empty applicable set all raise ``RuleCatalogError`` — an
unsupported case makes the policy NON-authorising rather than guessing Nuclei.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Callable, Optional, Sequence

from app.services.rule_revision import (
    MisconfigRuleSnapshot,
    ResolvedRuleSnapshot,
    RuleResolutionError,
    canonical_active_control,
    compute_misconfig_rule_revision,
    compute_rule_revision,
    content_digest,
    normalize_severity,
    normalize_tags,
)
from app.services.scan_policy import ENGINE_BUILTIN_MISCONFIG, ENGINE_NUCLEI, ScanPolicyManifest


class RuleCatalogError(Exception):
    """Raised when applicability cannot be proven (fail-closed → non-authorising)."""


@dataclass(frozen=True)
class ApplicableRule:
    engine_name: str
    detector_id: str
    relative_path: str
    content_digest: str
    severity: Optional[str]
    tags: tuple[str, ...]


@dataclass(frozen=True)
class ApplicableRuleSet:
    policy_hash: str
    rules: tuple[ApplicableRule, ...]

    def contains(self, detector_id: str) -> bool:
        needle = str(detector_id).strip()
        return any(r.detector_id == needle for r in self.rules)


def _make_ruleset(policy_hash: str, rules: list[ApplicableRule]) -> ApplicableRuleSet:
    if not rules:
        raise RuleCatalogError("no applicable detectors for policy (fail-closed)")
    ordered = tuple(sorted(rules, key=lambda r: r.detector_id))
    return ApplicableRuleSet(policy_hash=policy_hash, rules=ordered)


# --- Nuclei capabilities (runtime-applicable gate) --------------------------

CAP_CODE = "code"
CAP_HEADLESS = "headless"
CAP_DAST = "dast"
CAP_SELF_CONTAINED = "self_contained"
CAP_INTERACTSH = "interactsh"
NUCLEI_CAPABILITIES = (CAP_CODE, CAP_HEADLESS, CAP_DAST, CAP_SELF_CONTAINED, CAP_INTERACTSH)


def nuclei_required_capabilities(doc: Mapping, raw: bytes | bytearray) -> frozenset:
    """The nuclei capabilities a template REQUIRES to actually execute/match. A policy that does not
    enable one of these (via ``relevant_flags``) does not run the template, so it is not
    runtime-applicable and must be kept out of the coverage catalog.

    - ``code`` / ``headless``: opt-in protocols nuclei disables by default (need -code / -headless);
    - ``dast``: a ``fuzzing`` block or a dast/fuzz tag (only run with -dast);
    - ``self_contained``: the template ignores the scanned asset (its coverage per-asset is moot);
    - ``interactsh``: the template relies on OAST callbacks (disabled by -ni → it can never match).
    """
    caps = set()
    if doc.get("code") is not None:
        caps.add(CAP_CODE)
    if doc.get("headless") is not None:
        caps.add(CAP_HEADLESS)
    info = doc.get("info") if isinstance(doc.get("info"), Mapping) else {}
    try:
        tags = set(normalize_tags(info.get("tags"))) if isinstance(info, Mapping) else set()
    except RuleResolutionError:
        tags = set()
    has_fuzz = any(
        isinstance(r, Mapping) and r.get("fuzzing") is not None
        for key in ("http", "requests")
        if isinstance(doc.get(key), list)
        for r in doc[key]
    )
    if has_fuzz or {"dast", "fuzz"} & tags:
        caps.add(CAP_DAST)
    if doc.get("self-contained") is True or (isinstance(info, Mapping) and info.get("self-contained") is True):
        caps.add(CAP_SELF_CONTAINED)
    if isinstance(raw, (bytes, bytearray)) and b"interactsh" in bytes(raw).lower():
        caps.add(CAP_INTERACTSH)
    return frozenset(caps)


# --- Nuclei enumeration ------------------------------------------------------


def enumerate_nuclei_applicable_rules(
    manifest: ScanPolicyManifest,
    files: Sequence[tuple[str, bytes]],
    *,
    parse_yaml: Callable[[bytes], object],
) -> ApplicableRuleSet:
    """Enumerate the Nuclei templates applicable to ``manifest``.

    ``files`` are the (relative_path, content_bytes) pairs ALREADY resolved by 2B (see
    ``enumerate_nuclei_from_snapshot`` for the single-read path). The revision is
    recomputed from those exact bytes and must equal ``manifest.rule_revision``; a
    mismatch means the files are inconsistent with the policy → fail-closed. Then each
    template is parsed and filtered by the policy severity whitelist + exclude tags.
    A nuclei template MUST carry a string ``id`` and an ``info.severity``.
    """
    if manifest.engine_name != ENGINE_NUCLEI:
        raise RuleCatalogError(f"nuclei enumeration requires a nuclei policy, got {manifest.engine_name!r}")

    enabled_caps = frozenset(k for k, v in manifest.relevant_flags if str(v).lower() == "true")
    entries: list[tuple[str, str]] = []
    docs: dict[str, tuple[str, Mapping, bytes]] = {}  # rel_path -> (digest, parsed doc, raw bytes)
    for rel, data in files:
        if not isinstance(data, (bytes, bytearray)):
            raise RuleCatalogError(f"template {rel!r}: content must be bytes, got {type(data).__name__}")
        data = bytes(data)
        if rel in docs:
            raise RuleCatalogError(f"duplicate file path {rel!r}")
        digest = content_digest(data)
        entries.append((rel, digest))
        try:
            doc = parse_yaml(data)
        except Exception as exc:
            raise RuleCatalogError(f"invalid YAML in template {rel!r}: {exc}") from exc
        if not isinstance(doc, Mapping):
            raise RuleCatalogError(f"template {rel!r} is not a mapping")
        docs[rel] = (digest, doc, data)

    # Consistency with 2B: the exact bytes must reproduce the policy's rule_revision.
    try:
        recomputed = compute_rule_revision(entries)
    except RuleResolutionError as exc:
        raise RuleCatalogError(f"rule revision recompute failed: {exc}") from exc
    if recomputed != manifest.rule_revision:
        raise RuleCatalogError("template content disagrees with the policy rule_revision (fail-closed)")

    sev_whitelist = set(manifest.severity)
    exclude = set(manifest.exclude_tags)
    rules: list[ApplicableRule] = []
    id_to_path: dict[str, str] = {}
    for rel in sorted(docs):
        digest, doc, data = docs[rel]
        raw_id = doc.get("id")
        if not isinstance(raw_id, str) or not raw_id.strip():  # must be a real string id
            raise RuleCatalogError(f"template {rel!r} has no valid string id")
        detector_id = raw_id.strip()
        prev = id_to_path.get(detector_id)
        if prev is not None and prev != rel:
            raise RuleCatalogError(f"duplicate detector id {detector_id!r} in {prev!r} and {rel!r}")
        id_to_path[detector_id] = rel

        info = doc.get("info") or {}
        if not isinstance(info, Mapping):
            raise RuleCatalogError(f"template {rel!r} has an uninterpretable info block")
        if info.get("severity") is None:  # nuclei requires info.severity — a fail-closed catalog rejects
            raise RuleCatalogError(f"template {rel!r} has no severity")
        try:
            severity = normalize_severity(info.get("severity"))
            tags = normalize_tags(info.get("tags"))
        except RuleResolutionError as exc:
            raise RuleCatalogError(f"template {rel!r}: {exc}") from exc

        if sev_whitelist and severity not in sev_whitelist:
            continue  # not selected by the policy severity gate
        if exclude & set(tags):
            continue  # excluded by tag
        # Capability gate (runtime-applicable): a template that REQUIRES a nuclei capability the
        # policy does not enable (relevant_flags) is not actually executed / can't match, so it must
        # NOT sit in the catalog and authorise a future auto-close. code/headless need opt-in flags
        # nuclei disables by default; dast = fuzzing; self_contained ignores the scanned asset;
        # interactsh needs OAST (off via -ni → no OOB match). Fail-closed: unknown-enabled → excluded.
        required_caps = nuclei_required_capabilities(doc, data)
        if required_caps - enabled_caps:
            continue
        rules.append(
            ApplicableRule(
                engine_name=ENGINE_NUCLEI,
                detector_id=detector_id,
                relative_path=rel,
                content_digest=digest,
                severity=severity,
                tags=tags,
            )
        )

    return _make_ruleset(manifest.policy_hash, rules)


def enumerate_nuclei_from_snapshot(
    manifest: ScanPolicyManifest,
    snapshot: ResolvedRuleSnapshot,
    *,
    parse_yaml: Callable[[bytes], object],
) -> ApplicableRuleSet:
    """Single-read path: enumerate directly from the 2B snapshot's retained bytes, so
    the catalog and the revision observe the exact same files."""
    return enumerate_nuclei_applicable_rules(
        manifest, [(f.relative_path, f.content) for f in snapshot.files], parse_yaml=parse_yaml
    )


# --- misconfig enumeration ---------------------------------------------------


def _control_digest(canon_control: Mapping) -> str:
    """Per-control content digest over the SAME canonical structure 2B hashes."""
    payload = json.dumps(canon_control, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def enumerate_misconfig_from_snapshot(
    manifest: ScanPolicyManifest,
    snapshot: MisconfigRuleSnapshot,
) -> ApplicableRuleSet:
    """Single-snapshot path: enumerate the applicable misconfig controls from the captured
    active-control snapshot, so the catalog and the revision observe the exact same set."""
    return enumerate_misconfig_applicable_rules(manifest, snapshot.controls)


def enumerate_misconfig_applicable_rules(
    manifest: ScanPolicyManifest,
    controls: Sequence[Mapping],
) -> ApplicableRuleSet:
    """Enumerate the applicable built-in misconfig controls for ``manifest``.

    Only enabled controls count; ids must be non-empty and unique; the detector id IS
    the canonical control id. severity/tags are part of each control's canonical
    identity (shared with 2B), so editing them moves the revision. The revision
    recomputed over the active controls must equal ``manifest.rule_revision``, else
    fail-closed. Zero active controls → error.
    """
    if manifest.engine_name != ENGINE_BUILTIN_MISCONFIG:
        raise RuleCatalogError(f"misconfig enumeration requires a misconfig policy, got {manifest.engine_name!r}")

    active: list[Mapping] = []
    seen: set[str] = set()
    for c in controls or []:
        if not isinstance(c, Mapping):
            raise RuleCatalogError(f"misconfig control is not a mapping: {c!r}")
        if not bool(c.get("enabled", True)):
            continue  # disabled → not applicable
        try:
            canon = canonical_active_control(c)
        except RuleResolutionError as exc:
            raise RuleCatalogError(f"misconfig control: {exc}") from exc
        cid = canon["id"]
        if cid in seen:
            raise RuleCatalogError(f"duplicate misconfig control id {cid!r}")
        seen.add(cid)
        active.append(c)

    if not active:
        raise RuleCatalogError("no active misconfig controls (fail-closed)")

    # Consistency with 2B: the active id+severity+tags+config set must reproduce the revision.
    try:
        revision = compute_misconfig_rule_revision(active)
    except RuleResolutionError as exc:
        raise RuleCatalogError(f"misconfig revision recompute failed: {exc}") from exc
    if revision != manifest.rule_revision:
        raise RuleCatalogError("active controls disagree with the policy rule_revision (fail-closed)")

    rules: list[ApplicableRule] = []
    for c in active:
        canon = canonical_active_control(c)
        rules.append(
            ApplicableRule(
                engine_name=ENGINE_BUILTIN_MISCONFIG,
                detector_id=canon["id"],
                relative_path=f"{ENGINE_BUILTIN_MISCONFIG}/{canon['id']}",
                content_digest=_control_digest(canon),
                severity=canon["severity"],
                tags=tuple(canon["tags"]),
            )
        )
    return _make_ruleset(manifest.policy_hash, rules)
