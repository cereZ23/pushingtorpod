"""Detector applicability catalog — which detectors a policy actually runs.

Step 2B ([[rule_revision]]) proves *content identity* (did the rule bytes change?).
This module proves a different property: given a manifest ([[scan_policy]]) and the
real rule content, is a specific ``detector_id`` (a nuclei template id, or a misconfig
control id) *applicable* to that policy — i.e. selected AND not filtered out?

That is exactly what a per-detector auto-close needs: a finding may be closed only if
its detector was provably in the pass's applicable set for a healthy scan.

Pure and DB-free. I/O (reading bytes, parsing YAML) is injected. Fail-closed: an
invalid template, a missing/duplicate id, an uninterpretable severity/tags field, a
content digest that disagrees with 2B, or an empty applicable set all raise
``RuleCatalogError`` — an unsupported case makes the policy NON-authorising rather
than silently guessing Nuclei's behaviour.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Callable, Optional, Sequence

from app.services.rule_revision import (
    RuleResolutionError,
    canonical_json_value,
    compute_misconfig_rule_revision,
    compute_rule_revision,
    content_digest,
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


# --- shared field normalisation ----------------------------------------------


def _norm_severity(value) -> Optional[str]:
    """A severity is an optional string. A non-string severity is uninterpretable."""
    if value is None:
        return None
    if not isinstance(value, str):
        raise RuleCatalogError(f"uninterpretable severity: {value!r}")
    s = value.strip().lower()
    return s or None


def _norm_tags(value) -> tuple[str, ...]:
    """Tags may be a comma-separated string or a list of strings; anything else is
    uninterpretable. Normalised: lower-cased, trimmed, de-duplicated, sorted."""
    if value is None:
        return ()
    if isinstance(value, str):
        raw = value.split(",")
    elif isinstance(value, (list, tuple)):
        raw = value
    else:
        raise RuleCatalogError(f"uninterpretable tags: {value!r}")
    out: set[str] = set()
    for t in raw:
        if not isinstance(t, str):
            raise RuleCatalogError(f"uninterpretable tag element: {t!r}")
        s = t.strip().lower()
        if s:
            out.add(s)
    return tuple(sorted(out))


def _make_ruleset(policy_hash: str, rules: list[ApplicableRule]) -> ApplicableRuleSet:
    if not rules:
        raise RuleCatalogError("no applicable detectors for policy (fail-closed)")
    ordered = tuple(sorted(rules, key=lambda r: r.detector_id))
    return ApplicableRuleSet(policy_hash=policy_hash, rules=ordered)


# --- Nuclei enumeration ------------------------------------------------------


def enumerate_nuclei_applicable_rules(
    manifest: ScanPolicyManifest,
    files: Sequence[tuple[str, bytes]],
    *,
    parse_yaml: Callable[[bytes], object],
) -> ApplicableRuleSet:
    """Enumerate the Nuclei templates applicable to ``manifest``.

    ``files`` are the (relative_path, content_bytes) pairs ALREADY resolved by 2B —
    the catalog does not re-walk the filesystem, so it can't observe a different set
    than the one the revision was taken over. The revision is recomputed from those
    exact bytes and must equal ``manifest.rule_revision`` (2B's digest, which the
    manifest carries as its identity); a mismatch means the files are inconsistent
    with the policy → fail-closed. Then each template is parsed and filtered by the
    policy's severity whitelist and exclude tags.
    """
    if manifest.engine_name != ENGINE_NUCLEI:
        raise RuleCatalogError(f"nuclei enumeration requires a nuclei policy, got {manifest.engine_name!r}")

    entries: list[tuple[str, str]] = []
    docs: dict[str, tuple[str, object]] = {}  # rel_path -> (digest, parsed doc)
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
        docs[rel] = (digest, doc)

    # Consistency with 2B: same files+content must reproduce the same revision.
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
        digest, doc = docs[rel]
        detector_id = str(doc.get("id", "")).strip() if isinstance(doc.get("id"), (str, int)) else ""
        if not detector_id:
            raise RuleCatalogError(f"template {rel!r} has no id")
        prev = id_to_path.get(detector_id)
        if prev is not None and prev != rel:
            raise RuleCatalogError(f"duplicate detector id {detector_id!r} in {prev!r} and {rel!r}")
        id_to_path[detector_id] = rel

        info = doc.get("info") or {}
        if not isinstance(info, Mapping):
            raise RuleCatalogError(f"template {rel!r} has an uninterpretable info block")
        severity = _norm_severity(info.get("severity"))
        tags = _norm_tags(info.get("tags"))

        if sev_whitelist and severity not in sev_whitelist:
            continue  # not selected by the policy severity gate
        if exclude & set(tags):
            continue  # excluded by tag
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


# --- misconfig enumeration ---------------------------------------------------


def _control_digest(control_id: str, config) -> str:
    payload = json.dumps(
        {"id": control_id, "config": canonical_json_value(config or {}, "$.config")},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def enumerate_misconfig_applicable_rules(
    manifest: ScanPolicyManifest,
    controls: Sequence[Mapping],
) -> ApplicableRuleSet:
    """Enumerate the applicable built-in misconfig controls for ``manifest``.

    Only enabled controls count; ids must be non-empty and unique; the detector id IS
    the canonical control id. The revision recomputed over the active controls must
    match ``manifest.rule_revision`` (2B), else fail-closed. Zero active → error.
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
        cid = str(c.get("id", "")).strip()
        if not cid:
            raise RuleCatalogError("misconfig control has an empty id")
        if cid in seen:
            raise RuleCatalogError(f"duplicate misconfig control id {cid!r}")
        seen.add(cid)
        active.append(c)

    if not active:
        raise RuleCatalogError("no active misconfig controls (fail-closed)")

    # Consistency with 2B: the active id+config set must reproduce the same revision.
    try:
        revision = compute_misconfig_rule_revision(
            [{"id": str(c["id"]).strip(), "config": c.get("config")} for c in active]
        )
    except RuleResolutionError as exc:
        raise RuleCatalogError(f"misconfig revision recompute failed: {exc}") from exc
    if revision != manifest.rule_revision:
        raise RuleCatalogError("active controls disagree with the policy rule_revision (fail-closed)")

    rules: list[ApplicableRule] = []
    for c in active:
        cid = str(c["id"]).strip()
        rules.append(
            ApplicableRule(
                engine_name=ENGINE_BUILTIN_MISCONFIG,
                detector_id=cid,
                relative_path=f"{ENGINE_BUILTIN_MISCONFIG}/{cid}",
                content_digest=_control_digest(cid, c.get("config")),
                severity=_norm_severity(c.get("severity")),
                tags=_norm_tags(c.get("tags")),
            )
        )
    return _make_ruleset(manifest.policy_hash, rules)
