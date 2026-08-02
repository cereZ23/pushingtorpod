"""Scan-policy manifest — the immutable, *engine-generic* identity of what a scan pass executes.

A ``policy_hash`` lets the coverage ledger (scan_coverage) prove that a finding's
detector was actually part of the selected+executed rule set for the pass that
covered its asset — so auto-close can be per-detector, and rule/policy DRIFT
(a rule-revision change) can force a re-scan.

Engine-generic on purpose: the ledger is shared across detection engines. Phase 9
passes run under Nuclei; the ``misconfig`` pass (phase 8) runs Python built-in
checks — NOT Nuclei — so the identity must not be Nuclei-specific. The fields are:

  engine_name     nuclei | builtin_misconfig
  engine_version  the binary/app version of the engine
  rule_revision   content hash of the actual templates / checks in play
  phase, pass_name, tier, severity, rule_roots, exclude_tags, relevant_flags

Step 2A (this module) is PURE: it validates + canonicalises the inputs and produces
a deterministic hash. ``rule_revision`` (a content hash of the selected rules) is an
INPUT — filesystem/version resolution and DB persistence are separate later steps.

Identity is valid *by construction*: ``__post_init__`` validates and canonicalises,
so the direct constructor and the factories all yield the same hash — there is no
way to build a mal-normalised, under-specified, or *semantically false* identity
(a pass is bound to exactly one phase and one engine via ``_PASS_SPEC``).

Determinism contract:
  - required scalars (engine_name, engine_version, rule_revision, phase) non-empty;
    ``pass_name`` a known pass; ``phase`` and ``engine_name`` must match the pass's
    declared (phase, engine); ``tier`` an allowed tier — else ValueError;
  - order-independent for every list (severity, rule roots, exclude tags) and flags;
  - normalised: whitespace stripped; tags/severity case-folded; rule roots stripped
    of a trailing "/"; dups removed; boolean-ish flag values folded to true/false;
    None flag values dropped;
  - every field that changes *what runs* changes the hash;
  - fields that do NOT change what runs (rate, concurrency, timeout) are excluded.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Optional

SCHEMA_VERSION = "1"

# Detection engines that can own a pass.
ENGINE_NUCLEI = "nuclei"
ENGINE_BUILTIN_MISCONFIG = "builtin_misconfig"

# Canonical, STABLE pass names (a policy identity, not a rule category).
# "http_stock" is the tier's stock HTTP set on direct assets (cves + exposures +
# default-logins + misconfiguration + technologies + ssl, …) — NOT just "cve".
PASS_CUSTOM_HTTP = "custom_http"
PASS_HTTP_STOCK = "http_stock"
PASS_CDN_SSL_TAKEOVER = "cdn_ssl_takeover"
PASS_DNS_NETWORK = "dns_network"
PASS_MISCONFIG = "misconfig"
PASS_DAST = "dast"

# Single source of truth: each pass is bound to exactly one (phase, engine).
# This is what makes pass_name="misconfig", phase="9" — or engine=nuclei — a hard
# error instead of a valid-but-semantically-false PK.
_PASS_SPEC: dict[str, tuple[str, str]] = {
    PASS_CUSTOM_HTTP: ("9", ENGINE_NUCLEI),
    PASS_HTTP_STOCK: ("9", ENGINE_NUCLEI),
    PASS_CDN_SSL_TAKEOVER: ("9", ENGINE_NUCLEI),
    PASS_DNS_NETWORK: ("9", ENGINE_NUCLEI),
    PASS_MISCONFIG: ("8", ENGINE_BUILTIN_MISCONFIG),
    PASS_DAST: ("9d", ENGINE_NUCLEI),
}

ALLOWED_ENGINES = frozenset({ENGINE_NUCLEI, ENGINE_BUILTIN_MISCONFIG})
ALLOWED_TIERS = frozenset({1, 2, 3})


def expected_phase(pass_name: str) -> Optional[str]:
    """The phase a pass runs in, or None if the pass is unknown."""
    spec = _PASS_SPEC.get(str(pass_name).strip())
    return spec[0] if spec else None


def _canon_list(values, *, casefold: bool = False, strip_trailing_slash: bool = False) -> tuple[str, ...]:
    """Normalise a list to a deterministic, order-independent tuple."""
    out: set[str] = set()
    for v in values or []:
        s = str(v).strip()
        if strip_trailing_slash:
            s = s.rstrip("/")
        if casefold:
            s = s.lower()
        if s:
            out.add(s)
    return tuple(sorted(out))


def _canon_flag_value(v) -> str:
    """Fold a flag value to a stable string: booleans and boolean-ish strings → true/false."""
    if isinstance(v, bool):  # bool is an int subclass — check it FIRST
        return "true" if v else "false"
    s = str(v).strip()
    low = s.lower()
    if low in ("true", "false"):
        return low
    return s


def _canon_flags(flags) -> tuple[tuple[str, str], ...]:
    """Normalise the relevant-execution-flags map (only flags that change what runs).

    None values drop the key; keys are trimmed; values are folded; the result is a
    sorted tuple of (key, value) pairs so the flag order never affects the hash.
    """
    if not flags:
        return ()
    items = flags.items() if isinstance(flags, dict) else list(flags)
    out: dict[str, str] = {}
    for k, v in items:
        key = str(k).strip()
        if not key or v is None:
            continue
        out[key] = _canon_flag_value(v)
    return tuple(sorted(out.items()))


def _require(name: str, value) -> str:
    if value is None:
        raise ValueError(f"scan policy: {name} is required (got None)")
    s = str(value).strip()
    if not s:
        raise ValueError(f"scan policy: {name} is required (got empty)")
    return s


@dataclass(frozen=True)
class ScanPolicyManifest:
    """Immutable, canonicalised, *validated*, engine-generic identity of a scan pass.

    Valid by construction: pass raw lists/dicts in any order/case to either the
    constructor or a ``build_*`` factory — ``__post_init__`` validates and
    canonicalises, so equal policies always yield the same ``policy_hash``.
    """

    engine_name: str
    engine_version: str
    rule_revision: str  # content hash of the selected rules/checks (INPUT)
    phase: str
    pass_name: str
    tier: int
    severity: tuple[str, ...] = ()
    rule_roots: tuple[str, ...] = ()
    exclude_tags: tuple[str, ...] = ()
    relevant_flags: tuple[tuple[str, str], ...] = ()
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self) -> None:
        # --- required scalars (reject half-defined identities) ---------------
        object.__setattr__(self, "engine_version", _require("engine_version", self.engine_version))
        object.__setattr__(self, "rule_revision", _require("rule_revision", self.rule_revision))
        object.__setattr__(self, "phase", _require("phase", self.phase))
        object.__setattr__(self, "schema_version", _require("schema_version", self.schema_version))

        engine_name = _require("engine_name", self.engine_name).lower()
        if engine_name not in ALLOWED_ENGINES:
            raise ValueError(f"scan policy: unknown engine_name {engine_name!r} (allowed: {sorted(ALLOWED_ENGINES)})")
        object.__setattr__(self, "engine_name", engine_name)

        pass_name = _require("pass_name", self.pass_name)
        spec = _PASS_SPEC.get(pass_name)
        if spec is None:
            raise ValueError(f"scan policy: unknown pass_name {pass_name!r} (allowed: {sorted(_PASS_SPEC)})")
        object.__setattr__(self, "pass_name", pass_name)

        # --- pass binds phase AND engine (no semantically-false identity) ----
        exp_phase, exp_engine = spec
        if self.phase != exp_phase:
            raise ValueError(
                f"scan policy: pass {pass_name!r} runs in phase {exp_phase!r}, got phase {self.phase!r}"
            )
        if engine_name != exp_engine:
            raise ValueError(
                f"scan policy: pass {pass_name!r} runs on engine {exp_engine!r}, got {engine_name!r}"
            )

        try:
            tier = int(self.tier)
        except (TypeError, ValueError):
            raise ValueError(f"scan policy: tier must be an int (got {self.tier!r})") from None
        if tier not in ALLOWED_TIERS:
            raise ValueError(f"scan policy: invalid tier {tier} (allowed: {sorted(ALLOWED_TIERS)})")
        object.__setattr__(self, "tier", tier)

        # --- canonicalise the lists / flags (order- & case-independent) ------
        object.__setattr__(self, "severity", _canon_list(self.severity, casefold=True))
        object.__setattr__(self, "rule_roots", _canon_list(self.rule_roots, strip_trailing_slash=True))
        object.__setattr__(self, "exclude_tags", _canon_list(self.exclude_tags, casefold=True))
        object.__setattr__(self, "relevant_flags", _canon_flags(self.relevant_flags))

        # --- no declared-but-ignored filters on the built-in engine ----------
        # The misconfig engine has no template roots and no policy-level severity/tag
        # gate (its selection is per-control). Carrying such fields would let a policy
        # DECLARE a filter the catalog silently ignores — reject it by construction.
        if engine_name == ENGINE_BUILTIN_MISCONFIG:
            for fld in ("severity", "rule_roots", "exclude_tags"):
                if getattr(self, fld):
                    raise ValueError(
                        f"scan policy: {engine_name} carries no {fld} filter (got {getattr(self, fld)})"
                    )

    def canonical(self) -> dict:
        """The exact, normalised structure the hash is taken over (already canonical)."""
        return {
            "schema_version": self.schema_version,
            "engine_name": self.engine_name,
            "engine_version": self.engine_version,
            "rule_revision": self.rule_revision,
            "phase": self.phase,
            "pass_name": self.pass_name,
            "tier": self.tier,
            "severity": list(self.severity),
            "rule_roots": list(self.rule_roots),
            "exclude_tags": list(self.exclude_tags),
            "relevant_flags": dict(self.relevant_flags),
        }

    @property
    def policy_hash(self) -> str:
        """Full SHA-256 hex digest — durable PK / FK / audit identity (not truncated)."""
        blob = json.dumps(self.canonical(), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(blob.encode()).hexdigest()


def build_scan_policy_manifest(
    *,
    engine_name: str,
    engine_version: str,
    rule_revision: str,
    pass_name: str,
    tier: int,
    phase: Optional[str] = None,
    severity=None,
    rule_roots=None,
    exclude_tags=None,
    relevant_flags: Optional[dict] = None,
    schema_version: str = SCHEMA_VERSION,
) -> ScanPolicyManifest:
    """Generic, engine-agnostic builder (pure).

    ``phase`` may be omitted — it is derived from the pass's declared phase; if you
    pass it explicitly it is *validated* against the pass (a mismatch raises). All
    normalisation/validation lives in ``__post_init__`` so the constructor is equally
    safe. Prefer the engine-specific factories below for correct field semantics.
    """
    return ScanPolicyManifest(
        engine_name=engine_name,
        engine_version=engine_version,
        rule_revision=rule_revision,
        phase=phase if phase is not None else expected_phase(pass_name),
        pass_name=pass_name,
        tier=tier,
        severity=severity or (),
        rule_roots=rule_roots or (),
        exclude_tags=exclude_tags or (),
        relevant_flags=relevant_flags or (),
        schema_version=schema_version,
    )


def build_nuclei_policy_manifest(
    *,
    nuclei_version: str,
    template_revision: str,
    pass_name: str,
    tier: int,
    phase: Optional[str] = None,
    severity=None,
    template_roots=None,
    exclude_tags=None,
    relevant_flags: Optional[dict] = None,
    schema_version: str = SCHEMA_VERSION,
) -> ScanPolicyManifest:
    """Nuclei pass identity: engine=nuclei, engine_version=nuclei_version,
    rule_revision=template_revision, rule_roots=template roots."""
    return build_scan_policy_manifest(
        engine_name=ENGINE_NUCLEI,
        engine_version=nuclei_version,
        rule_revision=template_revision,
        pass_name=pass_name,
        tier=tier,
        phase=phase,
        severity=severity,
        rule_roots=template_roots,
        exclude_tags=exclude_tags,
        relevant_flags=relevant_flags,
        schema_version=schema_version,
    )


def build_misconfig_policy_manifest(
    *,
    app_version: str,
    rule_revision: str,
    tier: int,
    pass_name: str = PASS_MISCONFIG,
    phase: Optional[str] = None,
    severity=None,
    rule_roots=None,
    exclude_tags=None,
    relevant_flags: Optional[dict] = None,
    schema_version: str = SCHEMA_VERSION,
) -> ScanPolicyManifest:
    """Built-in misconfig pass identity: engine=builtin_misconfig,
    engine_version=application release/Git SHA, rule_revision=hash of the active
    control IDs + relevant config (NOT a Nuclei template revision)."""
    return build_scan_policy_manifest(
        engine_name=ENGINE_BUILTIN_MISCONFIG,
        engine_version=app_version,
        rule_revision=rule_revision,
        pass_name=pass_name,
        tier=tier,
        phase=phase,
        severity=severity,
        rule_roots=rule_roots,
        exclude_tags=exclude_tags,
        relevant_flags=relevant_flags,
        schema_version=schema_version,
    )
