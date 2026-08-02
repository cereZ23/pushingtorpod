"""Scan-policy manifest — the immutable identity of *what a scan pass executes*.

A ``policy_hash`` lets the coverage ledger (scan_coverage) prove that a finding's
detector was actually part of the selected+executed template set for the pass that
covered its asset — so auto-close can be per-detector, and template/policy DRIFT
(a template revision change) can force a re-scan.

Step 2A (this module) is PURE: it canonicalises the policy inputs and produces a
deterministic hash. ``template_revision`` (a content hash of the selected template
files) is an INPUT — filesystem resolution and DB persistence are separate steps,
deliberately kept out so canonicalisation + determinism can be locked first.

Identity is valid *by construction*: the manifest validates and canonicalises in
``__post_init__``, so the direct constructor and the factory both yield the same
hash — there is no way to build a mal-normalised or under-specified identity.

Determinism contract:
  - required scalars (nuclei_version, template_revision, phase) must be non-empty;
    ``pass_name`` must be a known pass; ``tier`` must be an allowed tier — otherwise
    ValueError (a policy that could become a durable PK must never be half-defined);
  - order-independent for every list (severity, template roots, exclude tags) and
    for the flags map;
  - normalised: whitespace stripped; tags/severity case-folded; template roots
    stripped of a trailing "/"; duplicates removed; boolean-ish flag values folded
    to "true"/"false"; None flag values dropped;
  - every field that changes *what runs* changes the hash (schema_version,
    nuclei_version, template_revision, phase, pass_name, tier, severity, template
    roots, exclude tags, and the relevant execution flags);
  - fields that do NOT change what runs (rate, concurrency, timeout) are excluded.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Optional

SCHEMA_VERSION = "1"

# Canonical, STABLE pass names (a policy identity, not a template category).
# "http_stock" is the tier's stock HTTP set on direct assets (cves + exposures +
# default-logins + misconfiguration + technologies + ssl, …) — NOT just "cve".
PASS_CUSTOM_HTTP = "custom_http"
PASS_HTTP_STOCK = "http_stock"
PASS_CDN_SSL_TAKEOVER = "cdn_ssl_takeover"
PASS_DNS_NETWORK = "dns_network"
PASS_MISCONFIG = "misconfig"
PASS_DAST = "dast"  # phase 9d — outside the MVP

ALLOWED_PASSES = frozenset(
    {PASS_CUSTOM_HTTP, PASS_HTTP_STOCK, PASS_CDN_SSL_TAKEOVER, PASS_DNS_NETWORK, PASS_MISCONFIG, PASS_DAST}
)
ALLOWED_TIERS = frozenset({1, 2, 3})


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
    if isinstance(flags, dict):
        items = flags.items()
    else:  # already a sequence of pairs (e.g. re-canonicalising a stored manifest)
        items = list(flags)
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
    """Immutable, canonicalised, *validated* identity of a scan pass's policy.

    Valid by construction: pass raw lists/dicts in any order/case to either the
    constructor or ``build_scan_policy_manifest`` — ``__post_init__`` validates and
    canonicalises, so equal policies always yield the same ``policy_hash``.
    """

    nuclei_version: str
    template_revision: str  # content hash of the selected template files (INPUT)
    phase: str
    pass_name: str
    tier: int
    severity: tuple[str, ...] = ()
    template_roots: tuple[str, ...] = ()
    exclude_tags: tuple[str, ...] = ()
    relevant_flags: tuple[tuple[str, str], ...] = ()
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self) -> None:
        # --- required scalars (reject half-defined identities) ---------------
        object.__setattr__(self, "nuclei_version", _require("nuclei_version", self.nuclei_version))
        object.__setattr__(self, "template_revision", _require("template_revision", self.template_revision))
        object.__setattr__(self, "phase", _require("phase", self.phase))
        object.__setattr__(self, "schema_version", _require("schema_version", self.schema_version))

        pass_name = _require("pass_name", self.pass_name)
        if pass_name not in ALLOWED_PASSES:
            raise ValueError(f"scan policy: unknown pass_name {pass_name!r} (allowed: {sorted(ALLOWED_PASSES)})")
        object.__setattr__(self, "pass_name", pass_name)

        try:
            tier = int(self.tier)
        except (TypeError, ValueError):
            raise ValueError(f"scan policy: tier must be an int (got {self.tier!r})") from None
        if tier not in ALLOWED_TIERS:
            raise ValueError(f"scan policy: invalid tier {tier} (allowed: {sorted(ALLOWED_TIERS)})")
        object.__setattr__(self, "tier", tier)

        # --- canonicalise the lists / flags (order- & case-independent) ------
        object.__setattr__(self, "severity", _canon_list(self.severity, casefold=True))
        object.__setattr__(self, "template_roots", _canon_list(self.template_roots, strip_trailing_slash=True))
        object.__setattr__(self, "exclude_tags", _canon_list(self.exclude_tags, casefold=True))
        object.__setattr__(self, "relevant_flags", _canon_flags(self.relevant_flags))

    def canonical(self) -> dict:
        """The exact, normalised structure the hash is taken over (already canonical)."""
        return {
            "schema_version": self.schema_version,
            "nuclei_version": self.nuclei_version,
            "template_revision": self.template_revision,
            "phase": self.phase,
            "pass_name": self.pass_name,
            "tier": self.tier,
            "severity": list(self.severity),
            "template_roots": list(self.template_roots),
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
    nuclei_version: str,
    template_revision: str,
    phase: str,
    pass_name: str,
    tier: int,
    severity=None,
    template_roots=None,
    exclude_tags=None,
    relevant_flags: Optional[dict] = None,
    schema_version: str = SCHEMA_VERSION,
) -> ScanPolicyManifest:
    """Build a fully-canonicalised, validated manifest (pure).

    Thin keyword-only wrapper over the dataclass; all normalisation/validation lives
    in ``__post_init__`` so the constructor is equally safe.
    """
    return ScanPolicyManifest(
        nuclei_version=nuclei_version,
        template_revision=template_revision,
        phase=phase,
        pass_name=pass_name,
        tier=tier,
        severity=severity or (),
        template_roots=template_roots or (),
        exclude_tags=exclude_tags or (),
        relevant_flags=relevant_flags or (),
        schema_version=schema_version,
    )
