"""Scan-policy manifest — the immutable identity of *what a scan pass executes*.

A ``policy_hash`` lets the coverage ledger (scan_coverage) prove that a finding's
detector was actually part of the selected+executed template set for the pass that
covered its asset — so auto-close can be per-detector, and template/policy DRIFT
(a template revision change) can force a re-scan.

Step 2A (this module) is PURE: it canonicalises the policy inputs and produces a
deterministic hash. ``template_revision`` (a content hash of the selected template
files) is an INPUT — filesystem resolution and DB persistence are separate steps,
deliberately kept out so canonicalisation + determinism can be locked first.

Determinism contract:
  - order-independent for every list (severity, template roots, exclude tags);
  - normalised: whitespace stripped; tags/severity case-folded; template roots
    stripped of a trailing "/"; duplicates removed;
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


def _canon_list(values, *, casefold: bool = False, strip_trailing_slash: bool = False) -> list[str]:
    """Normalise a list to a deterministic, order-independent form."""
    out: set[str] = set()
    for v in values or []:
        s = str(v).strip()
        if strip_trailing_slash:
            s = s.rstrip("/")
        if casefold:
            s = s.lower()
        if s:
            out.add(s)
    return sorted(out)


def _canon_flags(flags: Optional[dict]) -> dict:
    """Normalise the relevant-execution-flags map (only flags that change what runs)."""
    if not flags:
        return {}
    return {str(k).strip(): (str(v).strip() if v is not None else "") for k, v in sorted(flags.items())}


@dataclass(frozen=True)
class ScanPolicyManifest:
    """Immutable, canonicalised identity of a scan pass's policy."""

    nuclei_version: str
    template_revision: str  # content hash of the selected template files (INPUT)
    phase: str
    pass_name: str
    tier: int
    severity: tuple[str, ...]
    template_roots: tuple[str, ...]
    exclude_tags: tuple[str, ...]
    relevant_flags: tuple[tuple[str, str], ...]
    schema_version: str = SCHEMA_VERSION

    def canonical(self) -> dict:
        """The exact, normalised structure the hash is taken over."""
        return {
            "schema_version": self.schema_version,
            "nuclei_version": self.nuclei_version.strip(),
            "template_revision": self.template_revision.strip(),
            "phase": self.phase.strip(),
            "pass_name": self.pass_name.strip(),
            "tier": int(self.tier),
            "severity": list(self.severity),
            "template_roots": list(self.template_roots),
            "exclude_tags": list(self.exclude_tags),
            "relevant_flags": dict(self.relevant_flags),
        }

    @property
    def policy_hash(self) -> str:
        blob = json.dumps(self.canonical(), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(blob.encode()).hexdigest()[:32]


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
    """Build a fully-canonicalised manifest (pure). Inputs may be in any order/case."""
    return ScanPolicyManifest(
        nuclei_version=str(nuclei_version).strip(),
        template_revision=str(template_revision).strip(),
        phase=str(phase).strip(),
        pass_name=str(pass_name).strip(),
        tier=int(tier),
        severity=tuple(_canon_list(severity, casefold=True)),
        template_roots=tuple(_canon_list(template_roots, strip_trailing_slash=True)),
        exclude_tags=tuple(_canon_list(exclude_tags, casefold=True)),
        relevant_flags=tuple(sorted(_canon_flags(relevant_flags).items())),
        schema_version=str(schema_version),
    )
