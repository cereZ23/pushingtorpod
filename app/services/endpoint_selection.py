"""Pure, deterministic endpoint target selection for the Nuclei passes (Sprint 3, step 1).

This is the extraction of the endpoint-selection logic that used to live inline in
``run_nuclei_scan`` (``app/tasks/scanning.py``). Pulling it out as a PURE function makes it:

- **reusable** by the future dedicated ``http_endpoint`` pass AND by a faithful benchmark
  (both must apply the EXACT same scope/static/dedup/cap rules — reimplementing them would be
  the divergence the plan forbids);
- **testable** in isolation (no DB, no subprocess, no clock);
- **deterministic** — the same inputs yield the same selection regardless of candidate order,
  because the cap is applied after a STABLE TOTAL ordering (priority, then canonical identity).

Identity note: dedup / coverage / provenance all key off the ONE canonical endpoint identity
(:mod:`app.services.endpoint_identity` — ``endpoint_shape_hash``, which includes scheme + effective
port). This deliberately supersedes the old scheme-less ``endpoint_shape_key`` (which merged
``http://h/x`` and ``https://h/x``): distinct scheme/port ⇒ distinct surface ⇒ distinct row.

Privacy: the result NEVER exposes a raw URL in its ``repr`` or any aggregate — only host + the
64-hex shape hash + a reason. The selected URLs are held for the caller to submit to Nuclei
(transient), never for logging or persistence.

This module intentionally does NOT build a policy, catalog, coverage, provenance, or the new pass —
that is Sprint 3 step 2+.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Iterable, Optional, Sequence
from urllib.parse import parse_qs, urlparse

from app.services.endpoint_identity import endpoint_shape_hash

# --- pure host / shape helpers (moved here from app.tasks.scanning; re-exported there) -----------

# A path segment that is an opaque id → collapse so /user/1 and /user/2 share a legacy shape key.
_ID_SEGMENT_RE = re.compile(r"^\d+$|^[0-9a-f]{8,}$")


def endpoint_shape_key(url: str) -> tuple:
    """LEGACY shape key: (host, id-collapsed path, sorted query param names). Scheme/port-agnostic.

    Kept for backward compatibility (existing callers/tests). NEW selection dedups by the canonical
    :func:`app.services.endpoint_identity.endpoint_shape_hash` instead, which also distinguishes
    scheme and effective port.
    """
    p = urlparse(url)
    host = (p.hostname or "").lower()
    segs = ["{id}" if _ID_SEGMENT_RE.match(s) else s.lower() for s in p.path.split("/")]
    return (host, "/".join(segs), tuple(sorted(parse_qs(p.query).keys())))


def normalize_host(host: str | None) -> str:
    """Lowercase, strip a trailing dot, and IDNA-encode a hostname for scope comparison."""
    if not host:
        return ""
    h = host.strip().rstrip(".").lower()
    try:
        h = h.encode("idna").decode("ascii")
    except Exception:
        pass
    return h


def host_in_scope(host: str, authorised_hosts: set, scope_entries: list) -> bool:
    """Is a crawled endpoint host authorised to scan?

    In scope ONLY if the host is exactly one of the PASS's authorised assets, or matches an
    ACTIVE ScanAuthorization scope entry (a ``domain`` entry covers the domain + its subdomains via
    literal suffix; ``ip``/``cidr`` cover IP targets). The boundary is EXPLICIT authorization —
    never inferred from a discovered asset's registrable domain. No scope entries → exact-match
    only (fail-closed).
    """
    from app.services.scope_authorization import target_in_scope

    h = normalize_host(host)
    if not h:
        return False
    if h in authorised_hosts:
        return True
    return target_in_scope(h, scope_entries or [])


# --- static-asset filter + priority (unchanged semantics from run_nuclei_scan) -------------------

STATIC_EXTENSIONS = {
    ".css",
    ".js",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".ico",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
    ".map",
    ".mp4",
    ".mp3",
    ".pdf",
    ".zip",
}

INTERESTING_PATHS = {
    "/admin",
    "/login",
    "/signin",
    "/api/",
    "/graphql",
    "/upload",
    "/config",
    "/dashboard",
    "/manager",
    "/console",
    "/debug",
    "/actuator",
    "/swagger",
    "/openapi",
    "/wp-admin",
    "/wp-login",
    "/phpmyadmin",
    "/xmlrpc",
}


def _priority(url_lower: str, ep_type: Optional[str], has_query: bool) -> int:
    """Rank so the per-host cap keeps the highest-value endpoints first (0 = highest)."""
    if ep_type in ("api", "form") or any(p in url_lower for p in INTERESTING_PATHS):
        return 0
    if has_query:
        return 1
    return 2


# --- inputs / outputs ----------------------------------------------------------------------------


@dataclass(frozen=True)
class AuthorizedAsset:
    """An asset THIS pass is authorised to scan (exact host match) + its id for association."""

    asset_id: int
    host: str


@dataclass(frozen=True)
class CandidateEndpoint:
    """A crawled endpoint offered to the selector. ``asset_id`` optional — resolved by host match."""

    url: str
    endpoint_type: Optional[str] = None


@dataclass(frozen=True)
class SelectedEndpoint:
    """An authorised endpoint to submit to the pass, with its explicit asset association."""

    url: str  # transient — for the caller to scan; NEVER logged/persisted (see __repr__)
    host: str
    asset_id: Optional[int]
    endpoint_type: Optional[str]
    priority: int
    shape_hash: str

    def __repr__(self) -> str:  # redacted: no raw URL/path/query
        return (
            f"SelectedEndpoint(host={self.host!r}, shape={self.shape_hash[:12]}…, "
            f"asset_id={self.asset_id}, prio={self.priority})"
        )


@dataclass(frozen=True)
class ExcludedEndpoint:
    """A candidate that did NOT make it, with the reason. Carries NO raw URL — host + shape only."""

    host: str
    shape_hash: Optional[str]
    reason: str  # out_of_scope | static | shape_duplicate | cap | invalid

    def __repr__(self) -> str:
        sh = f"{self.shape_hash[:12]}…" if self.shape_hash else "-"
        return f"ExcludedEndpoint(host={self.host!r}, shape={sh}, reason={self.reason!r})"


@dataclass
class EndpointSelectionResult:
    """The full, auditable outcome of a selection — buckets + per-host counts + aggregate reasons.

    ``repr`` and every aggregate expose ONLY hosts, shape hashes, and counts — never a raw URL.
    """

    selected: list[SelectedEndpoint] = field(default_factory=list)
    out_of_scope: list[ExcludedEndpoint] = field(default_factory=list)
    static_filtered: list[ExcludedEndpoint] = field(default_factory=list)
    shape_deduplicated: list[ExcludedEndpoint] = field(default_factory=list)
    cap_dropped: list[ExcludedEndpoint] = field(default_factory=list)
    invalid: list[ExcludedEndpoint] = field(default_factory=list)
    per_host_counts: dict[str, int] = field(default_factory=dict)

    @property
    def selected_urls(self) -> list[str]:
        """The concrete URLs to submit to Nuclei (caller-side, transient)."""
        return [s.url for s in self.selected]

    def reasons(self) -> dict[str, int]:
        """Aggregate exclusion reasons → counts (safe to log)."""
        return {
            "selected": len(self.selected),
            "out_of_scope": len(self.out_of_scope),
            "static": len(self.static_filtered),
            "shape_duplicate": len(self.shape_deduplicated),
            "cap": len(self.cap_dropped),
            "invalid": len(self.invalid),
        }

    def __repr__(self) -> str:
        return f"EndpointSelectionResult(reasons={self.reasons()}, per_host={self.per_host_counts})"


def select_endpoint_targets(
    candidates: Iterable[CandidateEndpoint],
    *,
    authorized_assets: Sequence[AuthorizedAsset],
    per_host_cap: int,
    now: datetime,
    scope_entries: Sequence = (),
) -> EndpointSelectionResult:
    """Select the authorised endpoints to submit to a Nuclei pass — PURE and DETERMINISTIC.

    Pipeline (each dropped candidate is bucketed with its reason):
      1. **invalid** — empty/unparseable, non-http(s), or hostless → excluded fail-closed.
      2. **out_of_scope** — host not an authorised asset and not covered by an active scope entry.
      3. **static** — the path ends in a static asset extension (css/js/img/font/archive/…).
      4. Rank survivors by priority (api/form/interesting-path → parameterised → plain).
      5. Apply the per-host cap over a STABLE TOTAL ordering ``(priority, shape_hash, url)`` so the
         result is independent of candidate order; within a shape only the first survivor is kept
         (**shape_duplicate**), and once a host reaches ``per_host_cap`` the rest are **cap**-dropped.

    Args:
        candidates: crawled endpoints (already de-duplicated against base URLs by the caller).
        authorized_assets: the exact assets this pass may scan (host + asset_id for association).
        per_host_cap: max endpoints kept PER HOST (applied per host, never globally).
        now: injected clock (scope entries are pre-resolved as-of this instant by the caller). The
            function performs NO internal ``datetime.now()`` — the clock is always injected.
        scope_entries: active ScanAuthorization scope entries (pure list; already resolved by now).

    Returns:
        An :class:`EndpointSelectionResult` with the selected endpoints and every exclusion bucket.
    """
    if now is None:
        raise ValueError("select_endpoint_targets requires an injected `now` (no internal clock)")
    if per_host_cap is None or per_host_cap < 0:
        raise ValueError(f"per_host_cap must be a non-negative int, got {per_host_cap!r}")

    authorised_hosts = {normalize_host(a.host) for a in authorized_assets}
    authorised_hosts.discard("")
    host_to_asset: dict[str, int] = {}
    for a in authorized_assets:
        h = normalize_host(a.host)
        if h and h not in host_to_asset:  # first wins → stable association
            host_to_asset[h] = a.asset_id

    result = EndpointSelectionResult()

    # Phase 1: validate + scope + static, computing the canonical identity for each survivor.
    survivors: list[tuple[int, str, str, str, Optional[str]]] = []  # (prio, shape_hash, url, host, type)
    for cand in candidates:
        url = cand.url
        if not url:
            result.invalid.append(ExcludedEndpoint(host="", shape_hash=None, reason="invalid"))
            continue
        try:
            parsed = urlparse(url)
        except Exception:
            result.invalid.append(ExcludedEndpoint(host="", shape_hash=None, reason="invalid"))
            continue
        if parsed.scheme.lower() not in ("http", "https") or not parsed.hostname:
            result.invalid.append(ExcludedEndpoint(host="", shape_hash=None, reason="invalid"))
            continue

        norm_host = normalize_host(parsed.hostname)
        if not host_in_scope(parsed.hostname or "", authorised_hosts, list(scope_entries)):
            result.out_of_scope.append(ExcludedEndpoint(host=norm_host, shape_hash=None, reason="out_of_scope"))
            continue
        # Static check on the PATH (not the whole URL — a /download.php/backup.zip?id=1 handler
        # hides the .zip in the query otherwise).
        if any(parsed.path.lower().endswith(ext) for ext in STATIC_EXTENSIONS):
            result.static_filtered.append(ExcludedEndpoint(host=norm_host, shape_hash=None, reason="static"))
            continue

        try:
            shape = endpoint_shape_hash(url)
        except ValueError:
            # http/https + host already validated, but be fail-closed if the identity can't form.
            result.invalid.append(ExcludedEndpoint(host=norm_host, shape_hash=None, reason="invalid"))
            continue

        prio = _priority(url.lower(), cand.endpoint_type, bool(parsed.query))
        survivors.append((prio, shape, url, norm_host, cand.endpoint_type))

    # Phase 2: STABLE TOTAL order so the cap is order-independent. (priority, shape, url) is a total
    # order over distinct candidates → reordering the input cannot change the outcome.
    survivors.sort(key=lambda s: (s[0], s[1], s[2]))

    # Phase 3: shape-dedup + per-host cap, in that order.
    seen_shapes: set[str] = set()
    for prio, shape, url, norm_host, ep_type in survivors:
        if shape in seen_shapes:
            result.shape_deduplicated.append(
                ExcludedEndpoint(host=norm_host, shape_hash=shape, reason="shape_duplicate")
            )
            continue
        if result.per_host_counts.get(norm_host, 0) >= per_host_cap:
            result.cap_dropped.append(ExcludedEndpoint(host=norm_host, shape_hash=shape, reason="cap"))
            continue
        seen_shapes.add(shape)
        result.per_host_counts[norm_host] = result.per_host_counts.get(norm_host, 0) + 1
        result.selected.append(
            SelectedEndpoint(
                url=url,
                host=norm_host,
                asset_id=host_to_asset.get(norm_host),
                endpoint_type=ep_type,
                priority=prio,
                shape_hash=shape,
            )
        )

    return result
