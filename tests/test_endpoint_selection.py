"""Pure endpoint target selection (Sprint 3, step 1) — the extraction of run_nuclei_scan's inline
scope/static/dedup/cap logic into a deterministic, reusable, DB-free function.

Pins the binding contract: explicit exclusion buckets with reasons, per-host (not global) cap,
order-independence, scheme/port-aware identity, fail-closed on invalid input, explicit
endpoint→asset_id association, no cleartext URL in any repr, and equivalence with the previous
selection on a realistic fixture.
"""

from __future__ import annotations

from datetime import datetime, timezone
from urllib.parse import urlparse

from app.services.endpoint_selection import (
    STATIC_EXTENSIONS,
    AuthorizedAsset,
    CandidateEndpoint,
    _priority,
    endpoint_shape_key,
    host_in_scope,
    select_endpoint_targets,
)

NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)

# One authorised asset (exact host) + an active domain authorization covering subdomains.
ASSETS = [AuthorizedAsset(asset_id=10, host="app.curci.it")]
SCOPE = [{"type": "domain", "value": "curci.it"}]


def _sel(cands, *, cap=50, assets=ASSETS, scope=SCOPE):
    return select_endpoint_targets(
        [CandidateEndpoint(url=u, endpoint_type=t) for u, t in cands],
        authorized_assets=assets,
        per_host_cap=cap,
        now=NOW,
        scope_entries=scope,
    )


# --- scope ----------------------------------------------------------------------------------------


def test_scope_exact_asset_and_authorized_subdomain_in_scope():
    r = _sel([("https://app.curci.it/a", None), ("https://sub.curci.it/b", None)])
    hosts = {s.host for s in r.selected}
    assert hosts == {"app.curci.it", "sub.curci.it"}
    assert not r.out_of_scope


def test_scope_offsite_host_is_out_of_scope_with_reason():
    r = _sel([("https://app.curci.it/a", None), ("https://youtube.com/watch", None)])
    assert [s.host for s in r.selected] == ["app.curci.it"]
    assert len(r.out_of_scope) == 1
    assert r.out_of_scope[0].reason == "out_of_scope"
    assert r.out_of_scope[0].host == "youtube.com"


def test_scope_failclosed_without_authorizations_exact_only():
    r = _sel([("https://sub.curci.it/b", None)], scope=[])  # no active auth → exact-match only
    assert not r.selected
    assert len(r.out_of_scope) == 1


# --- static filter --------------------------------------------------------------------------------


def test_static_assets_filtered_with_reason():
    r = _sel(
        [
            ("https://app.curci.it/app.js", None),
            ("https://app.curci.it/style.css", None),
            ("https://app.curci.it/login", None),
        ]
    )
    assert [s.host for s in r.selected] == ["app.curci.it"]
    assert r.selected[0].url.endswith("/login")
    assert len(r.static_filtered) == 2
    assert all(e.reason == "static" for e in r.static_filtered)


def test_static_extension_checked_on_path_not_query():
    # /download.php/backup.zip?id=1 → the .zip is in the path → filtered (not hidden by the query)
    r = _sel([("https://app.curci.it/download.php/backup.zip?id=1", None)])
    assert not r.selected
    assert len(r.static_filtered) == 1


# --- shape dedup + scheme/port distinctness -------------------------------------------------------


def test_shape_dedup_keeps_one_representative():
    r = _sel([("https://app.curci.it/user/1", None), ("https://app.curci.it/user/2", None)])
    assert len(r.selected) == 1  # /user/{id} collapses to one shape
    assert len(r.shape_deduplicated) == 1
    assert r.shape_deduplicated[0].reason == "shape_duplicate"


def test_http_https_and_ports_are_distinct_surfaces():
    r = _sel(
        [
            ("http://app.curci.it/x", None),  # :80
            ("https://app.curci.it/x", None),  # :443
            ("https://app.curci.it:8443/x", None),
        ],
        cap=50,
    )
    assert len(r.selected) == 3  # scheme + effective port are part of the identity
    assert not r.shape_deduplicated


# --- per-host cap (NOT global) --------------------------------------------------------------------


def test_cap_is_per_host_not_global():
    cands = [
        ("https://app.curci.it/a", None),
        ("https://app.curci.it/b", None),
        ("https://app.curci.it/c", None),
        ("https://sub.curci.it/a", None),
        ("https://sub.curci.it/b", None),
        ("https://sub.curci.it/c", None),
    ]
    r = _sel(cands, cap=2)
    assert r.per_host_counts == {"app.curci.it": 2, "sub.curci.it": 2}
    assert len(r.selected) == 4  # 2 per host, NOT 2 total
    assert len(r.cap_dropped) == 2
    assert all(e.reason == "cap" for e in r.cap_dropped)


def test_cap_keeps_highest_priority_first():
    # a plain page (prio 2) and an interesting path (prio 0) on the same host, cap 1 → keep /admin
    r = _sel([("https://app.curci.it/blog", None), ("https://app.curci.it/admin", None)], cap=1)
    assert len(r.selected) == 1
    assert r.selected[0].url.endswith("/admin")


# --- determinism ----------------------------------------------------------------------------------


def test_selection_is_order_independent():
    cands = [
        ("https://app.curci.it/admin", None),
        ("https://app.curci.it/api/v1", "api"),
        ("https://app.curci.it/user/1", None),
        ("https://app.curci.it/user/9", None),  # same shape as /user/1
        ("https://app.curci.it/report?id=1", None),
        ("https://sub.curci.it/login", None),
    ]
    fwd = _sel(cands, cap=2).selected_urls
    rev = _sel(list(reversed(cands)), cap=2).selected_urls
    assert fwd == rev  # identical LIST, not just set — total stable order


# --- invalid, fail-closed -------------------------------------------------------------------------


def test_invalid_candidates_are_excluded_failclosed():
    r = _sel(
        [
            ("", None),  # empty
            ("not-a-url", None),  # no scheme
            ("ftp://app.curci.it/x", None),  # non-HTTP scheme
            ("http://", None),  # no host
            ("https://app.curci.it/ok", None),  # the only valid one
        ]
    )
    assert [s.url for s in r.selected] == ["https://app.curci.it/ok"]
    assert len(r.invalid) == 4
    assert all(e.reason == "invalid" for e in r.invalid)


# --- explicit endpoint → asset_id association -----------------------------------------------------


def test_explicit_asset_association():
    r = _sel([("https://app.curci.it/a", None), ("https://sub.curci.it/b", None)])
    by_host = {s.host: s.asset_id for s in r.selected}
    assert by_host["app.curci.it"] == 10  # exact asset → its id
    assert by_host["sub.curci.it"] is None  # in-scope via authorization, but not itself an asset


# --- privacy: no cleartext URL in any repr --------------------------------------------------------


def test_no_cleartext_url_in_reprs():
    secret = "https://app.curci.it/reset/secret-token-abc123?token=SUPERSECRET"
    r = _sel([(secret, None), ("https://youtube.com/x", None), ("https://app.curci.it/x.css", None)])
    blob = repr(r) + repr(r.selected) + repr(r.out_of_scope) + repr(r.static_filtered)
    for leak in ("secret-token-abc123", "SUPERSECRET", "reset"):
        assert leak not in blob
    # the selected URL is still available to the caller (transient), just never in repr
    assert secret in r.selected_urls


def test_reasons_aggregate_counts():
    r = _sel(
        [
            ("https://app.curci.it/admin", None),
            ("https://app.curci.it/admin", None),  # shape dup
            ("https://youtube.com/x", None),  # out of scope
            ("https://app.curci.it/a.js", None),  # static
            ("bad", None),  # invalid
        ],
        cap=50,
    )
    reasons = r.reasons()
    assert reasons["selected"] == 1
    assert reasons["shape_duplicate"] == 1
    assert reasons["out_of_scope"] == 1
    assert reasons["static"] == 1
    assert reasons["invalid"] == 1


# --- equivalence with the previous inline selection -----------------------------------------------


def _legacy_select(endpoints, *, authorised_hosts, scope_entries, url_to_asset, max_per_host):
    """Faithful copy of the ORIGINAL inline logic in run_nuclei_scan (pre-extraction), for the
    equivalence assertion below."""
    cand = []
    for ep_url, ep_type in endpoints:
        if not ep_url or ep_url in url_to_asset:
            continue
        try:
            parsed = urlparse(ep_url)
        except Exception:
            continue
        if not host_in_scope(parsed.hostname or "", authorised_hosts, scope_entries):
            continue
        if any(parsed.path.lower().endswith(ext) for ext in STATIC_EXTENSIONS):
            continue
        cand.append((_priority(ep_url.lower(), ep_type, bool(parsed.query)), ep_url, parsed))
    cand.sort(key=lambda c: c[0])
    urls, seen, phc = [], set(), {}
    for _p, ep_url, parsed in cand:
        k = endpoint_shape_key(ep_url)
        if k in seen:
            continue
        h = (parsed.hostname or "").lower()
        if phc.get(h, 0) >= max_per_host:
            continue
        seen.add(k)
        phc[h] = phc.get(h, 0) + 1
        urls.append(ep_url)
    return urls


def test_equivalence_with_legacy_on_realistic_fixture():
    # Realistic Katana output: distinct shapes, single scheme per host, under the cap → the legacy
    # (scheme-less endpoint_shape_key) and the new (scheme/port-aware identity) selections agree
    # exactly. (Cross-scheme duplicates / over-cap ties are covered by the dedicated tests above,
    # where the new identity is the deliberate, correct strengthening.)
    endpoints = [
        ("https://app.curci.it/", "html"),
        ("https://app.curci.it/login", "form"),
        ("https://app.curci.it/api/v1/users", "api"),
        ("https://app.curci.it/search?q=1", None),
        ("https://app.curci.it/static/app.js", None),  # static → dropped both
        ("https://youtube.com/watch?v=1", None),  # off-site → dropped both
        ("https://sub.curci.it/dashboard", None),
    ]
    url_to_asset = {"https://app.curci.it/": 10}  # the base URL already scanned
    legacy = _legacy_select(
        endpoints,
        authorised_hosts={"app.curci.it"},
        scope_entries=SCOPE,
        url_to_asset=url_to_asset,
        max_per_host=50,
    )
    new = select_endpoint_targets(
        [CandidateEndpoint(url=u, endpoint_type=t) for u, t in endpoints if u and u not in url_to_asset],
        authorized_assets=ASSETS,
        per_host_cap=50,
        now=NOW,
        scope_entries=SCOPE,
    )
    assert set(new.selected_urls) == set(legacy)
    assert len(new.selected_urls) == len(legacy)  # no accidental dup/drop divergence
