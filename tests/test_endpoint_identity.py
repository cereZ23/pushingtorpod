"""Endpoint IDENTITY hash — the load-bearing key for endpoint coverage (Sprint 2).

The identity is a SHA-256 over a versioned canonical JSON. These tests pin the two properties the
coverage/finding tables depend on:

1. PRIVACY — the raw URL / path / query / token / PII is NEVER present in the persisted hash.
2. SEPARATION — scheme, effective port, and case-sensitive path all participate, so distinct
   surfaces get distinct identities; only clearly-opaque id segments collapse (dedup, not privacy).
"""

from __future__ import annotations

import re

from app.services.endpoint_identity import (
    IDENTITY_VERSION,
    canonical_endpoint,
    endpoint_shape_hash,
    is_shape_hash,
)

_HEX64 = re.compile(r"^[0-9a-f]{64}$")


# --- shape / determinism -------------------------------------------------------------------------


def test_hash_is_64_lowercase_hex_and_deterministic():
    h1 = endpoint_shape_hash("https://api.example.com/users?q=1")
    h2 = endpoint_shape_hash("https://api.example.com/users?q=1")
    assert _HEX64.match(h1)
    assert h1 == h2


def test_is_shape_hash_accepts_only_canonical_hex():
    assert is_shape_hash(endpoint_shape_hash("https://h/x"))
    assert not is_shape_hash("https://h/x")  # a raw URL is rejected
    assert not is_shape_hash("ABC123")  # too short / uppercase
    assert not is_shape_hash("g" * 64)  # non-hex
    assert not is_shape_hash("A" * 64)  # uppercase hex rejected (canonical is lowercase)
    assert not is_shape_hash(None)
    assert not is_shape_hash(12345)


# --- separation: scheme / port / path-case must NOT collide ---------------------------------------


def test_http_and_https_do_not_collide():
    assert endpoint_shape_hash("http://host/x") != endpoint_shape_hash("https://host/x")


def test_ports_do_not_collide():
    # :80, :443 and :8443 are three distinct surfaces — never one coverage row.
    default_http = endpoint_shape_hash("http://host/x")  # effective :80
    explicit_443 = endpoint_shape_hash("https://host:443/x")  # effective :443
    explicit_8443 = endpoint_shape_hash("https://host:8443/x")
    assert len({default_http, explicit_443, explicit_8443}) == 3


def test_default_port_matches_explicit_default():
    # http://host/x and http://host:80/x are the SAME surface.
    assert endpoint_shape_hash("http://host/x") == endpoint_shape_hash("http://host:80/x")
    assert endpoint_shape_hash("https://host/x") == endpoint_shape_hash("https://host:443/x")


def test_path_is_case_sensitive():
    # HTTP paths are case-sensitive → /Admin ≠ /admin.
    assert endpoint_shape_hash("https://host/Admin") != endpoint_shape_hash("https://host/admin")


def test_host_is_case_insensitive():
    assert endpoint_shape_hash("https://HOST/x") == endpoint_shape_hash("https://host/x")


def test_param_names_matter_values_do_not():
    # Same param NAME, different value → same identity (values never participate).
    assert endpoint_shape_hash("https://h/s?q=a") == endpoint_shape_hash("https://h/s?q=b")
    # Different param name → different identity.
    assert endpoint_shape_hash("https://h/s?q=a") != endpoint_shape_hash("https://h/s?r=a")


# --- id collapse (dedup, not privacy) -------------------------------------------------------------


def test_numeric_uuid_hex_segments_collapse():
    base = endpoint_shape_hash("https://h/users/1")
    assert endpoint_shape_hash("https://h/users/2") == base  # numeric id
    assert endpoint_shape_hash("https://h/users/00000000-0000-0000-0000-000000000000") == base  # uuid
    assert endpoint_shape_hash("https://h/users/deadbeefcafebabe") == base  # long hex


def test_distinct_slugs_stay_distinct():
    # Non-opaque segments (usernames, slugs) are NOT collapsed — distinct surfaces stay distinct.
    assert endpoint_shape_hash("https://h/users/alice") != endpoint_shape_hash("https://h/users/bob")


# --- privacy: no raw value/token/PII in the canonical or hash -------------------------------------


def test_canonical_drops_query_values_keeps_only_names():
    # The canonical dict is an in-memory PRE-IMAGE (never persisted). Query VALUES must never
    # appear in it — only sorted param names survive. (Path segments ARE kept to keep surfaces
    # distinct; privacy for those comes from the hash, asserted below and in the DB tests.)
    url = "https://h/reset/secret-token-abc123?token=SUPERSECRET&email=mario.rossi@example.com"
    canon = canonical_endpoint(url)
    blob = repr(canon)
    for value_leak in ("SUPERSECRET", "mario.rossi", "example.com"):
        assert value_leak not in blob  # query values never participate
    assert canon["params"] == ["email", "token"]  # only param NAMES survive


def test_persisted_hash_leaks_no_path_secret():
    # The hash is the ONLY persisted form — even path secrets that live in the pre-image are gone.
    url = "https://h/reset/secret-token-abc123?token=SUPERSECRET"
    h = endpoint_shape_hash(url)
    assert _HEX64.match(h)
    for leak in ("secret-token-abc123", "SUPERSECRET"):
        assert leak not in h


def test_hash_output_carries_no_input_substring():
    url = "https://h/invite/1a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d?jwt=eyJhbGciOi"
    h = endpoint_shape_hash(url)
    assert _HEX64.match(h)
    assert "eyJhbGciOi" not in h


def test_version_is_part_of_identity():
    canon = canonical_endpoint("https://h/x")
    assert canon["v"] == IDENTITY_VERSION


def test_method_distinguishes_when_supplied():
    assert endpoint_shape_hash("https://h/x", method="get") != endpoint_shape_hash("https://h/x", method="post")
    # method is uppercased → case-insensitive
    assert endpoint_shape_hash("https://h/x", method="get") == endpoint_shape_hash("https://h/x", method="GET")
    # omitting method ≠ supplying one
    assert endpoint_shape_hash("https://h/x") != endpoint_shape_hash("https://h/x", method="GET")
