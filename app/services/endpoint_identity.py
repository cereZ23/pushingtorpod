"""Canonical endpoint IDENTITY hash — the single load-bearing key for endpoint coverage (Sprint 2).

We persist ONLY a SHA-256 hash (``endpoint_shape_hash``, 64 lowercase hex), NEVER the URL / path /
query — so NO CLEARTEXT DATA (reset tokens, usernames, UUIDs, emails carried in the path or query)
is ever stored in the coverage or finding tables. This is confidentiality-at-rest, NOT a claim of
irreversibility: SHA-256 here is UNSALTED, so an attacker who can guess a candidate endpoint can
confirm it by recomputing the hash — predictable surfaces are inferrable. The value is that the
plaintext is absent, not that the identity is un-guessable.

The hash is taken over a VERSIONED canonical JSON, so the identity is stable and collision-safe:

- ``v``       — identity schema version (bump ⇒ every hash changes; old rows stay distinct).
- ``scheme``  — http/https (lowercased). Included so ``http://h/x`` ≠ ``https://h/x``.
- ``host``    — IDNA-encoded, lowercased, trailing dot stripped (hosts are case-insensitive).
- ``port``    — the EFFECTIVE port (default 80/443 filled in). So ``:80`` ≠ ``:443`` ≠ ``:8443``
                never collapse to one coverage row.
- ``path``    — CASE PRESERVED (HTTP paths are case-sensitive) with ONLY clearly-id segments
                collapsed to ``{id}`` (numeric, long hex, or a UUID) so ``/user/1`` and ``/user/2``
                share an identity — for dedup, not privacy (privacy is the hash itself).
- ``params``  — sorted query param NAMES only (never values).
- ``method``  — optional HTTP method, uppercased, when the caller distinguishes verbs.

JSON serialization handles all escaping (no ambiguous ``|``/``,`` joins). Deterministic.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Optional
from urllib.parse import parse_qs, urlparse

IDENTITY_VERSION = 1

# A path segment that is an opaque id → collapse to {id} (dedup only). Numeric, a long hex blob,
# or a UUID. Everything else (usernames, slugs, tokens with punctuation) is kept AS INPUT to the
# hash — never stored, so it cannot leak, but it keeps distinct surfaces distinct.
_NUMERIC_RE = re.compile(r"^\d+$")
_HEX_RE = re.compile(r"^[0-9a-fA-F]{8,}$")
_UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_DEFAULT_PORT = {"http": 80, "https": 443}


def _collapse(seg: str) -> str:
    return "{id}" if (_NUMERIC_RE.match(seg) or _UUID_RE.match(seg) or _HEX_RE.match(seg)) else seg


def canonical_endpoint(url: str, *, method: Optional[str] = None) -> dict:
    """The canonical identity dict the hash is taken over (pure; useful for tests/debugging).

    Fails CLOSED on anything that is not a well-formed web endpoint: the scheme must be http/https,
    a host must be present, and the host must be valid IDNA. An invalid input must never silently
    yield a hash (that would create a bogus coverage identity), so we raise ``ValueError`` instead.
    """
    p = urlparse(url or "")
    scheme = (p.scheme or "").lower()
    if scheme not in ("http", "https"):
        raise ValueError(f"endpoint identity requires an http/https URL, got scheme {scheme!r}")
    host = (p.hostname or "").strip().rstrip(".").lower()
    if not host:
        raise ValueError(f"endpoint identity requires a host, got {url!r}")
    try:
        host = host.encode("idna").decode("ascii")
    except (UnicodeError, ValueError) as exc:
        raise ValueError(f"invalid IDNA host {host!r}: {exc}") from exc
    port = p.port if p.port is not None else _DEFAULT_PORT.get(scheme)
    path = "/".join(_collapse(s) for s in p.path.split("/"))  # case preserved; only id segments collapse
    params = sorted(parse_qs(p.query, keep_blank_values=True).keys())
    canon = {"v": IDENTITY_VERSION, "scheme": scheme, "host": host, "port": port, "path": path, "params": params}
    if method:
        canon["method"] = method.upper()
    return canon


def endpoint_shape_hash(url: str, *, method: Optional[str] = None) -> str:
    """The 64-hex SHA-256 endpoint identity — the ONLY thing persisted (coverage + finding)."""
    blob = json.dumps(canonical_endpoint(url, method=method), sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


_HASH_RE = re.compile(r"^[0-9a-f]{64}$")


def is_shape_hash(value: object) -> bool:
    """True iff ``value`` is a canonical 64-lowercase-hex shape hash — used to fail-closed reject an
    arbitrary string (e.g. a raw URL/query) at the coverage/finding write boundary."""
    return isinstance(value, str) and bool(_HASH_RE.match(value))
