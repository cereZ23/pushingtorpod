"""Sprint 1 (endpoint-aware scanning) — classify a nuclei template as
``host_only`` | ``endpoint_sensitive`` | ``unknown`` purely from its parsed YAML.

Why: the base HTTP-stock pass scans ``BaseURL = <host root>``. It ALREADY covers every
template that appends its own fixed path to ``{{BaseURL}}``/``{{RootURL}}`` (they probe
host-relative paths). What it does NOT cover is a template whose detection depends on being
pointed at a SPECIFIC discovered endpoint — its own path/params. Those are the ones a
dedicated ``http_endpoint`` pass must run against Katana endpoints. This classifier decides
which is which, DETERMINISTICALLY and FAIL-CLOSED: anything uncertain is ``unknown`` and is
never admitted to the endpoint pass without human analysis (Sprint-1 criterion).

Categories:
  - ``host_only``          — no HTTP block (dns/network/tcp/ssl/whois/… target the host/service),
                             OR every HTTP path appends a fixed segment to ``{{BaseURL}}``/uses
                             ``{{RootURL}}`` (the base scan covers the host-root variant).
  - ``endpoint_sensitive`` — an HTTP request hits ``{{BaseURL}}`` AS-IS (no appended path; a
                             query/fuzz placeholder is fine) OR the template fuzzes (``fuzzing:``
                             / dast) — i.e. it tests whatever URL you point it at.
  - ``unknown``            — cannot be decided with confidence (opaque protocol, unparseable raw,
                             unknown path var, no request block, …) → fail-closed.

Known v1 limitation (documented, quantified in the report): a ``{{BaseURL}}/login`` template on
a discovered SUB-APP root (e.g. ``https://host/app/``) would find ``/app/login`` — so some
``host_only`` templates would benefit from directory endpoints. v1 keeps them ``host_only`` (the
base scan covers the host-root variant); refined later.

Pure, DB-free, no I/O. YAML is parsed by the caller (a Mapping is passed in), exactly like
``rule_catalog.enumerate_nuclei_applicable_rules``.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

HOST_ONLY = "host_only"
ENDPOINT_SENSITIVE = "endpoint_sensitive"
UNKNOWN = "unknown"

# Protocol blocks that target a host/service rather than an HTTP path.
_HOST_LEVEL_PROTOCOLS = ("dns", "network", "tcp", "ssl", "tls", "whois")
# Protocol blocks we cannot confidently reason about → unknown (fail-closed). NOTE: ``flow`` is
# deliberately NOT here — it only orchestrates the template's OWN http/dns/… blocks (control flow),
# it does not change WHERE the requests go, so we classify a flow template by its http paths. Real
# report data: treating flow as opaque wrongly parked 843/1083 unknown templates. ``workflows`` IS
# opaque (it references OTHER template files, not a self-contained detection).
_OPAQUE_PROTOCOLS = ("headless", "code", "javascript", "websocket", "workflows")

_BASEURL_RE = re.compile(r"^\{\{\s*BaseURL\s*\}\}", re.IGNORECASE)
_ROOTURL_RE = re.compile(r"^\{\{\s*RootURL\s*\}\}", re.IGNORECASE)
# request-line of a raw HTTP request: "METHOD <path> HTTP/x"
_RAW_REQUEST_LINE_RE = re.compile(r"^\s*[A-Z]+\s+(\S+)\s+HTTP/", re.IGNORECASE)
_FUZZ_TAGS = frozenset({"fuzz", "fuzzing", "dast"})
# Semantic host/domain-level families: their check is about the HOST, not a path — running them
# on discovered endpoints would just duplicate the host-level check. A syntactic {{BaseURL}}-as-is
# match is not enough to call these endpoint-sensitive (e.g. subdomain-takeover templates).
_HOST_LEVEL_TAGS = frozenset({"takeover"})


@dataclass(frozen=True)
class TemplateClass:
    category: str  # HOST_ONLY | ENDPOINT_SENSITIVE | UNKNOWN
    reason: str  # short, human-readable justification for the Sprint-1 report


def _as_seq(value) -> list:
    """A YAML list, normalised; a scalar becomes a single-element list; else []."""
    if isinstance(value, (str, bytes)):
        return [value]
    if isinstance(value, Sequence):
        return list(value)
    if value is None:
        return []
    return [value]


def _http_requests(doc: Mapping):
    """The HTTP request list (new ``http:`` or legacy ``requests:``), or None."""
    for key in ("http", "requests"):
        block = doc.get(key)
        if isinstance(block, Sequence) and not isinstance(block, (str, bytes)):
            return list(block)
    return None


def _tags(doc: Mapping) -> set:
    info = doc.get("info")
    if not isinstance(info, Mapping):
        return set()
    tags = info.get("tags")
    out: set = set()
    for t in _as_seq(tags):
        if isinstance(t, str):
            out.update(p.strip().lower() for p in t.split(",") if p.strip())
    return out


def _path_shape(path: str) -> str:
    """Classify one nuclei URL-path template string.

    Returns: 'base_bare' (endpoint-sensitive), 'base_appended' / 'root' (host_only),
    or 'other' (unparseable / unknown var → unknown).
    """
    s = path.strip()
    m = _BASEURL_RE.match(s)
    if m:
        rest = s[m.end() :]
        rest_path = rest.split("?", 1)[0].split("#", 1)[0]
        if rest_path in ("", "/"):
            return "base_bare"
        if "{{" in rest_path:
            # an unresolved variable in the path SUFFIX (e.g. {{BaseURL}}{{SomePath}}): what it
            # appends depends on the input — cannot prove it is host-only → unknown (fail-closed).
            return "other"
        return "base_appended"
    if _ROOTURL_RE.match(s):
        return "root"  # RootURL is always the host root regardless of input → host-level
    return "other"


def _request_shapes(req: Mapping) -> list:
    """All path shapes of one HTTP request (from ``path:`` list and/or ``raw:`` blocks)."""
    shapes: list = []
    for p in _as_seq(req.get("path")):
        shapes.append(_path_shape(p) if isinstance(p, str) else "other")
    for raw in _as_seq(req.get("raw")):
        if not isinstance(raw, str):
            shapes.append("other")
            continue
        line = next((ln for ln in raw.splitlines() if ln.strip()), "")
        mline = _RAW_REQUEST_LINE_RE.match(line)
        if not mline:
            shapes.append("other")
            continue
        target = mline.group(1)
        if _BASEURL_RE.match(target) or _ROOTURL_RE.match(target):
            shapes.append(_path_shape(target))
        elif target.startswith("/"):
            shapes.append("root")  # host-relative request line → host-level path
        else:
            shapes.append("other")
    return shapes


def _has_fuzzing(doc: Mapping, requests: list) -> bool:
    if _FUZZ_TAGS & _tags(doc):
        return True
    for req in requests:
        if isinstance(req, Mapping) and req.get("fuzzing") is not None:
            return True
    return False


def classify_nuclei_template(doc: Mapping) -> TemplateClass:
    """Classify a parsed nuclei template. Deterministic; fail-closed to ``unknown``."""
    if not isinstance(doc, Mapping):
        return TemplateClass(UNKNOWN, "template is not a mapping")

    # Semantic override: a host/domain-level family (e.g. takeover) is about the HOST, so it is
    # host_only even when its request hits {{BaseURL}} as-is — running it per-endpoint just repeats
    # the host check. This corrects the syntactic classifier for these families.
    if _HOST_LEVEL_TAGS & _tags(doc):
        return TemplateClass(HOST_ONLY, "host/domain-level family (tag) — endpoints add no coverage")

    requests = _http_requests(doc)

    if requests is None:
        # No HTTP block: decide from the other protocol blocks present.
        opaque = [p for p in _OPAQUE_PROTOCOLS if doc.get(p) is not None]
        if opaque:
            return TemplateClass(UNKNOWN, f"opaque protocol(s) {opaque} — cannot reason about targeting")
        host_level = [p for p in _HOST_LEVEL_PROTOCOLS if doc.get(p) is not None]
        if host_level:
            return TemplateClass(HOST_ONLY, f"host/service protocol(s) {host_level} — no HTTP path")
        return TemplateClass(UNKNOWN, "no recognizable request/protocol block")

    # Opaque protocol alongside HTTP → we can't be sure what the browser/code path does.
    opaque = [p for p in _OPAQUE_PROTOCOLS if doc.get(p) is not None]
    if opaque:
        return TemplateClass(UNKNOWN, f"HTTP mixed with opaque protocol(s) {opaque}")

    if _has_fuzzing(doc, requests):
        return TemplateClass(ENDPOINT_SENSITIVE, "fuzzing/dast — exercises the input URL's params")

    shapes: list = []
    for req in requests:
        if not isinstance(req, Mapping):
            return TemplateClass(UNKNOWN, "malformed HTTP request entry")
        shapes.extend(_request_shapes(req))

    if not shapes:
        return TemplateClass(UNKNOWN, "HTTP block with no parseable path/raw")
    if "other" in shapes:
        return TemplateClass(UNKNOWN, "unparseable path / unknown URL variable in a request")
    if "base_bare" in shapes:
        return TemplateClass(ENDPOINT_SENSITIVE, "hits {{BaseURL}} as-is — tests the given endpoint")
    # every shape is base_appended or root
    return TemplateClass(
        HOST_ONLY, "all paths append a fixed segment / use {{RootURL}} — base scan covers the host-root variant"
    )
