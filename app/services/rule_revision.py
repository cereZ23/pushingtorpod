"""Rule-revision resolver — the deterministic content digest of the rules a pass runs.

``rule_revision`` is the INPUT the scan-policy manifest ([[scan_policy]]) treats as
the identity of *which rule content* was in play. This module computes it — purely
from real bytes — and resolves the engine version. It stays OUT of the database and
is change-visible by design: it hashes the actual file bytes every time (no newline
or YAML normalisation, no metadata cache), so any file edit always moves the
revision. A cache keyed on metadata could hide an edit, so there is none.

Two engines:
  - Nuclei: revision = SHA256 over a versioned, length-prefixed binary serialisation
    of (len(rel_path) ‖ rel_path ‖ SHA256(file_bytes)) for every selected template
    file, sorted by rel_path (relative to the templates home, POSIX, no case-folding)
    — stable across machines, sensitive to BOTH path and content, and immune to any
    path character (a filename may even contain a newline).
  - builtin_misconfig: revision = SHA256 over canonical JSON of the active controls
    (sorted id + per-control config) — NOT a template tree.

Fail-closed: a missing base/root, an unreadable file, a symlink escaping the base, an
ambiguous path, or a zero-rule selection all raise ``RuleResolutionError`` — the
caller must then produce non-authorising coverage, never a plausible-but-wrong policy.

Scope note (Step 2B): this proves *content identity*. Which detectors are actually
applicable (template-id enumeration → scan_policy_templates) is Step 2C — a different
property, kept separate on purpose.
"""

from __future__ import annotations

import enum
import hashlib
import json
import math
import os
import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import PurePath
from typing import Callable, Iterable, Optional, Sequence

_RULE_SUFFIXES = (".yaml", ".yml")
_REVISION_PREFIX = b"rule-revision-v2"
_MISCONFIG_SCHEMA_VERSION = 1
_HEX64_RE = re.compile(r"[0-9a-f]{64}")


class RuleResolutionError(Exception):
    """Raised when the rule set / engine version cannot be determined (fail-closed)."""


# --- pure content digest -----------------------------------------------------


def content_digest(data: bytes) -> str:
    """SHA-256 hex of a single rule file's raw bytes (no normalisation)."""
    return hashlib.sha256(data).hexdigest()


def _validate_rel_path(raw) -> str:
    """Validate + normalise a relative rule path (fail-closed).

    Rejects: empty; absolute (leading '/' or a Windows drive); any '..' segment
    (traversal); NUL. A newline is ALLOWED — the v2 encoding is length-prefixed, so a
    filename containing '\\n' is unambiguous. '.' segments and '//' collapse.
    """
    p = str(raw).replace("\\", "/")
    if "\x00" in p:
        raise RuleResolutionError(f"rule path contains NUL: {p!r}")
    if p.startswith("/"):
        raise RuleResolutionError(f"rule path is absolute: {p!r}")
    if len(p) >= 2 and p[1] == ":":  # C:/... Windows drive
        raise RuleResolutionError(f"rule path is absolute: {p!r}")
    segments = p.split("/")
    if any(seg == ".." for seg in segments):
        raise RuleResolutionError(f"rule path has a traversal segment: {p!r}")
    parts = [s for s in segments if s not in ("", ".")]
    if not parts:
        raise RuleResolutionError(f"rule path is empty: {raw!r}")
    return "/".join(parts)


# Back-compat alias for the resolver's internal normalisation of clean rel paths.
def _posix_rel(path: str) -> str:
    return _validate_rel_path(path)


def compute_rule_revision(entries: Iterable[tuple[str, str]]) -> str:
    """Deterministic revision from (rel_path, content_digest) pairs (pure).

    Serialisation is length-prefixed binary (v2) so no path character can blur entry
    boundaries::

        sha256( b"rule-revision-v2"
                + for each entry, sorted by path:
                    len(path_utf8):4-byte-big-endian || path_utf8 || digest:32-byte )

    Validated, since this public pure function has no filesystem to lean on: each path
    non-empty, relative, no '..' segment, no NUL (newline allowed); each digest exactly
    64 hex; NO duplicate path (always rejected — even with an identical digest). Order-
    independent and sensitive to both path and content. Raises on an empty selection.
    """
    seen: dict[str, str] = {}
    for rel, digest in entries:
        path = _validate_rel_path(rel)
        norm_digest = str(digest).strip().lower()
        if not _HEX64_RE.fullmatch(norm_digest):
            raise RuleResolutionError(f"compute_rule_revision: invalid content digest for {path!r}")
        if path in seen:
            raise RuleResolutionError(f"compute_rule_revision: duplicate path {path!r}")
        seen[path] = norm_digest
    if not seen:
        raise RuleResolutionError("compute_rule_revision: empty rule selection")
    hasher = hashlib.sha256()
    hasher.update(_REVISION_PREFIX)
    for path in sorted(seen):
        path_bytes = path.encode("utf-8")
        hasher.update(len(path_bytes).to_bytes(4, "big"))
        hasher.update(path_bytes)
        hasher.update(bytes.fromhex(seen[path]))
    return hasher.hexdigest()


def canonical_json_value(value, path: str = "$"):
    """Strictly canonicalise a value to deterministic JSON-safe types (fail-closed).

    A config error must NOT become a valid-but-unreliable policy — there is no
    ``default=str`` fallback. Supported: None; bool (checked BEFORE int); Enum (by
    .value); int; finite float; str; list/tuple; dict with string keys; Path (POSIX
    form). NaN/Inf, sets, custom objects and non-string keys raise
    ``RuleResolutionError`` with the offending JSON path (e.g. ``$.controls[2].config.timeout``).
    """
    if value is None:
        return None
    if isinstance(value, bool):  # before int — bool is an int subclass
        return value
    if isinstance(value, enum.Enum):  # before int/str — IntEnum/StrEnum use .value
        return canonical_json_value(value.value, path)
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise RuleResolutionError(f"{path}: non-finite float ({value})")
        return value
    if isinstance(value, str):
        return value
    if isinstance(value, PurePath):
        return value.as_posix()
    if isinstance(value, (list, tuple)):
        return [canonical_json_value(v, f"{path}[{i}]") for i, v in enumerate(value)]
    if isinstance(value, Mapping):
        out = {}
        for k, v in value.items():
            if not isinstance(k, str):
                raise RuleResolutionError(f"{path}: non-string dict key {k!r}")
            out[k] = canonical_json_value(v, f"{path}.{k}")
        return out
    raise RuleResolutionError(f"{path}: unsupported value type {type(value).__name__}")


def compute_misconfig_rule_revision(controls: Iterable) -> str:
    """Deterministic revision for the built-in misconfig engine.

    ``controls`` is an iterable of either mappings ``{"id": str, "config": dict}`` or
    ``(id, config)`` pairs. The canonical structure hashed is::

        {"schema_version": 1, "controls": [{"id": ..., "config": {...}}, ...]}

    with controls sorted by id and all keys sorted. Requirements (all fail-closed):
    non-empty id; NO duplicate ids; at least one control; every config value of a
    supported type (see ``_canon_config``). Secrets, if they truly change execution,
    belong in ``config`` (hashed) — but never surface them in diagnostics. Pure.
    """
    norm: list[dict] = []
    seen: set[str] = set()
    for i, c in enumerate(controls or []):
        if isinstance(c, Mapping):
            cid = str(c.get("id", "")).strip()
            cfg = c.get("config")
        else:  # (id, config) pair
            cid = str(c[0]).strip()
            cfg = c[1] if len(c) > 1 else None
        if not cid:
            raise RuleResolutionError("compute_misconfig_rule_revision: empty control id")
        if cid in seen:
            raise RuleResolutionError(f"compute_misconfig_rule_revision: duplicate control id {cid!r}")
        seen.add(cid)
        canon_cfg = canonical_json_value({} if cfg is None else cfg, f"$.controls[{i}].config")
        norm.append({"id": cid, "config": canon_cfg})
    if not norm:
        raise RuleResolutionError("compute_misconfig_rule_revision: no active controls")
    norm.sort(key=lambda x: x["id"])
    payload = json.dumps(
        {"schema_version": _MISCONFIG_SCHEMA_VERSION, "controls": norm},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


# --- filesystem resolver (fail-closed) ---------------------------------------


@dataclass(frozen=True)
class RuleRevision:
    """A resolved rule set: its content digest + diagnostics (no content retained)."""

    digest: str
    rule_count: int
    total_bytes: int
    relative_paths: tuple[str, ...]  # sorted, relative to the templates home (POSIX)


def _default_read_bytes(path: str) -> bytes:
    with open(path, "rb") as fh:
        return fh.read()


def _within(base_real: str, target_real: str) -> bool:
    try:
        return os.path.commonpath([base_real, target_real]) == base_real
    except ValueError:  # different drives / mixed abs+rel
        return False


def resolve_nuclei_rule_revision(
    base_dir: str,
    rule_roots: Sequence[str],
    *,
    read_bytes: Callable[[str], bytes] = _default_read_bytes,
) -> RuleRevision:
    """Resolve the Nuclei rule content selected by ``rule_roots`` under ``base_dir``.

    The CALLER passes the policy's roots (e.g. ["http/cves", "http/exposures"], or
    [""] for the whole base) — the resolver never implicitly globs "all templates",
    so the digest can't include rules the pass wouldn't run.

    Fail-closed on: missing/non-dir base; a root that is missing, escapes the base, or
    is non-dir; an unreadable file; a symlink whose target escapes the base; two
    logical paths resolving to the same real file; a zero-rule selection.

    The LOGICAL relative path (as reached, symlinks not dereferenced in the path) is
    what goes into the digest; symlink targets are only checked for containment. Note:
    if both an internal alias and its real file fall within the selected roots, they
    are two logical paths for one file and resolution FAILS — consistent with the
    "one file, one logical identity" rule (a same-path overlap across roots is fine).
    """
    base_abs = os.path.abspath(base_dir)
    base_real = os.path.realpath(base_dir)
    if not os.path.isdir(base_real):
        raise RuleResolutionError(f"base_dir is not a directory: {base_dir}")

    roots = list(rule_roots) if rule_roots else [""]
    entries: dict[str, str] = {}  # logical rel -> content digest
    real_to_rel: dict[str, str] = {}  # real path -> logical rel (ambiguity guard)
    total_bytes = 0

    for root in roots:
        r = str(root).replace("\\", "/")
        if r in ("", "."):
            root_rel = ""  # whole base
        else:
            if r.startswith("/") or (len(r) >= 2 and r[1] == ":"):
                raise RuleResolutionError(f"rule root is absolute: {root!r}")
            if any(seg == ".." for seg in r.split("/")):
                raise RuleResolutionError(f"rule root has a traversal segment: {root!r}")
            root_rel = "/".join(s for s in r.split("/") if s not in ("", "."))
        root_dir = os.path.join(base_abs, root_rel) if root_rel else base_abs
        if not os.path.isdir(root_dir) or not _within(base_real, os.path.realpath(root_dir)):
            raise RuleResolutionError(f"rule root missing or escapes base_dir: {root!r}")

        visited_dirs: set[str] = set()
        for dirpath, dirs, files in os.walk(root_dir, followlinks=True):
            dp_real = os.path.realpath(dirpath)
            if not _within(base_real, dp_real):
                raise RuleResolutionError(f"directory escapes base_dir: {dirpath}")
            if dp_real in visited_dirs:  # symlink loop guard
                dirs[:] = []
                continue
            visited_dirs.add(dp_real)

            for name in files:
                if not name.lower().endswith(_RULE_SUFFIXES):
                    continue
                abs_path = os.path.join(dirpath, name)
                real_path = os.path.realpath(abs_path)
                if not _within(base_real, real_path):
                    raise RuleResolutionError(f"symlink target escapes base_dir: {abs_path}")
                rel = _posix_rel(os.path.relpath(abs_path, base_abs))

                prev_rel = real_to_rel.get(real_path)
                if prev_rel is not None and prev_rel != rel:
                    raise RuleResolutionError(
                        f"ambiguous rule: {rel!r} and {prev_rel!r} resolve to the same file"
                    )
                if rel in entries:  # same logical path via overlapping roots — count once
                    continue
                try:
                    data = read_bytes(abs_path)
                except OSError as exc:
                    raise RuleResolutionError(f"cannot read rule file {abs_path}: {exc}") from exc
                entries[rel] = content_digest(data)
                real_to_rel[real_path] = rel
                total_bytes += len(data)

    digest = compute_rule_revision(entries.items())  # raises on empty selection
    paths = tuple(sorted(entries))
    return RuleRevision(digest=digest, rule_count=len(paths), total_bytes=total_bytes, relative_paths=paths)


# --- engine version resolver (injected runner) -------------------------------


@dataclass(frozen=True)
class CompletedCommand:
    """Minimal result shape for an injected command runner (subprocess-compatible)."""

    returncode: int
    stdout: str = ""
    stderr: str = ""


_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
_VERSION_RE = re.compile(r"v?(\d+\.\d+\.\d+(?:-[0-9A-Za-z.]+)?)")


def _as_text(v) -> str:
    if isinstance(v, (bytes, bytearray)):
        return v.decode("utf-8", "replace")
    return v or ""


def parse_nuclei_version(text: str) -> str:
    """Extract and normalise the semver from version output (ANSI-stripped).

    Returns the version WITHOUT a leading 'v' so that "v3.3.1" and "3.3.1" can never
    produce two different policies. Pure; raises if nothing parseable.
    """
    clean = _ANSI_RE.sub("", _as_text(text))
    m = _VERSION_RE.search(clean)
    if not m:
        raise RuleResolutionError(f"could not parse nuclei version from: {text!r}")
    return m.group(1)


def resolve_nuclei_version(
    runner: Callable[[Sequence[str]], CompletedCommand],
    *,
    argv: Sequence[str] = ("nuclei", "-version"),
) -> str:
    """Resolve the Nuclei engine version via an injected runner (fail-closed).

    Handles version text on stdout OR stderr, a leading 'v', surrounding text, and
    ANSI colour. A non-zero exit, a runner failure/timeout, or unparseable output all
    raise ``RuleResolutionError`` — the caller never builds a manifest with an unknown
    engine version.
    """
    try:
        result = runner(list(argv))
    except Exception as exc:  # missing binary, timeout, OSError …
        raise RuleResolutionError(f"nuclei version probe failed: {exc}") from exc
    if getattr(result, "returncode", 1) != 0:
        raise RuleResolutionError(f"nuclei -version exited {result.returncode}")
    combined = f"{_as_text(result.stdout)}\n{_as_text(result.stderr)}"
    return parse_nuclei_version(combined)
