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


def normalize_severity(value) -> Optional[str]:
    """A severity is an optional lower-cased string; a non-string is uninterpretable."""
    if value is None:
        return None
    if not isinstance(value, str):
        raise RuleResolutionError(f"uninterpretable severity: {value!r}")
    s = value.strip().lower()
    return s or None


def normalize_tags(value) -> tuple[str, ...]:
    """Tags may be a comma-separated string or a list of strings; anything else is
    uninterpretable. Normalised: lower-cased, trimmed, de-duplicated, sorted."""
    if value is None:
        return ()
    if isinstance(value, str):
        raw = value.split(",")
    elif isinstance(value, (list, tuple)):
        raw = value
    else:
        raise RuleResolutionError(f"uninterpretable tags: {value!r}")
    out: set[str] = set()
    for t in raw:
        if not isinstance(t, str):
            raise RuleResolutionError(f"uninterpretable tag element: {t!r}")
        s = t.strip().lower()
        if s:
            out.add(s)
    return tuple(sorted(out))


def canonical_active_control(control, path: str = "$") -> dict:
    """Canonical structure of ONE active control, shared by 2B (revision) and 2C
    (catalog) so they never disagree. Includes everything that defines the control's
    behaviour — id, severity, tags, config — so changing any of them moves the
    identity. ``enabled`` is intentionally absent: the digest is taken over the active
    set only. Fail-closed on empty id / uninterpretable severity or tags / bad config.
    """
    if isinstance(control, Mapping):
        cid = str(control.get("id", "")).strip()
        severity = normalize_severity(control.get("severity"))
        tags = list(normalize_tags(control.get("tags")))
        cfg = control.get("config")
    else:  # (id, config) pair — no severity/tags
        cid = str(control[0]).strip()
        severity = None
        tags = []
        cfg = control[1] if len(control) > 1 else None
    if not cid:
        raise RuleResolutionError(f"{path}: empty control id")
    return {
        "id": cid,
        "severity": severity,
        "tags": tags,
        "config": canonical_json_value({} if cfg is None else cfg, f"{path}.config"),
    }


def compute_misconfig_rule_revision(controls: Iterable) -> str:
    """Deterministic revision for the built-in misconfig engine.

    ``controls`` is an iterable of mappings ``{"id","severity","tags","config"}`` (or
    ``(id, config)`` pairs). The canonical structure hashed is::

        {"schema_version": 1,
         "controls": [{"id","severity","tags","config"}, ...]}   # sorted by id

    Requirements (all fail-closed): non-empty id; NO duplicate ids; at least one
    control; interpretable severity/tags; supported config values. Because severity
    and tags are part of the structure, editing them moves the revision — so the
    2C catalog can never diverge from the policy identity. Pure.
    """
    norm: list[dict] = []
    seen: set[str] = set()
    for i, c in enumerate(controls or []):
        canon = canonical_active_control(c, f"$.controls[{i}]")
        cid = canon["id"]
        if cid in seen:
            raise RuleResolutionError(f"compute_misconfig_rule_revision: duplicate control id {cid!r}")
        seen.add(cid)
        norm.append(canon)
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


@dataclass(frozen=True)
class ResolvedRuleFile:
    """One resolved rule file, with its bytes retained for a single-read snapshot."""

    relative_path: str
    content: bytes
    content_digest: str


@dataclass(frozen=True)
class ResolvedRuleSnapshot:
    """A single filesystem read: the revision AND the exact bytes it was taken over.

    Wiring 2B → 2C should pass THIS to the catalog so both observe the same snapshot
    (no second, possibly-divergent discovery). ``resolve_nuclei_rule_revision`` remains
    for callers that only need the digest and don't want to retain bytes.
    """

    revision: RuleRevision
    files: tuple[ResolvedRuleFile, ...]  # sorted by relative_path


def _default_read_bytes(path: str) -> bytes:
    with open(path, "rb") as fh:
        return fh.read()


def _within(base_real: str, target_real: str) -> bool:
    try:
        return os.path.commonpath([base_real, target_real]) == base_real
    except ValueError:  # different drives / mixed abs+rel
        return False


def _resolve_nuclei_files(base_dir, rule_roots, read_bytes) -> dict[str, ResolvedRuleFile]:
    """Read the selected rule files ONCE (fail-closed). Shared by the revision and
    snapshot resolvers so there is a single walk. Returns {rel_path: ResolvedRuleFile}.

    Fail-closed on: missing/non-dir base; a root that is absolute, has a traversal
    segment, is missing, or escapes the base; an unreadable file; a symlink whose
    target escapes the base; two logical paths resolving to the same real file; a
    zero-rule selection. The LOGICAL relative path (symlinks not dereferenced in the
    path) is the identity; symlink targets are only checked for containment.
    """
    base_abs = os.path.abspath(base_dir)
    base_real = os.path.realpath(base_dir)
    if not os.path.isdir(base_real):
        raise RuleResolutionError(f"base_dir is not a directory: {base_dir}")

    roots = list(rule_roots) if rule_roots else [""]
    files: dict[str, ResolvedRuleFile] = {}  # logical rel -> file
    real_to_rel: dict[str, str] = {}  # real path -> logical rel (ambiguity guard)

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
        for dirpath, dirs, names in os.walk(root_dir, followlinks=True):
            dp_real = os.path.realpath(dirpath)
            if not _within(base_real, dp_real):
                raise RuleResolutionError(f"directory escapes base_dir: {dirpath}")
            if dp_real in visited_dirs:  # symlink loop guard
                dirs[:] = []
                continue
            visited_dirs.add(dp_real)

            for name in names:
                if not name.lower().endswith(_RULE_SUFFIXES):
                    continue
                abs_path = os.path.join(dirpath, name)
                real_path = os.path.realpath(abs_path)
                if not _within(base_real, real_path):
                    raise RuleResolutionError(f"symlink target escapes base_dir: {abs_path}")
                rel = _validate_rel_path(os.path.relpath(abs_path, base_abs))

                prev_rel = real_to_rel.get(real_path)
                if prev_rel is not None and prev_rel != rel:
                    raise RuleResolutionError(f"ambiguous rule: {rel!r} and {prev_rel!r} resolve to the same file")
                if rel in files:  # same logical path via overlapping roots — count once
                    continue
                try:
                    data = read_bytes(abs_path)
                except OSError as exc:
                    raise RuleResolutionError(f"cannot read rule file {abs_path}: {exc}") from exc
                files[rel] = ResolvedRuleFile(rel, data, content_digest(data))
                real_to_rel[real_path] = rel

    if not files:
        raise RuleResolutionError("resolve: zero rules selected")
    return files


def _rule_revision_from_files(files: dict[str, ResolvedRuleFile]) -> RuleRevision:
    digest = compute_rule_revision((f.relative_path, f.content_digest) for f in files.values())
    paths = tuple(sorted(files))
    total = sum(len(f.content) for f in files.values())
    return RuleRevision(digest=digest, rule_count=len(paths), total_bytes=total, relative_paths=paths)


def resolve_nuclei_rule_revision(
    base_dir: str,
    rule_roots: Sequence[str],
    *,
    read_bytes: Callable[[str], bytes] = _default_read_bytes,
) -> RuleRevision:
    """Resolve the digest of the Nuclei rules selected by ``rule_roots`` (bytes not
    retained). See ``_resolve_nuclei_files`` for the fail-closed contract."""
    return _rule_revision_from_files(_resolve_nuclei_files(base_dir, rule_roots, read_bytes))


def resolve_nuclei_rule_snapshot(
    base_dir: str,
    rule_roots: Sequence[str],
    *,
    read_bytes: Callable[[str], bytes] = _default_read_bytes,
) -> ResolvedRuleSnapshot:
    """Single-read snapshot: the revision AND the exact bytes, for handing to 2C so it
    never re-walks the filesystem. Same fail-closed contract as the revision resolver."""
    files = _resolve_nuclei_files(base_dir, rule_roots, read_bytes)
    revision = _rule_revision_from_files(files)
    ordered = tuple(files[p] for p in sorted(files))
    return ResolvedRuleSnapshot(revision=revision, files=ordered)


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
