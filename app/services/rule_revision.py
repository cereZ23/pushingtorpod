"""Rule-revision resolver — the deterministic content digest of the rules a pass runs.

``rule_revision`` is the INPUT the scan-policy manifest ([[scan_policy]]) treats as
the identity of *which rule content* was in play. This module computes it — purely
from real bytes — and resolves the engine version. It stays OUT of the database and
is change-visible by design: it hashes the actual file bytes every time (no newline
or YAML normalisation, no metadata cache), so any file edit always moves the
revision. A cache keyed on metadata could hide an edit, so there is none.

Two engines:
  - Nuclei: revision = SHA256 over a versioned, sorted serialisation of
    (``rel_path`` ‖ NUL ‖ SHA256(file_bytes)) for every selected template file, with
    rel_path relative to the templates home (POSIX, no case-folding) — stable across
    machines and sensitive to BOTH path and content.
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

import hashlib
import json
import os
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Callable, Iterable, Optional, Sequence

_RULE_SUFFIXES = (".yaml", ".yml")
_REVISION_PREFIX = "rule-revision-v1"
_MISCONFIG_SCHEMA_VERSION = 1


class RuleResolutionError(Exception):
    """Raised when the rule set / engine version cannot be determined (fail-closed)."""


# --- pure content digest -----------------------------------------------------


def content_digest(data: bytes) -> str:
    """SHA-256 hex of a single rule file's raw bytes (no normalisation)."""
    return hashlib.sha256(data).hexdigest()


def _posix_rel(path: str) -> str:
    """Stable, OS-independent relative path: forward slashes, no leading './' or '/'."""
    p = str(path).replace("\\", "/").replace(os.sep, "/")
    while p.startswith("./"):
        p = p[2:]
    return p.strip("/")


def compute_rule_revision(entries: Iterable[tuple[str, str]]) -> str:
    """Deterministic revision from (rel_path, content_digest) pairs.

    Serialisation (versioned so the scheme can evolve without silent collisions):

        rule-revision-v1\\0
        relative/path.yaml\\0<sha256>
        ...                              (entries sorted by relative path)

    Order-independent and sensitive to both path and content. Pure. Raises on an
    empty selection — an empty rule set must never mint a valid revision.
    """
    lines = sorted(f"{_posix_rel(rel)}\x00{digest}" for rel, digest in entries)
    if not lines:
        raise RuleResolutionError("compute_rule_revision: empty rule selection")
    serialised = _REVISION_PREFIX + "\x00\n" + "\n".join(lines)
    return hashlib.sha256(serialised.encode()).hexdigest()


def compute_misconfig_rule_revision(controls: Iterable) -> str:
    """Deterministic revision for the built-in misconfig engine.

    ``controls`` is an iterable of either mappings ``{"id": str, "config": dict}`` or
    ``(id, config)`` pairs. The canonical structure hashed is::

        {"schema_version": 1, "controls": [{"id": ..., "config": {...}}, ...]}

    with controls sorted by id and all keys sorted. Requirements (all fail-closed):
    non-empty id; NO duplicate ids; at least one control. Secrets, if they truly
    change execution, belong in ``config`` (hashed) — but never surface them in
    diagnostics elsewhere. Pure.
    """
    norm: list[dict] = []
    seen: set[str] = set()
    for c in controls or []:
        if isinstance(c, Mapping):
            cid = str(c.get("id", "")).strip()
            cfg = c.get("config") or {}
        else:  # (id, config) pair
            cid = str(c[0]).strip()
            cfg = (c[1] if len(c) > 1 else None) or {}
        if not cid:
            raise RuleResolutionError("compute_misconfig_rule_revision: empty control id")
        if cid in seen:
            raise RuleResolutionError(f"compute_misconfig_rule_revision: duplicate control id {cid!r}")
        seen.add(cid)
        norm.append({"id": cid, "config": cfg})
    if not norm:
        raise RuleResolutionError("compute_misconfig_rule_revision: no active controls")
    norm.sort(key=lambda x: x["id"])
    payload = json.dumps(
        {"schema_version": _MISCONFIG_SCHEMA_VERSION, "controls": norm},
        sort_keys=True,
        separators=(",", ":"),
        default=str,  # never crash on an exotic config value; str repr is deterministic
    )
    return hashlib.sha256(payload.encode()).hexdigest()


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
    what goes into the digest; symlink targets are only checked for containment.
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
        root_rel = _posix_rel(root)
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
