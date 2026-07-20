"""
Scanning tool (plugin) manager.

Gives visibility into the external ProjectDiscovery tools the scanner depends on
and lets them be updated in a controlled way. Two concerns it addresses:

1. Silent-failure prevention — a missing or broken binary (or a nuclei with an
   empty templates dir) makes scans quietly under-report. ``check_tools`` reports
   each tool's version (or MISSING/ERROR) so a broken toolchain is caught before
   a scan, not after.

2. Controlled updates — ``update_tools`` refreshes the nuclei templates (verified,
   see TemplateManager) and, optionally, self-updates the tool binaries that
   support it. Tools that are intentionally version-pinned (see ``PINNED_TOOLS``)
   are never auto-updated.
"""

from __future__ import annotations

import logging
import re
from typing import Dict, List, Optional

from app.utils.secure_executor import SecureToolExecutor, ToolExecutionError

logger = logging.getLogger(__name__)

# ProjectDiscovery scanning tools we surface/version. Kept explicit rather than
# derived from the allowlist so utility binaries (notify, etc.) aren't included.
SCANNING_TOOLS: List[str] = [
    "subfinder",
    "dnsx",
    "httpx",
    "naabu",
    "katana",
    "tlsx",
    "nuclei",
    "uncover",
    "alterx",
    "cdncheck",
]

# Tools deliberately pinned to a specific version — NEVER self-updated, because a
# newer release has been observed to regress. Keep the reason with the pin.
PINNED_TOOLS: Dict[str, str] = {
    # httpx 1.6.8 — later builds reintroduced a tech-detect memory leak / behaviour
    # change; keep pinned until re-validated.
    "httpx": "1.6.8",
}

_VERSION_RE = re.compile(r"(\d+\.\d+\.\d+)")


def _tool_version(tool: str) -> Optional[str]:
    """Return the installed version string of a tool, or None if unavailable."""
    try:
        with SecureToolExecutor(0) as executor:
            returncode, stdout, stderr = executor.execute(tool, ["-version"], timeout=30)
    except ToolExecutionError as exc:
        logger.warning("Tool %s failed to report version: %s", tool, exc)
        return None
    # PD tools print the version banner to stderr on most builds.
    blob = f"{stdout}\n{stderr}"
    match = _VERSION_RE.search(blob)
    return match.group(1) if match else None


def check_tools() -> Dict:
    """Inventory the scanning toolchain.

    Returns:
        {
          'tools': {name: {'version': str|None, 'status': 'ok'|'missing'|'pinned',
                           'pinned_to': str|None}},
          'healthy': bool,        # every tool present
          'missing': [names],
        }
    """
    tools: Dict[str, Dict] = {}
    missing: List[str] = []

    for name in SCANNING_TOOLS:
        version = _tool_version(name)
        if version is None:
            tools[name] = {"version": None, "status": "missing", "pinned_to": PINNED_TOOLS.get(name)}
            missing.append(name)
            continue
        status = "pinned" if name in PINNED_TOOLS else "ok"
        tools[name] = {"version": version, "status": status, "pinned_to": PINNED_TOOLS.get(name)}

    result = {"tools": tools, "healthy": not missing, "missing": missing}
    if missing:
        logger.error("Scanning toolchain UNHEALTHY — missing/broken tools: %s", missing)
    else:
        logger.info("Scanning toolchain healthy: %s", {k: v["version"] for k, v in tools.items()})
    return result


def update_tools(update_binaries: bool = False) -> Dict:
    """Update the scanning toolchain.

    Always refreshes nuclei templates (verified via TemplateManager). When
    ``update_binaries`` is True, also self-updates the tool binaries that support
    a ``-update`` flag — except pinned tools, which are skipped.

    Returns a per-component result dict.
    """
    from app.services.scanning.template_manager import template_manager

    result: Dict = {"templates": None, "binaries": {}, "skipped_pinned": []}

    # 1. Templates (hardened: verifies template count on disk)
    result["templates"] = template_manager.update_templates()

    # 2. Binaries (opt-in) — most PD tools self-update with `-update`.
    if update_binaries:
        for name in SCANNING_TOOLS:
            if name in PINNED_TOOLS:
                result["skipped_pinned"].append(name)
                logger.info("Skipping self-update of pinned tool %s (pinned to %s)", name, PINNED_TOOLS[name])
                continue
            try:
                with SecureToolExecutor(0) as executor:
                    returncode, stdout, stderr = executor.execute(name, ["-update"], timeout=120)
                result["binaries"][name] = {"success": returncode == 0, "output": (stdout or stderr)[:400]}
            except ToolExecutionError as exc:
                result["binaries"][name] = {"success": False, "error": str(exc)}
                logger.warning("Self-update failed for %s: %s", name, exc)

    return result
