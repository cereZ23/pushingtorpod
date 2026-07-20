"""Finding confidence classification: presumptive vs confirmed.

A finding is *presumptive* when detection is inferred from a version banner
rather than proven by matching an exploit or behavioural response — e.g.
nuclei's version-check matchers. Such findings need manual validation before
being reported to a client as exploitable (the Roundcube CVE-2025-49113 case:
a vulnerable version was detected, but no working exploit was demonstrated).

Everything else — a template that matched an actual response condition — is
treated as *confirmed* detection of the condition it tests for.

This is a deliberately conservative heuristic keyed off the nuclei matcher
name / tags. It classifies *how the match was made*, NOT whether the issue is
remotely exploitable. It never upgrades a finding to "confirmed exploit".
"""

from __future__ import annotations

import json
import re
from typing import Optional

PRESUMPTIVE = "presumptive"
CONFIRMED = "confirmed"

_VERSION_HINT = re.compile(r"version", re.IGNORECASE)


def derive_confidence(
    matcher_name: Optional[str] = None,
    template_id: Optional[str] = None,
    tags: Optional[list] = None,
) -> str:
    """Classify a nuclei finding as ``presumptive`` or ``confirmed``.

    Presumptive when the match is version-derived (nuclei version-check
    matcher, or a version tag); confirmed otherwise.
    """
    if matcher_name and _VERSION_HINT.search(str(matcher_name)):
        return PRESUMPTIVE
    for tag in tags or []:
        if _VERSION_HINT.search(str(tag)):
            return PRESUMPTIVE
    return CONFIRMED


def confidence_from_evidence(evidence) -> str:
    """Read the stored confidence from a finding's ``evidence``.

    ``evidence`` may be a dict or a JSON string (the repository json.dumps it
    before insert). Findings written before this feature have no ``confidence``
    key; they default to ``confirmed`` (the non-alarming default — only
    version-check findings are ever presumptive).
    """
    data = evidence
    if isinstance(data, str):
        try:
            data = json.loads(data)
        except (ValueError, TypeError):
            return CONFIRMED
    if isinstance(data, dict):
        value = data.get("confidence")
        if value in (PRESUMPTIVE, CONFIRMED):
            return value
    return CONFIRMED
