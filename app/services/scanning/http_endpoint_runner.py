"""http_endpoint runner contract + execution evidence (Sprint 3, step 3b).

The orchestrator (``http_endpoint_orchestrator``) drives the pass; the RUNNER is the injected
subprocess boundary that actually invokes Nuclei on one batch and returns structured evidence. The
concrete Nuclei runner + its evidence extraction lands in 3b-2 — this module defines the shared
contract so the orchestrator is fully testable against a fake runner.

Fail-closed philosophy: ``BatchExecutionEvidence`` carries POSITIVE PROOF of completion
(``output_complete`` / ``catalog_verified`` / ``targets_completed`` + the raw counts they derive
from), never just the absence of errors. The orchestrator maps it via ``endpoint_pass.batch_verdict``
so COVERED is only reachable with real proof. No repr exposes a URL / path / Nuclei output.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Mapping, Optional, Protocol, runtime_checkable


class EndpointRunnerError(Exception):
    """A structural runner failure (process unstartable, staging/exec error) → batch FAILED.

    Carries a reason code only — NEVER a URL / target / command / output.
    """


class EndpointRunnerTimeout(EndpointRunnerError):
    """The batch exceeded its timeout / budget → batch PARTIAL (incompleteness, not a hard failure)."""


@dataclass(frozen=True)
class BatchExecutionEvidence:
    """What the runner observed for ONE batch — the raw counts + the derived positive proofs.

    ``findings`` are the normalised Nuclei result dicts (each SHOULD carry the input target so the
    orchestrator can attribute by target, not by a tenant-wide hostname search). ``repr`` deliberately
    hides the findings and every count-free detail that could leak a target.
    """

    launched: bool
    exit_code: Optional[int]
    timed_out: bool = False
    budget_expired: bool = False
    truncated: bool = False
    drift: bool = False
    unresponsive_targets: int = 0
    targets_loaded: Optional[int] = None
    templates_loaded: Optional[int] = None
    completion_percent: Optional[int] = None
    output_complete: bool = False
    catalog_verified: bool = False
    targets_completed: bool = False
    parse_incomplete: bool = False
    duration_seconds: float = 0.0
    findings: tuple[dict, ...] = field(default_factory=tuple)

    def __repr__(self) -> str:  # counts + proofs only — never a URL / finding body
        return (
            f"BatchExecutionEvidence(launched={self.launched}, exit={self.exit_code}, "
            f"timed_out={self.timed_out}, targets_loaded={self.targets_loaded}, "
            f"templates_loaded={self.templates_loaded}, completion={self.completion_percent}, "
            f"unresponsive={self.unresponsive_targets}, output_complete={self.output_complete}, "
            f"catalog_verified={self.catalog_verified}, targets_completed={self.targets_completed}, "
            f"parse_incomplete={self.parse_incomplete}, findings={len(self.findings)})"
        )


@runtime_checkable
class EndpointNucleiRunner(Protocol):
    """The subprocess boundary the orchestrator injects. A real impl runs Nuclei on the staged
    template dir + a batch target file; a fake impl returns canned evidence for tests.

    Contract: run Nuclei with ``-l <target_file> -t <template_dir> -jsonl -no-color -duc -stats
    -si 30``; ``-ni`` when ``interactsh_server`` is falsy else ``-iserver <server>``; NEVER pass a
    capability flag (``-code``/``-headless``/``-dast``/``-esc``) whose policy flag is "false", and if
    the CLI capabilities diverge from ``relevant_flags`` do not launch. Never log the target list or
    full JSONL lines.
    """

    def run_batch(
        self,
        *,
        tenant_id: int,
        target_file: str,
        template_dir: str,
        expected_targets: int,
        expected_templates: int,
        timeout_seconds: int,
        interactsh_server: Optional[str],
        relevant_flags: Mapping[str, str],
    ) -> BatchExecutionEvidence: ...
