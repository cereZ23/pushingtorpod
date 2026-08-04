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

import json
import re
import subprocess
import time
from dataclasses import dataclass, field
from typing import Callable, Mapping, Optional, Protocol, Sequence, runtime_checkable


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


# ==================================================================================================
# Concrete runner (Sprint 3, step 3b-2): runs Nuclei once on a staged template dir + a batch target
# file, and extracts POSITIVE PROOF from -stats/-jsonl. The exec is injectable so the parser can be
# unit-tested without Nuclei; the parser is PURE and fail-closed (a proof is True only when the stats
# unambiguously confirm it, else the batch is PARTIAL).
# ==================================================================================================

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
_TEMPLATES_LOADED_RE = re.compile(r"Templates loaded for current scan:\s*(\d+)", re.IGNORECASE)
_TARGETS_LOADED_RE = re.compile(r"Targets loaded for current scan:\s*(\d+)", re.IGNORECASE)
# The -stats interval line ends with e.g. "Requests: 1095/1095 (100%)" — the last one is the finish.
_REQUESTS_PCT_RE = re.compile(r"Requests:\s*\d+/\d+\s*\((\d+)%\)", re.IGNORECASE)
_UNRESPONSIVE_RE = re.compile(r"(\d+)\s+unresponsive", re.IGNORECASE)
_SKIPPED_TARGETS_RE = re.compile(r"skipped\s+(\d+)\b[^\n]*from target list", re.IGNORECASE)

# Nuclei capability flags gated by the policy's relevant_flags (never passed when the value is false).
_CAPABILITY_FLAG = {"code": "-code", "headless": "-headless", "dast": "-dast", "self_contained": "-esc"}


def _finding_from_result(obj: dict) -> dict:
    """Normalise one JSONL result, KEEPING the input target so the orchestrator can attribute by
    target shape (never a hostname search)."""
    info = obj.get("info") if isinstance(obj.get("info"), dict) else {}
    target = obj.get("url") or obj.get("matched-at") or obj.get("host") or obj.get("input")
    return {
        "target": target,
        "template_id": obj.get("template-id"),
        "name": info.get("name") or obj.get("template-id") or "nuclei",
        "severity": info.get("severity") or "info",
        "matcher_name": obj.get("matcher-name"),
    }


def _last_int(pattern: re.Pattern, text: str) -> Optional[int]:
    matches = pattern.findall(text)
    return int(matches[-1]) if matches else None


def parse_nuclei_batch_output(
    returncode: Optional[int],
    stdout: str,
    stderr: str,
    *,
    expected_targets: int,
    expected_templates: Optional[int],
    timed_out: bool = False,
    truncated: bool = False,
    duration_seconds: float = 0.0,
) -> BatchExecutionEvidence:
    """PURE: map a Nuclei run's raw output to conservative positive-proof evidence.

    A proof is True ONLY when the stats unambiguously confirm it; anything unknown stays False so the
    batch degrades to PARTIAL. Findings keep their input ``target`` for attribution.
    """
    findings: list[dict] = []
    parse_incomplete = False
    for line in (stdout or "").splitlines():
        s = line.strip()
        if not s or not s.startswith("{"):  # skip [INF] logs / blanks
            continue
        try:
            findings.append(_finding_from_result(json.loads(s)))
        except Exception:
            parse_incomplete = True  # a result line that won't parse ⇒ output not fully processed

    err = _ANSI_RE.sub("", stderr or "")
    templates_loaded = _last_int(_TEMPLATES_LOADED_RE, err)
    targets_loaded = _last_int(_TARGETS_LOADED_RE, err)
    pcts = _REQUESTS_PCT_RE.findall(err)
    completion_percent = int(pcts[-1]) if pcts else None
    unresponsive = sum(int(x) for x in _UNRESPONSIVE_RE.findall(err)) + sum(
        int(x) for x in _SKIPPED_TARGETS_RE.findall(err)
    )

    catalog_verified = (
        expected_templates is not None and templates_loaded is not None and templates_loaded == expected_templates
    )
    targets_completed = (
        targets_loaded is not None
        and targets_loaded == expected_targets
        and completion_percent == 100
        and unresponsive == 0
        and not timed_out
        and not truncated
    )
    output_complete = (
        returncode == 0 and not parse_incomplete and completion_percent == 100 and not timed_out and not truncated
    )
    return BatchExecutionEvidence(
        launched=True,
        exit_code=returncode,
        timed_out=timed_out,
        truncated=truncated,
        unresponsive_targets=unresponsive,
        targets_loaded=targets_loaded,
        templates_loaded=templates_loaded,
        completion_percent=completion_percent,
        output_complete=output_complete,
        catalog_verified=catalog_verified,
        targets_completed=targets_completed,
        parse_incomplete=parse_incomplete,
        duration_seconds=duration_seconds,
        findings=tuple(findings),
    )


def build_nuclei_args(
    *,
    target_file: str,
    template_dir: str,
    interactsh_server: Optional[str],
    relevant_flags: Mapping[str, str],
    severity: Sequence[str],
    exclude_tags: Sequence[str],
    rate_limit: int,
    concurrency: int,
    request_timeout: int,
    max_host_errors: int,
) -> list[str]:
    """Build the Nuclei CLI args. Runs the staged ``template_dir`` (NOT stock roots) over
    ``target_file``. A capability flag (-code/-headless/-dast/-esc) is added ONLY when the policy's
    relevant_flags enables it — so the CLI can never diverge from the manifest identity. Interactsh
    is -ni unless a server is configured (never let Nuclei pick oast.me)."""
    args = [
        "-l",
        target_file,
        "-t",
        template_dir,
        "-jsonl",
        "-no-color",
        "-duc",
        "-stats",
        "-si",
        "30",
        "-rl",
        str(rate_limit),
        "-c",
        str(concurrency),
        "-timeout",
        str(request_timeout),
        "-retries",
        "0",
        "-mhe",
        str(max_host_errors),
        "-no-httpx",
    ]
    if severity:
        args += ["-severity", ",".join(severity)]
    if exclude_tags:
        args += ["-exclude-tags", ",".join(exclude_tags)]
    for cap, flag in _CAPABILITY_FLAG.items():
        if str(relevant_flags.get(cap, "false")).lower() == "true":
            args.append(flag)
    if interactsh_server:
        args += ["-iserver", interactsh_server, "-itoken", ""]
    else:
        args.append("-ni")
    return args


_NUCLEI_ENV = {
    "PATH": "/usr/local/pd-tools:/usr/local/bin:/usr/bin:/bin",
    "HOME": "/tmp",
    "LANG": "C.UTF-8",
    "NUCLEI_TEMPLATES": "/home/appuser/nuclei-templates",
}


def _default_nuclei_exec(args: list[str], timeout_seconds: int) -> tuple[Optional[int], str, str]:
    """Guarded subprocess: own process group + SIGKILL on timeout. Not routed through
    SecureToolExecutor because the staged/target temp paths are outside its allowed prefixes.
    Raises subprocess.TimeoutExpired on timeout (translated to EndpointRunnerTimeout by the caller)."""
    import os
    import signal

    proc = subprocess.Popen(
        ["nuclei", *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
        env=_NUCLEI_ENV,
    )
    try:
        stdout, stderr = proc.communicate(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except Exception:
            pass
        try:
            proc.communicate(timeout=10)  # reap
        except Exception:
            pass
        raise
    return proc.returncode, stdout or "", stderr or ""


class NucleiEndpointRunner:
    """Concrete ``EndpointNucleiRunner`` — runs one batch through Nuclei and extracts evidence.

    The tier knobs (rate/concurrency/…) are injected at construction (from phase 9). ``exec_fn`` is
    injectable so tests exercise the args + parser without a real subprocess.
    """

    def __init__(
        self,
        *,
        severity: Sequence[str],
        exclude_tags: Sequence[str],
        rate_limit: int = 150,
        concurrency: int = 25,
        request_timeout: int = 10,
        max_host_errors: int = 30,
        exec_fn: Optional[Callable[[list[str], int], tuple[Optional[int], str, str]]] = None,
    ):
        self.severity = list(severity)
        self.exclude_tags = list(exclude_tags)
        self.rate_limit = rate_limit
        self.concurrency = concurrency
        self.request_timeout = request_timeout
        self.max_host_errors = max_host_errors
        self._exec = exec_fn or _default_nuclei_exec

    def run_batch(
        self,
        *,
        tenant_id: int,
        target_file: str,
        template_dir: str,
        expected_targets: int,
        expected_templates: Optional[int],
        timeout_seconds: int,
        interactsh_server: Optional[str],
        relevant_flags: Mapping[str, str],
    ) -> BatchExecutionEvidence:
        args = build_nuclei_args(
            target_file=target_file,
            template_dir=template_dir,
            interactsh_server=interactsh_server,
            relevant_flags=relevant_flags,
            severity=self.severity,
            exclude_tags=self.exclude_tags,
            rate_limit=self.rate_limit,
            concurrency=self.concurrency,
            request_timeout=self.request_timeout,
            max_host_errors=self.max_host_errors,
        )
        started = time.monotonic()
        try:
            returncode, stdout, stderr = self._exec(args, timeout_seconds)
        except subprocess.TimeoutExpired as exc:
            raise EndpointRunnerTimeout("http_endpoint batch timed out") from exc
        except EndpointRunnerError:
            raise
        except Exception as exc:  # unstartable / structural subprocess failure
            raise EndpointRunnerError(f"nuclei exec failed: {type(exc).__name__}") from exc
        return parse_nuclei_batch_output(
            returncode,
            stdout,
            stderr,
            expected_targets=expected_targets,
            expected_templates=expected_templates,
            duration_seconds=time.monotonic() - started,
        )
