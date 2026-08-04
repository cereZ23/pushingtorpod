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
# Legacy TEXT stats (fallback only). The REAL Nuclei -stats output is a JSON object (see below).
_TEMPLATES_LOADED_RE = re.compile(r"Templates loaded for current scan:\s*(\d+)", re.IGNORECASE)
_TARGETS_LOADED_RE = re.compile(r"Targets loaded for current scan:\s*(\d+)", re.IGNORECASE)
_REQUESTS_PCT_RE = re.compile(r"Requests:\s*\d+/\d+\s*\((\d+)%\)", re.IGNORECASE)
# A NUMERIC unresponsive summary, e.g. "Found 3 unresponsive hosts".
_UNRESPONSIVE_N_RE = re.compile(r"(\d+)\s+unresponsive", re.IGNORECASE)
# A PER-TARGET unresponsive line, exactly as prod emits it:
#   "Skipped link.example.it:443 from target list as found unresponsive permanently"
_UNRESPONSIVE_LINE_RE = re.compile(
    r"(from target list[^\n]*unresponsive|found unresponsive permanently)", re.IGNORECASE
)

# Nuclei capability flags gated by the policy's relevant_flags (never passed when the value is false).
_CAPABILITY_FLAG = {"code": "-code", "headless": "-headless", "dast": "-dast", "self_contained": "-esc"}
# Every capability key the manifest MUST declare (canonical "true"/"false"). interactsh is separate.
_REQUIRED_CAPS = ("code", "headless", "dast", "self_contained", "interactsh")


def _is_stats_obj(obj: dict) -> bool:
    """A Nuclei -stats JSON record, e.g. {"percent":"99","requests":"8851","total":"8904",
    "hosts":"21","templates":"284","duration":"0:01:12"} — recognised by its stat keys, NEVER a
    finding (which carries template-id)."""
    return isinstance(obj, dict) and ("percent" in obj or ("requests" in obj and "total" in obj))


def _to_int(v) -> Optional[int]:
    try:
        return int(str(v).strip())
    except (TypeError, ValueError):
        return None


def _finding_from_result(obj: dict) -> dict:
    """Normalise one JSONL finding, KEEPING the ORIGINAL input target so the orchestrator can
    attribute by target shape. Order matters: ``input``/``host`` are the -l target we submitted;
    ``url``/``matched-at`` may be a template-CONSTRUCTED URL that would break the shape."""
    info = obj.get("info") if isinstance(obj.get("info"), dict) else {}
    target = obj.get("input") or obj.get("host") or obj.get("url") or obj.get("matched-at")
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


def _scan_json_lines(text: str, *, findings: list, stats: list, collect_findings: bool) -> bool:
    """Scan a stream for JSON objects. Stats records → ``stats``; findings (template-id) →
    ``findings`` (only when ``collect_findings``); a JSON object that is NEITHER → returns True
    (parse incomplete: an unknown result must not be dropped nor become a finding)."""
    incomplete = False
    for line in (text or "").splitlines():
        s = line.strip()
        if not s or not s.startswith("{"):
            continue
        try:
            obj = json.loads(s)
        except Exception:
            incomplete = True
            continue
        if not isinstance(obj, dict):
            incomplete = True
            continue
        if _is_stats_obj(obj):
            stats.append(obj)
        elif obj.get("template-id"):
            if collect_findings:
                findings.append(_finding_from_result(obj))
        else:
            incomplete = True  # JSON without template-id and not a stats record → unknown
    return incomplete


def _count_unresponsive(err: str) -> int:
    """Count unresponsive/skipped targets from real prod lines, without double-counting a line."""
    n = 0
    for line in err.splitlines():
        m = _UNRESPONSIVE_N_RE.search(line)
        if m:
            n += int(m.group(1))  # numeric summary line
        elif _UNRESPONSIVE_LINE_RE.search(line):
            n += 1  # per-target "... from target list ... unresponsive" / "found unresponsive permanently"
    return n


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
    batch degrades to PARTIAL. Findings keep their ORIGINAL input ``target`` for attribution. The
    real Nuclei -stats record is a JSON object (percent/requests/total/hosts/templates), emitted on
    stdout and/or stderr — parsed from both; a legacy TEXT format is kept as a fallback.
    """
    findings: list[dict] = []
    stats_records: list[dict] = []
    err = _ANSI_RE.sub("", stderr or "")
    # findings come from stdout only; stats JSON can appear on either stream.
    inc_out = _scan_json_lines(stdout, findings=findings, stats=stats_records, collect_findings=True)
    _scan_json_lines(err, findings=findings, stats=stats_records, collect_findings=False)
    parse_incomplete = inc_out

    # Prefer the JSON stats (last record wins per key); fall back to the legacy text format.
    templates_json = hosts_json = percent_json = None
    for rec in stats_records:
        if "templates" in rec:
            templates_json = _to_int(rec["templates"])
        if "hosts" in rec:
            hosts_json = _to_int(rec["hosts"])
        if "percent" in rec:
            percent_json = _to_int(rec["percent"])
    templates_loaded = templates_json if templates_json is not None else _last_int(_TEMPLATES_LOADED_RE, err)
    targets_loaded = hosts_json if hosts_json is not None else _last_int(_TARGETS_LOADED_RE, err)
    if percent_json is not None:
        completion_percent = percent_json
    else:
        pcts = _REQUESTS_PCT_RE.findall(err)
        completion_percent = int(pcts[-1]) if pcts else None
    unresponsive = _count_unresponsive(err)

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
    is -ni unless a server is configured (never let Nuclei pick oast.me).

    Validates BEFORE building (raises ``EndpointRunnerError`` → the caller never launches on a
    mismatch): every capability declared with a canonical ``true``/``false``, no unknown capability,
    the interactsh server present iff the interactsh flag is ``true``, and positive-int tuning knobs.
    """
    _validate_runner_inputs(
        relevant_flags=relevant_flags,
        interactsh_server=interactsh_server,
        rate_limit=rate_limit,
        concurrency=concurrency,
        request_timeout=request_timeout,
        max_host_errors=max_host_errors,
    )
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
        if relevant_flags[cap] == "true":
            args.append(flag)
    if interactsh_server:
        args += ["-iserver", interactsh_server]  # NO empty -itoken (it can invalidate the config)
    else:
        args.append("-ni")
    return args


def _validate_runner_inputs(
    *,
    relevant_flags: Mapping[str, str],
    interactsh_server: Optional[str],
    rate_limit,
    concurrency,
    request_timeout,
    max_host_errors,
) -> None:
    """Fail-closed pre-flight so the CLI can never diverge from the manifest (raises before exec)."""
    for cap in _REQUIRED_CAPS:
        v = relevant_flags.get(cap)
        if v not in ("true", "false"):
            raise EndpointRunnerError(f"capability {cap!r} must be canonical 'true'/'false', got {v!r}")
    unknown = set(relevant_flags) - set(_REQUIRED_CAPS)
    if unknown:
        raise EndpointRunnerError(f"unknown capabilities {sorted(unknown)}")
    if (interactsh_server is not None) != (relevant_flags["interactsh"] == "true"):
        raise EndpointRunnerError("interactsh server/flag mismatch (CLI would diverge from the manifest)")
    for name, val in (
        ("rate_limit", rate_limit),
        ("concurrency", concurrency),
        ("request_timeout", request_timeout),
        ("max_host_errors", max_host_errors),
    ):
        if type(val) is not int or val <= 0:
            raise EndpointRunnerError(f"{name} must be a positive int, got {val!r}")


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
