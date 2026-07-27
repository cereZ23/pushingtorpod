"""Nuclei salvages partial findings on timeout instead of discarding the pass."""

from __future__ import annotations

import asyncio
import json

import app.services.scanning.nuclei_service as ns
from app.utils.secure_executor import ToolExecutionError


def test_tool_execution_error_carries_partial_output():
    e = ToolExecutionError("timed out", partial_stdout="x", partial_stderr="y", timed_out=True)
    assert e.timed_out is True
    assert e.partial_stdout == "x"
    assert e.partial_stderr == "y"
    # backward compatible: message-only construction still works
    e2 = ToolExecutionError("boom")
    assert e2.timed_out is False
    assert e2.partial_stdout == ""


def _jsonl(*ids):
    lines = []
    for tid in ids:
        lines.append(
            json.dumps(
                {
                    "template-id": tid,
                    "info": {"name": tid, "severity": "high"},
                    "type": "http",
                    "host": "https://example.com",
                    "matched-at": "https://example.com/",
                    "timestamp": "2026-01-01T00:00:00Z",
                }
            )
        )
    return "\n".join(lines)


class _FakeExecutor:
    """Stand-in for SecureToolExecutor whose execute() times out with partial output."""

    def __init__(self, partial: str, timed_out: bool = True):
        self._partial = partial
        self._timed_out = timed_out

    def __call__(self, tenant_id):  # SecureToolExecutor(tenant_id)
        return self

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def create_input_file(self, name, content):
        return f"/tmp/{name}"

    def execute(self, tool, args, timeout=None):
        raise ToolExecutionError(
            f"Execution timed out after {timeout}s",
            partial_stdout=self._partial,
            partial_stderr="",
            timed_out=self._timed_out,
        )


def _run(partial, timed_out=True):
    svc = ns.NucleiService(tenant_id=1)
    fake = _FakeExecutor(partial, timed_out=timed_out)
    # patch the executor + silence MinIO storage (salvage path returns before it,
    # but keep it safe if anything changes)
    orig_exec, orig_store = ns.SecureToolExecutor, ns.store_raw_output
    ns.SecureToolExecutor = fake
    ns.store_raw_output = lambda *a, **k: None
    try:
        return asyncio.run(svc.scan_urls(["https://example.com"], templates=["cves/"]))
    finally:
        ns.SecureToolExecutor = orig_exec
        ns.store_raw_output = orig_store


def test_timeout_salvages_partial_findings_and_flags_truncated():
    # two complete findings + a truncated trailing line (SIGKILL mid-write)
    partial = _jsonl("CVE-2021-1", "CVE-2021-2") + '\n{"template-id":"CVE-2021-3","in'
    result = _run(partial, timed_out=True)

    assert result["truncated"] is True
    assert result["stats"]["truncated"] is True
    assert result["stats"]["timed_out"] is True
    # the two complete lines are salvaged; the truncated one is skipped
    assert len(result["findings"]) == 2


def test_non_timeout_error_returns_empty_and_not_truncated():
    result = _run("", timed_out=False)
    assert result["findings"] == []
    assert result["truncated"] is False
