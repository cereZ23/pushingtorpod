"""Sensitive-port probe pre-warm cache (EXP-011 perf fix)."""

from __future__ import annotations

import app.tasks.misconfig as mc


def _fake_probe(calls):
    def _p(host, port, timeout):
        calls.append((host, port))
        # pretend one port is open so the result is non-trivial
        return (port == 22, "SSH-2.0" if port == 22 else "")

    return _p


def test_prewarm_populates_cache_and_reads_are_cached(monkeypatch):
    calls: list = []
    monkeypatch.setattr(mc, "_probe_tcp", _fake_probe(calls))
    mc._sensitive_probe_cache.clear()

    mc._prewarm_sensitive_probes(["10.0.0.1", "10.0.0.2"], timeout=1)

    # every sensitive port probed for each host, exactly once
    ports = set(mc._SENSITIVE_PORTS)
    assert set(mc._sensitive_probe_cache["10.0.0.1"]) == ports
    assert set(mc._sensitive_probe_cache["10.0.0.2"]) == ports
    prewarm_calls = len(calls)
    assert prewarm_calls == 2 * len(ports)

    # a read for a pre-warmed host must NOT probe again
    res = mc._probe_sensitive_ports("10.0.0.1", timeout=1)
    assert len(calls) == prewarm_calls  # no new probes
    assert res[22][0] is True  # port 22 reported open


def test_uncached_host_falls_back_to_live_probe(monkeypatch):
    calls: list = []
    monkeypatch.setattr(mc, "_probe_tcp", _fake_probe(calls))
    mc._sensitive_probe_cache.clear()

    res = mc._probe_sensitive_ports("192.0.2.9", timeout=1)
    # not pre-warmed -> live probe hit every sensitive port
    assert len(calls) == len(mc._SENSITIVE_PORTS)
    assert set(res) == set(mc._SENSITIVE_PORTS)


def test_prewarm_empty_hosts_is_noop(monkeypatch):
    calls: list = []
    monkeypatch.setattr(mc, "_probe_tcp", _fake_probe(calls))
    mc._sensitive_probe_cache.clear()
    mc._prewarm_sensitive_probes([], timeout=1)
    assert calls == []
    assert mc._sensitive_probe_cache == {}
