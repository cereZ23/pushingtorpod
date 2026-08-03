"""scan_urls_batched: batching + split-and-retry guarantees full coverage."""

from __future__ import annotations

import asyncio

from app.services.scanning.nuclei_service import NucleiService


class _BatchSvc(NucleiService):
    """NucleiService whose scan_urls is faked: a batch 'times out' when it has
    more than `fit` URLs; it always emits one finding per URL (salvaged)."""

    def __init__(self, fit: int):
        super().__init__(tenant_id=1)
        self.fit = fit
        self.batches: list[list[str]] = []

    async def scan_urls(self, urls, **kwargs):
        self.batches.append(list(urls))
        return {
            "findings": [{"template_id": u, "info": {"severity": "high"}} for u in urls],
            "stats": {},
            "errors": [],
            "truncated": len(urls) > self.fit,
        }


def _run(svc, urls, **kw):
    return asyncio.run(svc.scan_urls_batched(urls, **kw))


def test_small_input_is_single_shot():
    svc = _BatchSvc(fit=100)
    res = _run(svc, [f"u{i}" for i in range(10)], chunk_size=50)
    assert len(svc.batches) == 1
    assert len(res["findings"]) == 10
    assert res["truncated"] is False


def test_all_batches_fit_full_coverage_no_dupes():
    urls = [f"u{i}" for i in range(120)]
    svc = _BatchSvc(fit=1000)  # nothing times out
    res = _run(svc, urls, chunk_size=50)
    # 120 -> 50,50,20
    assert len(svc.batches) == 3
    ids = [f["template_id"] for f in res["findings"]]
    assert sorted(ids) == sorted(urls)  # every URL once, no dupes
    assert res["truncated"] is False


def test_oversized_batch_splits_and_retries_to_full_coverage():
    urls = [f"u{i}" for i in range(80)]
    # 80 > chunk_size(40) so it batches; a batch only fits when <= 10 URLs, so
    # each 40-URL batch times out -> splits (40->20->10) until it fits.
    svc = _BatchSvc(fit=10)
    res = _run(svc, urls, chunk_size=40, min_chunk=1)
    ids = sorted(f["template_id"] for f in res["findings"])
    assert ids == sorted(urls)  # complete coverage
    assert len(ids) == len(set(ids))  # no duplicates (partial discarded on retry)
    assert res["truncated"] is False  # everything eventually fit


def test_floor_batch_still_timing_out_flags_truncated():
    urls = [f"u{i}" for i in range(12)]
    svc = _BatchSvc(fit=0)  # every batch times out, even size 1
    res = _run(svc, urls, chunk_size=8, min_chunk=1)
    # floor-size (1) batches still time out -> their partial kept, truncated set
    assert res["truncated"] is True
    assert len(res["findings"]) > 0  # partial salvage, not empty


def test_overall_deadline_stops_early_and_flags_truncated():
    urls = [f"u{i}" for i in range(200)]
    svc = _BatchSvc(fit=1000)
    # deadline 0 -> stop before scanning any batch
    res = _run(svc, urls, chunk_size=10, max_total_seconds=0)
    assert res["truncated"] is True
    assert len(svc.batches) == 0


class _TimeoutRecSvc(_BatchSvc):
    """Records the subprocess timeout each batch was invoked with."""

    def __init__(self, fit):
        super().__init__(fit)
        self.timeouts: list = []

    async def scan_urls(self, urls, **kwargs):
        self.timeouts.append(kwargs.get("timeout"))
        return await super().scan_urls(urls, **kwargs)


def test_batch_timeout_clamped_to_remaining_budget():
    # A batch must never be launched with the full per-batch timeout when less budget
    # remains — otherwise it overshoots the phase wall-clock and the phase hard-FAILS.
    svc = _TimeoutRecSvc(fit=1000)
    _run(svc, [f"u{i}" for i in range(30)], chunk_size=10, timeout=300, max_total_seconds=45)
    assert svc.timeouts  # ran at least one batch
    assert all(t <= 45 for t in svc.timeouts)  # clamped to remaining, never the full 300
