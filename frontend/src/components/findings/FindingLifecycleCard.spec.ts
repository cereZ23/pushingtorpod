import { describe, it, expect } from "vitest";
import { mount } from "@vue/test-utils";
import FindingLifecycleCard from "@/components/findings/FindingLifecycleCard.vue";
import type { FindingLifecycle } from "@/api/types";

const stubs = { RouterLink: { template: "<a><slot /></a>" } };

function make(partial: Partial<FindingLifecycle> = {}): FindingLifecycle {
  return {
    finding_id: 1,
    auto_close: {
      state: "open",
      current_streak: 0,
      threshold: 2,
      last_detected_run_id: null,
      last_eligible_run_id: null,
      coverage_scope: "host",
      origin_tier: null,
    },
    events: [],
    total_events: 0,
    has_more: false,
    has_history: false,
    ...partial,
  };
}

function render(lifecycle: FindingLifecycle | null, loading = false) {
  return mount(FindingLifecycleCard, { props: { lifecycle, loading }, global: { stubs } });
}

describe("FindingLifecycleCard", () => {
  it("shows the miss progression for an awaiting-confirmation finding", () => {
    const w = render(
      make({
        auto_close: {
          state: "eligible_miss",
          current_streak: 1,
          threshold: 2,
          last_detected_run_id: 42,
          last_eligible_run_id: 43,
          coverage_scope: "endpoint",
          origin_tier: 2,
        },
      }),
    );
    const t = w.text();
    expect(t).toContain("Awaiting confirmation");
    expect(t).toContain("Automatically monitored");
    expect(t).toContain("Endpoint");
    expect(t).toContain("Tier T2");
    expect(t).toMatch(/1\s+of\s+2\s+covered misses/);
    expect(t).toContain("Run #42");
  });

  it("renders the timeline as human text (no raw tokens)", () => {
    const w = render(
      make({
        auto_close: { ...make().auto_close, state: "auto_fixed" },
        events: [
          { type: "detected", scan_run_id: 1, created_at: "2026-08-01T00:00:00Z", reason_code: null },
          { type: "eligible_miss", scan_run_id: 2, created_at: "2026-08-02T00:00:00Z", reason_code: null },
          { type: "auto_closed", scan_run_id: 3, created_at: "2026-08-03T00:00:00Z", reason_code: "coverage_miss_streak" },
        ],
        total_events: 3,
        has_history: true,
      }),
    );
    const t = w.text();
    expect(t).toContain("Detected");
    expect(t).toContain("Covered miss");
    expect(t).toContain("Automatically fixed");
    // no raw event tokens leaked
    expect(t).not.toContain("auto_closed");
    expect(t).not.toContain("eligible_miss");
  });

  it("shows the conservative backfill note for legacy findings with no history", () => {
    const w = render(make({ has_history: false, events: [] }));
    expect(w.text()).toContain("migration 031");
  });

  it("marks a non-coverage-aware finding as not monitored", () => {
    const w = render(make({ auto_close: { ...make().auto_close, coverage_scope: null } }));
    expect(w.text()).toContain("Not automatically monitored");
  });

  it("shows a truncation notice when has_more", () => {
    const w = render(
      make({
        events: [{ type: "detected", scan_run_id: 1, created_at: "2026-08-01T00:00:00Z", reason_code: null }],
        total_events: 350,
        has_more: true,
        has_history: true,
      }),
    );
    expect(w.text()).toMatch(/most recent 1 of\s+350/);
  });
});
