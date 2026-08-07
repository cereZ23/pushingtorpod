import { describe, it, expect } from "vitest";
import { mount } from "@vue/test-utils";
import ScanOperationalSummary from "@/components/scans/ScanOperationalSummary.vue";
import type {
  OperationalSummary,
  EndpointVerificationSummary,
  AutoCloseSummary,
} from "@/stores/scans";

function ev(partial: Partial<EndpointVerificationSummary> = {}): EndpointVerificationSummary {
  return {
    available: true,
    enabled: true,
    state: "complete",
    limitation: null,
    limitations: [],
    selected: 100,
    covered: 100,
    not_verifiable: 0,
    failed: 0,
    skipped: 0,
    unstarted: 0,
    coverage_percent: 100,
    data_inconsistent: false,
    ...partial,
  };
}

function ac(partial: Partial<AutoCloseSummary> = {}): AutoCloseSummary {
  return { detected: 0, eligible_miss: 0, would_close: 0, closed: 0, reopened: 0, ...partial };
}

function summary(partial: Partial<OperationalSummary> = {}): OperationalSummary {
  return {
    schema_version: 1,
    outcome: "completed",
    tier: 1,
    trigger_type: "manual",
    trigger_label: null,
    endpoint_verification: partial.endpoint_verification ?? ev(),
    auto_close: partial.auto_close ?? ac(),
    ...partial,
  };
}

function render(s: OperationalSummary) {
  return mount(ScanOperationalSummary, { props: { summary: s } });
}

describe("ScanOperationalSummary", () => {
  it("scenario 1 — clean completed scan, 100% covered", () => {
    const w = render(summary());
    expect(w.get('[data-testid="scan-outcome-badge"]').text()).toBe("Completed");
    expect(w.get('[data-testid="endpoint-state-badge"]').text()).toBe("All endpoints verified");
    expect(w.get('[data-testid="coverage-percent"]').text()).toContain("100%");
    expect(w.find('[data-testid="limitation-reasons"]').exists()).toBe(false);
    expect(w.find('[data-testid="data-inconsistent-note"]').exists()).toBe(false);
  });

  it("scenario 2 — completed with unresponsive origins", () => {
    const w = render(
      summary({
        outcome: "completed_with_limitations",
        endpoint_verification: ev({
          state: "limited",
          limitation: "unresponsive_origins",
          limitations: ["unresponsive_origins"],
          selected: 100,
          covered: 96,
          not_verifiable: 4,
          coverage_percent: 96,
        }),
      }),
    );
    expect(w.get('[data-testid="scan-outcome-badge"]').text()).toBe("Completed with limitations");
    expect(w.get('[data-testid="endpoint-state-badge"]').text()).toBe("Verified with limitations");
    expect(w.get('[data-testid="coverage-percent"]').text()).toContain("96%");
    const reasons = w.get('[data-testid="limitation-reasons"]').text();
    expect(reasons).toContain("Some origins did not respond");
    // raw enum code must NOT be visible
    expect(w.text()).not.toContain("unresponsive_origins");
  });

  it("scenario 3 — budget exhaustion is incomplete", () => {
    const w = render(
      summary({
        outcome: "completed_with_limitations",
        endpoint_verification: ev({
          state: "incomplete",
          limitation: "insufficient_budget",
          limitations: ["insufficient_budget"],
          selected: 100,
          covered: 60,
          not_verifiable: 0,
          skipped: 40,
          coverage_percent: 60,
        }),
      }),
    );
    expect(w.get('[data-testid="scan-outcome-badge"]').text()).toBe("Completed with limitations");
    expect(w.get('[data-testid="endpoint-state-badge"]').text()).toBe("Verification incomplete");
    expect(w.get('[data-testid="limitation-reasons"]').text()).toContain("The scan budget was exhausted");
    expect(w.text()).not.toContain("All endpoints verified");
  });

  it("scenario 4a — legacy clean run has no endpoint data", () => {
    const w = render(
      summary({
        outcome: "completed",
        endpoint_verification: ev({
          available: false,
          state: null,
          limitation: null,
          selected: 0,
          covered: 0,
          coverage_percent: null,
        }),
      }),
    );
    expect(w.get('[data-testid="scan-outcome-badge"]').text()).toBe("Completed");
    expect(w.get('[data-testid="endpoint-unavailable"]').text()).toContain("not available");
    expect(w.find('[data-testid="endpoint-verification"]').exists()).toBe(false);
    expect(w.text()).not.toContain("100%");
  });

  it("scenario 4b — legacy run with uncovered rows is incomplete/unknown", () => {
    const w = render(
      summary({
        outcome: "completed_with_limitations",
        endpoint_verification: ev({
          available: false,
          state: "incomplete",
          limitation: "unknown",
          limitations: ["unknown"],
          selected: 10,
          covered: 8,
          not_verifiable: 2,
          coverage_percent: 80,
        }),
      }),
    );
    // block still shows (state is set even though available is false)
    expect(w.find('[data-testid="endpoint-verification"]').exists()).toBe(true);
    expect(w.get('[data-testid="endpoint-state-badge"]').text()).toBe("Verification incomplete");
    expect(w.get('[data-testid="limitation-reasons"]').text()).toContain("unknown reason");
  });

  it("scenario 5 — data inconsistency", () => {
    const w = render(
      summary({
        outcome: "completed_with_limitations",
        endpoint_verification: ev({
          state: "incomplete",
          limitation: "data_inconsistent",
          limitations: ["data_inconsistent"],
          selected: 50,
          covered: 25,
          not_verifiable: 25,
          coverage_percent: 50,
          data_inconsistent: true,
        }),
      }),
    );
    expect(w.get('[data-testid="scan-outcome-badge"]').text()).toBe("Completed with limitations");
    expect(w.get('[data-testid="endpoint-state-badge"]').text()).not.toBe("All endpoints verified");
    expect(w.find('[data-testid="data-inconsistent-note"]').exists()).toBe(true);
    // authoritative ledger counts are shown; no hashes/internal fields
    expect(w.text()).toContain("25");
    expect(w.text()).not.toMatch(/[a-f0-9]{32,}/);
  });

  it("scenario 6 — auto-close activity renders every counter", () => {
    const w = render(
      summary({
        auto_close: ac({ detected: 3, eligible_miss: 2, would_close: 1, closed: 1, reopened: 1 }),
      }),
    );
    expect(w.find('[data-testid="auto-close-summary"]').exists()).toBe(true);
    expect(w.get('[data-testid="auto-close-detected"]').text()).toContain("3");
    expect(w.get('[data-testid="auto-close-eligible-miss"]').text()).toContain("Awaiting confirmation");
    expect(w.get('[data-testid="auto-close-eligible-miss"]').text()).toContain("2");
    expect(w.get('[data-testid="auto-close-would-close"]').text()).toContain("Reached close threshold");
    expect(w.get('[data-testid="auto-close-would-close"]').text()).toContain("1");
    expect(w.get('[data-testid="auto-close-closed"]').text()).toContain("Automatically fixed");
    expect(w.get('[data-testid="auto-close-reopened"]').text()).toContain("1");
  });

  it("scenario 6b — auto-close section is absent when all counts are zero", () => {
    const w = render(summary({ auto_close: ac() }));
    expect(w.find('[data-testid="auto-close-summary"]').exists()).toBe(false);
  });

  it("null coverage percent renders an em dash, never 100%", () => {
    const w = render(
      summary({
        endpoint_verification: ev({
          state: "no_targets",
          selected: 0,
          covered: 0,
          coverage_percent: null,
        }),
      }),
    );
    expect(w.get('[data-testid="coverage-percent"]').text()).toContain("—");
    expect(w.get('[data-testid="coverage-percent"]').text()).not.toContain("100%");
  });

  it("unknown outcome renders an Unknown badge", () => {
    const w = render(
      summary({
        outcome: "unknown",
        endpoint_verification: ev({
          available: false,
          state: null,
          coverage_percent: null,
          selected: 0,
          covered: 0,
        }),
      }),
    );
    expect(w.get('[data-testid="scan-outcome-badge"]').text()).toBe("Unknown");
  });

  it("unstarted appears only when greater than zero", () => {
    const withZero = render(summary());
    expect(withZero.text()).not.toContain("Not reached");
    const withUnstarted = render(
      summary({
        outcome: "completed_with_limitations",
        endpoint_verification: ev({
          state: "incomplete",
          limitation: "unknown",
          limitations: ["unknown"],
          selected: 10,
          covered: 6,
          unstarted: 4,
          coverage_percent: 60,
        }),
      }),
    );
    expect(withUnstarted.text()).toContain("Not reached");
    expect(withUnstarted.text()).toContain("4");
  });
});
