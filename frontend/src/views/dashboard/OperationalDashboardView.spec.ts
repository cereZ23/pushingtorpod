import { describe, it, expect, vi, beforeEach } from "vitest";
import { mount, flushPromises } from "@vue/test-utils";
import type { OperationalDashboard, DashTierBlock } from "@/api/dashboardSummary";

const getOperational = vi.fn();

vi.mock("@/api/dashboardSummary", () => ({
  dashboardSummaryApi: { getOperational: (...args: unknown[]) => getOperational(...args) },
}));

vi.mock("@/stores/tenant", () => ({
  useTenantStore: () => ({ currentTenantId: 1 }),
}));

import OperationalDashboardView from "@/views/dashboard/OperationalDashboardView.vue";

function tier(partial: Partial<DashTierBlock> = {}): DashTierBlock {
  return {
    scans: { total: 0, completed: 0, completed_with_limitations: 0, failed: 0, cancelled: 0 },
    endpoints: { selected: 0, verified: 0, not_verifiable: 0, failed: 0, skipped: 0, coverage_percent: null },
    findings: { auto_closed: 0, reopened: 0, awaiting_confirmation: 0 },
    ...partial,
  };
}

function data(partial: Partial<OperationalDashboard> = {}): OperationalDashboard {
  return {
    schema_version: 1,
    period_days: 30,
    from: "2026-07-08T12:00:00Z",
    to: "2026-08-07T12:00:00Z",
    scans: { total: 31, completed: 30, completed_with_limitations: 1, failed: 0, cancelled: 1 },
    endpoints: { selected: 100, verified: 96, not_verifiable: 4, failed: 0, skipped: 0, coverage_percent: 96.0 },
    findings: { auto_closed: 2, reopened: 1, awaiting_confirmation: 3 },
    by_tier: { "1": tier(), "2": tier() },
    ...partial,
  };
}

async function render() {
  const w = mount(OperationalDashboardView);
  await flushPromises();
  return w;
}

beforeEach(() => {
  getOperational.mockReset();
});

describe("OperationalDashboardView", () => {
  it("shows the loading state while the request is pending", () => {
    getOperational.mockReturnValue(new Promise(() => {})); // never resolves
    const w = mount(OperationalDashboardView);
    expect(w.find('[data-testid="dash-loading"]').exists()).toBe(true);
  });

  it("shows the error state when the request fails", async () => {
    getOperational.mockRejectedValue(new Error("boom"));
    const w = await render();
    expect(w.find('[data-testid="dash-error"]').exists()).toBe(true);
    expect(w.get('[data-testid="dash-error"]').text()).toContain("boom");
  });

  it("shows the empty state when there is no activity", async () => {
    getOperational.mockResolvedValue(
      data({
        scans: { total: 0, completed: 0, completed_with_limitations: 0, failed: 0, cancelled: 0 },
        endpoints: { selected: 0, verified: 0, not_verifiable: 0, failed: 0, skipped: 0, coverage_percent: null },
        findings: { auto_closed: 0, reopened: 0, awaiting_confirmation: 0 },
      }),
    );
    const w = await render();
    expect(w.find('[data-testid="dash-empty"]').exists()).toBe(true);
    expect(w.find('[data-testid="dash-scans"]').exists()).toBe(false);
  });

  it("renders the scan / endpoint / finding counts", async () => {
    getOperational.mockResolvedValue(data());
    const w = await render();
    expect(w.get('[data-testid="scans-completed"]').text()).toBe("30");
    expect(w.get('[data-testid="scans-cwl"]').text()).toBe("1");
    expect(w.get('[data-testid="scans-cancelled"]').text()).toBe("1");
    expect(w.get('[data-testid="endpoints-verified"]').text()).toBe("96");
    expect(w.get('[data-testid="endpoints-not-verifiable"]').text()).toBe("4");
    expect(w.get('[data-testid="endpoints-coverage"]').text()).toContain("96%");
    expect(w.get('[data-testid="findings-auto-closed"]').text()).toBe("2");
    expect(w.get('[data-testid="findings-reopened"]').text()).toBe("1");
    expect(w.get('[data-testid="findings-awaiting"]').text()).toBe("3");
  });

  it("shows an em dash for null coverage, never 100%", async () => {
    getOperational.mockResolvedValue(
      data({
        endpoints: { selected: 0, verified: 0, not_verifiable: 0, failed: 0, skipped: 0, coverage_percent: null },
        scans: { total: 5, completed: 5, completed_with_limitations: 0, failed: 0, cancelled: 0 },
      }),
    );
    const w = await render();
    expect(w.get('[data-testid="endpoints-coverage"]').text()).toContain("—");
    expect(w.get('[data-testid="endpoints-coverage"]').text()).not.toContain("100%");
  });

  it("always renders the T1 and T2 breakdown rows with per-tier values", async () => {
    getOperational.mockResolvedValue(
      data({
        by_tier: {
          "1": tier({ scans: { total: 10, completed: 9, completed_with_limitations: 1, failed: 0, cancelled: 0 } }),
          "2": tier({ endpoints: { selected: 4, verified: 2, not_verifiable: 2, failed: 0, skipped: 0, coverage_percent: 50.0 } }),
        },
      }),
    );
    const w = await render();
    expect(w.find('[data-testid="tier-1"]').exists()).toBe(true);
    expect(w.find('[data-testid="tier-2"]').exists()).toBe(true);
    expect(w.get('[data-testid="tier-1"]').text()).toContain("9"); // completed
    expect(w.get('[data-testid="tier-2"]').text()).toContain("50%"); // coverage
  });

  it("refetches with the new window when a period is selected", async () => {
    getOperational.mockResolvedValue(data());
    const w = await render();
    // default window = 30
    expect(getOperational).toHaveBeenLastCalledWith(1, 30);
    await w.get('[data-testid="period-7"]').trigger("click");
    await flushPromises();
    expect(getOperational).toHaveBeenLastCalledWith(1, 7);
  });
});
