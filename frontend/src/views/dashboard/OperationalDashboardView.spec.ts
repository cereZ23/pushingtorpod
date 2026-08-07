import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { mount, flushPromises, enableAutoUnmount } from "@vue/test-utils";
import { nextTick, ref, type Ref } from "vue";
import type { OperationalDashboard, DashTierBlock } from "@/api/dashboardSummary";

// Unmount every wrapper after each test. Without this, leaked components share the module-level
// tenant ref (below) and their watchers fire on a later test's tenant change — polluting the shared
// request queue and breaking the race tests.
enableAutoUnmount(afterEach);

// A single lazily-created reactive tenant ref, shared between the mocked store and the tests.
// Function declaration is hoisted, so the vi.mock factory below may reference it; `ref` is only
// touched when the component first reads the store (well after module init) — no TDZ, no require.
let _tenantRef: Ref<number | null> | null = null;
function tenantRef(): Ref<number | null> {
  if (!_tenantRef) _tenantRef = ref<number | null>(1);
  return _tenantRef;
}

// Deferred queue so tests control resolution ORDER (for the race cases). Hoisted so the vi.mock
// factory can reference it safely.
type Deferred = { promise: Promise<unknown>; resolve: (v: unknown) => void; reject: (e: unknown) => void };
const h = vi.hoisted(() => {
  const deferreds: Deferred[] = [];
  const getOperational = vi.fn((..._args: unknown[]) => {
    let resolve!: (v: unknown) => void;
    let reject!: (e: unknown) => void;
    const promise = new Promise<unknown>((res, rej) => {
      resolve = res;
      reject = rej;
    });
    deferreds.push({ promise, resolve, reject });
    return promise;
  });
  return { deferreds, getOperational };
});
const deferreds = h.deferreds;
const getOperational = h.getOperational;

vi.mock("@/api/dashboardSummary", () => ({
  dashboardSummaryApi: { getOperational: (...args: unknown[]) => h.getOperational(...args) },
}));

// Reactive tenant so a tenant switch drives the watcher, like production.
vi.mock("@/stores/tenant", () => ({
  useTenantStore: () => ({
    get currentTenantId() {
      return tenantRef().value;
    },
  }),
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

beforeEach(() => {
  deferreds.length = 0;
  getOperational.mockClear();
  tenantRef().value = 1;
});

describe("OperationalDashboardView", () => {
  it("shows the loading state while the request is pending", async () => {
    const w = mount(OperationalDashboardView);
    await nextTick();
    expect(getOperational).toHaveBeenCalledWith(1, 30);
    expect(w.find('[data-testid="dash-loading"]').exists()).toBe(true);
  });

  it("shows the error state when the request fails", async () => {
    const w = mount(OperationalDashboardView);
    deferreds[0].reject(new Error("boom"));
    await flushPromises();
    expect(w.get('[data-testid="dash-error"]').text()).toContain("boom");
  });

  it("shows the empty state when there is no activity", async () => {
    const w = mount(OperationalDashboardView);
    deferreds[0].resolve(
      data({
        scans: { total: 0, completed: 0, completed_with_limitations: 0, failed: 0, cancelled: 0 },
        endpoints: { selected: 0, verified: 0, not_verifiable: 0, failed: 0, skipped: 0, coverage_percent: null },
        findings: { auto_closed: 0, reopened: 0, awaiting_confirmation: 0 },
      }),
    );
    await flushPromises();
    expect(w.find('[data-testid="dash-empty"]').exists()).toBe(true);
    expect(w.find('[data-testid="dash-scans"]').exists()).toBe(false);
  });

  it("renders scan / endpoint / finding counts including failed endpoints", async () => {
    const w = mount(OperationalDashboardView);
    deferreds[0].resolve(
      data({
        endpoints: { selected: 100, verified: 90, not_verifiable: 4, failed: 6, skipped: 0, coverage_percent: 90.0 },
      }),
    );
    await flushPromises();
    expect(w.get('[data-testid="scans-completed"]').text()).toBe("30");
    expect(w.get('[data-testid="endpoints-verified"]').text()).toBe("90");
    expect(w.get('[data-testid="endpoints-not-verifiable"]').text()).toBe("4");
    expect(w.get('[data-testid="endpoints-failed"]').text()).toBe("6"); // failed is NOT hidden
    expect(w.get('[data-testid="endpoints-coverage"]').text()).toContain("90%");
    expect(w.get('[data-testid="findings-awaiting"]').text()).toBe("3");
  });

  it("shows an em dash for null coverage, never 100%", async () => {
    const w = mount(OperationalDashboardView);
    deferreds[0].resolve(
      data({
        endpoints: { selected: 0, verified: 0, not_verifiable: 0, failed: 0, skipped: 0, coverage_percent: null },
        scans: { total: 5, completed: 5, completed_with_limitations: 0, failed: 0, cancelled: 0 },
      }),
    );
    await flushPromises();
    expect(w.get('[data-testid="endpoints-coverage"]').text()).toContain("—");
    expect(w.get('[data-testid="endpoints-coverage"]').text()).not.toContain("100%");
  });

  it("renders the T1/T2 breakdown with per-tier failed endpoints", async () => {
    const w = mount(OperationalDashboardView);
    deferreds[0].resolve(
      data({
        by_tier: {
          "1": tier({ scans: { total: 10, completed: 9, completed_with_limitations: 1, failed: 0, cancelled: 0 } }),
          "2": tier({ endpoints: { selected: 5, verified: 2, not_verifiable: 1, failed: 2, skipped: 0, coverage_percent: 40.0 } }),
        },
      }),
    );
    await flushPromises();
    expect(w.get('[data-testid="tier-1"]').text()).toContain("9");
    expect(w.get('[data-testid="tier-2"]').text()).toContain("40%");
    expect(w.get('[data-testid="tier-2"]').text()).toContain("2"); // failed endpoints shown per tier
  });

  it("shows the inconsistent state when a tier block is missing", async () => {
    const w = mount(OperationalDashboardView);
    // malformed: only tier 1 present
    deferreds[0].resolve({ ...data(), by_tier: { "1": tier() } } as unknown as OperationalDashboard);
    await flushPromises();
    expect(w.find('[data-testid="dash-inconsistent"]').exists()).toBe(true);
    expect(w.find('[data-testid="dash-by-tier"]').exists()).toBe(false); // no invented zeros
  });

  it("refetches with the new window when a period is selected", async () => {
    const w = mount(OperationalDashboardView);
    deferreds[0].resolve(data());
    await flushPromises();
    expect(getOperational).toHaveBeenLastCalledWith(1, 30);
    await w.get('[data-testid="period-7"]').trigger("click");
    await nextTick();
    expect(getOperational).toHaveBeenLastCalledWith(1, 7);
  });

  // --- race safety (generation token) ---

  it("out-of-order period responses: keeps the latest window", async () => {
    const w = mount(OperationalDashboardView); // gen1 → 30d (deferreds[0])
    await w.get('[data-testid="period-7"]').trigger("click"); // gen2 → 7d (deferreds[1])
    await nextTick();
    // 7d resolves FIRST, 30d (older) resolves LATER
    deferreds[1].resolve(data({ endpoints: { selected: 40, verified: 40, not_verifiable: 0, failed: 0, skipped: 0, coverage_percent: 100.0 } }));
    await flushPromises();
    deferreds[0].resolve(data({ endpoints: { selected: 100, verified: 96, not_verifiable: 4, failed: 0, skipped: 0, coverage_percent: 96.0 } }));
    await flushPromises();
    expect(w.get('[data-testid="endpoints-verified"]').text()).toBe("40"); // stays the 7d result
  });

  it("tenant switch: a slow old-tenant response cannot overwrite the new tenant", async () => {
    const w = mount(OperationalDashboardView); // gen1 tenant1 (deferreds[0])
    tenantRef().value = 2; // tenant change → gen2 tenant2 (deferreds[1])
    await nextTick();
    expect(getOperational).toHaveBeenLastCalledWith(2, 30);
    deferreds[1].resolve(data({ endpoints: { selected: 7, verified: 7, not_verifiable: 0, failed: 0, skipped: 0, coverage_percent: 100.0 } }));
    await flushPromises();
    deferreds[0].resolve(data({ endpoints: { selected: 999, verified: 999, not_verifiable: 0, failed: 0, skipped: 0, coverage_percent: 100.0 } }));
    await flushPromises();
    expect(w.get('[data-testid="endpoints-verified"]').text()).toBe("7"); // tenant-2 data, not the stale tenant-1
  });

  it("a stale request failing after a newer success does not show an error", async () => {
    const w = mount(OperationalDashboardView); // gen1 (deferreds[0])
    await w.get('[data-testid="period-7"]').trigger("click"); // gen2 (deferreds[1])
    await nextTick();
    deferreds[1].resolve(data()); // new one succeeds
    await flushPromises();
    deferreds[0].reject(new Error("stale failure")); // old one fails late
    await flushPromises();
    expect(w.find('[data-testid="dash-error"]').exists()).toBe(false);
    expect(w.find('[data-testid="dash-scans"]').exists()).toBe(true);
  });

  it("loading stays active until the current request resolves", async () => {
    const w = mount(OperationalDashboardView);
    await nextTick();
    expect(w.find('[data-testid="dash-loading"]').exists()).toBe(true);
    deferreds[0].resolve(data());
    await flushPromises();
    expect(w.find('[data-testid="dash-loading"]').exists()).toBe(false);
  });
});
