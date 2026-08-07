import { describe, it, expect } from "vitest";
import {
  autoCloseStateInfo,
  lifecycleEventText,
  coverageScopeLabel,
} from "@/utils/lifecycleLabels";

describe("autoCloseStateInfo", () => {
  it("maps each state to an operator label", () => {
    expect(autoCloseStateInfo("open").label).toBe("Open");
    expect(autoCloseStateInfo("eligible_miss").label).toBe("Awaiting confirmation");
    expect(autoCloseStateInfo("awaiting_confirmation").label).toBe("Awaiting confirmation");
    expect(autoCloseStateInfo("auto_fixed").label).toBe("Automatically fixed");
    expect(autoCloseStateInfo("manually_fixed").label).toBe("Manually fixed");
    expect(autoCloseStateInfo("suppressed").label).toBe("Suppressed");
  });

  it("colours fixed green, awaiting amber", () => {
    expect(autoCloseStateInfo("auto_fixed").classes).toContain("green");
    expect(autoCloseStateInfo("awaiting_confirmation").classes).toContain("amber");
  });

  it("falls back to the raw token for an unknown state", () => {
    expect(autoCloseStateInfo("weird").label).toBe("weird");
  });
});

describe("lifecycleEventText", () => {
  it("translates each event type to human text (never raw tokens)", () => {
    expect(lifecycleEventText("detected", null)).toBe("Detected");
    expect(lifecycleEventText("eligible_miss", null)).toContain("Covered miss");
    expect(lifecycleEventText("miss_reset", null)).toBe("Miss streak reset");
    expect(lifecycleEventText("would_close", null)).toContain("threshold");
    expect(lifecycleEventText("auto_closed", null)).toBe("Automatically fixed");
  });

  it("refines reopened by reason code", () => {
    expect(lifecycleEventText("reopened", "manual_reopen")).toBe("Reopened (manual)");
    expect(lifecycleEventText("reopened", "manual_status_change")).toContain("Status changed");
    expect(lifecycleEventText("reopened", "re_detected")).toContain("detected again");
    expect(lifecycleEventText("reopened", null)).toBe("Reopened");
  });
});

describe("coverageScopeLabel", () => {
  it("maps endpoint/host, null for non-coverage-aware", () => {
    expect(coverageScopeLabel("endpoint")).toBe("Endpoint");
    expect(coverageScopeLabel("host")).toBe("Host");
    expect(coverageScopeLabel(null)).toBeNull();
  });
});
