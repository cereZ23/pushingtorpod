import { describe, it, expect } from "vitest";
import { tierBadge, triggerBadge } from "@/utils/scanBadges";

describe("tierBadge", () => {
  it("maps tiers 1/2/3 to their labels", () => {
    expect(tierBadge(1).label).toBe("T1 Safe Continuous");
    expect(tierBadge(2).label).toBe("T2 Extended");
    expect(tierBadge(3).label).toBe("T3 Authorized Active");
  });

  it("colours tiers distinctly", () => {
    expect(tierBadge(1).classes).toContain("green");
    expect(tierBadge(2).classes).toContain("amber");
    expect(tierBadge(3).classes).toContain("red");
  });

  it("renders null/unknown/out-of-range as Unknown (never a guess)", () => {
    expect(tierBadge(null).label).toBe("Unknown");
    expect(tierBadge(undefined).label).toBe("Unknown");
    expect(tierBadge(4).label).toBe("Unknown");
    expect(tierBadge(0).label).toBe("Unknown");
  });
});

describe("triggerBadge", () => {
  it("maps known triggers to normalized labels", () => {
    expect(triggerBadge("manual").label).toBe("Manual");
    expect(triggerBadge("scheduler").label).toBe("Scheduled");
    expect(triggerBadge("schedule").label).toBe("Scheduled");
    expect(triggerBadge("api").label).toBe("API");
    expect(triggerBadge("retest").label).toBe("Retest");
  });

  it("colours triggers distinctly", () => {
    expect(triggerBadge("manual").classes).toContain("blue");
    expect(triggerBadge("scheduler").classes).toContain("violet");
    expect(triggerBadge("retest").classes).toContain("indigo");
  });

  it("shows a custom/unknown trigger verbatim with a neutral style", () => {
    expect(triggerBadge("t2-cutover-verify").label).toBe("t2-cutover-verify");
    expect(triggerBadge("t2-cutover-verify").classes).toContain("gray");
    expect(triggerBadge(null).label).toBe("Unknown");
    expect(triggerBadge("").label).toBe("Unknown");
  });
});
