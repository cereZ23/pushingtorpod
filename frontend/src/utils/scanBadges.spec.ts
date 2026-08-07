import { describe, it, expect } from "vitest";
import { tierBadge, triggerBadge } from "@/utils/scanBadges";

describe("tierBadge", () => {
  it("maps tiers 1/2/3 to full label + compact short", () => {
    expect(tierBadge(1).label).toBe("T1 Safe Continuous");
    expect(tierBadge(1).short).toBe("T1");
    expect(tierBadge(2).short).toBe("T2");
    expect(tierBadge(3).short).toBe("T3");
    expect(tierBadge(2).label).toBe("T2 Extended");
  });

  it("colours tiers distinctly", () => {
    expect(tierBadge(1).classes).toContain("green");
    expect(tierBadge(2).classes).toContain("amber");
    expect(tierBadge(3).classes).toContain("red");
  });

  it("renders null/unknown/out-of-range as Unknown (never a guess)", () => {
    expect(tierBadge(null).label).toBe("Unknown");
    expect(tierBadge(null).short).toBe("—");
    expect(tierBadge(undefined).label).toBe("Unknown");
    expect(tierBadge(4).label).toBe("Unknown");
    expect(tierBadge(0).label).toBe("Unknown");
  });
});

describe("triggerBadge", () => {
  it("maps known provenance to normalized labels", () => {
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

  it("shows an unknown/custom trigger as 'Custom' with the raw value in the tooltip (never 'Manual')", () => {
    const b = triggerBadge("t2-cutover-verify");
    expect(b.label).toBe("Custom");
    expect(b.title).toBe("t2-cutover-verify");
    expect(b.classes).toContain("gray");
  });

  it("renders empty/null trigger as Unknown with no tooltip", () => {
    expect(triggerBadge(null).label).toBe("Unknown");
    expect(triggerBadge(null).title).toBeUndefined();
    expect(triggerBadge("").label).toBe("Unknown");
  });
});
