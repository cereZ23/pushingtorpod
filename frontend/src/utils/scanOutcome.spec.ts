import { describe, it, expect } from "vitest";
import {
  outcomeBadge,
  endpointStateLabel,
  endpointStateBadge,
  limitationText,
  limitationTexts,
  coveragePercentText,
} from "@/utils/scanOutcome";

describe("outcomeBadge", () => {
  it("maps each outcome to a label + colour", () => {
    expect(outcomeBadge("completed").label).toBe("Completed");
    expect(outcomeBadge("completed").classes).toContain("green");
    expect(outcomeBadge("completed_with_limitations").label).toBe(
      "Completed with limitations",
    );
    expect(outcomeBadge("completed_with_limitations").classes).toContain("amber");
    expect(outcomeBadge("failed").classes).toContain("red");
    expect(outcomeBadge("running").classes).toContain("blue");
    expect(outcomeBadge("pending").label).toBe("Pending");
    expect(outcomeBadge("cancelled").label).toBe("Cancelled");
  });

  it("falls back to the raw code for unknown outcomes", () => {
    expect(outcomeBadge("weird").label).toBe("weird");
  });
});

describe("endpointStateLabel / endpointStateBadge", () => {
  it("labels each state", () => {
    expect(endpointStateLabel("complete")).toBe("All endpoints verified");
    expect(endpointStateLabel("limited")).toBe("Verified with limitations");
    expect(endpointStateLabel("incomplete")).toBe("Verification incomplete");
    expect(endpointStateLabel("failed")).toBe("Verification failed");
    expect(endpointStateLabel("no_targets")).toBe("No endpoints to verify");
    expect(endpointStateLabel("disabled")).toBe("Endpoint verification off");
  });

  it("handles the legacy null state", () => {
    expect(endpointStateLabel(null)).toBe("Not available");
  });

  it("colours complete green, limited/incomplete amber, failed red", () => {
    expect(endpointStateBadge("complete").classes).toContain("green");
    expect(endpointStateBadge("limited").classes).toContain("amber");
    expect(endpointStateBadge("incomplete").classes).toContain("amber");
    expect(endpointStateBadge("failed").classes).toContain("red");
  });
});

describe("limitationText", () => {
  it("maps each reason code to a plain-language line", () => {
    expect(limitationText("unresponsive_origins")).toBe(
      "Some origins did not respond",
    );
    expect(limitationText("insufficient_budget")).toBe(
      "The scan budget was exhausted",
    );
    expect(limitationText("timeout")).toBe("The verification pass timed out");
    expect(limitationText("writer_error")).toBe("Some results could not be saved");
    expect(limitationText("parser_incomplete")).toBe(
      "Some results could not be attributed",
    );
    expect(limitationText("execution_error")).toBe(
      "The verification pass errored",
    );
    expect(limitationText("data_inconsistent")).toContain("inconsistent");
  });

  it("returns null for no limitation", () => {
    expect(limitationText(null)).toBeNull();
  });

  it("filters nulls out of the list form and preserves order", () => {
    expect(limitationTexts(["writer_error", "timeout"])).toEqual([
      "Some results could not be saved",
      "The verification pass timed out",
    ]);
    expect(limitationTexts(null)).toEqual([]);
  });
});

describe("coveragePercentText", () => {
  it("formats a percent", () => {
    expect(coveragePercentText(96)).toBe("96%");
    expect(coveragePercentText(0)).toBe("0%");
  });

  it("shows an em dash for null (empty set), never 100%", () => {
    expect(coveragePercentText(null)).toBe("—");
  });
});
