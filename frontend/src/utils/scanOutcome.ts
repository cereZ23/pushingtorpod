// Human labels + colors for the backend-decided operational_summary (UI-1).
// This util ONLY maps closed-enum codes → display text/classes and formats numbers. It NEVER
// re-derives outcome or endpoint state — the backend owns those decisions.

export interface Badge {
  label: string;
  classes: string;
}

const GREEN = "bg-green-100 text-green-800 dark:bg-green-900/20 dark:text-green-400";
const AMBER = "bg-amber-100 text-amber-800 dark:bg-amber-900/20 dark:text-amber-400";
const RED = "bg-red-100 text-red-800 dark:bg-red-900/20 dark:text-red-400";
const BLUE = "bg-blue-100 text-blue-800 dark:bg-blue-900/20 dark:text-blue-400";
const GRAY = "bg-gray-100 text-gray-700 dark:bg-gray-700/30 dark:text-gray-300";

// Customer-facing scan outcome → badge.
export function outcomeBadge(outcome: string): Badge {
  switch (outcome) {
    case "completed":
      return { label: "Completed", classes: GREEN };
    case "completed_with_limitations":
      return { label: "Completed with limitations", classes: AMBER };
    case "failed":
      return { label: "Failed", classes: RED };
    case "running":
      return { label: "Running", classes: BLUE };
    case "pending":
      return { label: "Pending", classes: GRAY };
    case "cancelled":
      return { label: "Cancelled", classes: GRAY };
    case "unknown":
      return { label: "Unknown", classes: GRAY };
    default:
      return { label: outcome, classes: GRAY };
  }
}

// Endpoint-verification state → a short human phrase (customer-friendly).
export function endpointStateLabel(state: string | null): string {
  switch (state) {
    case "complete":
      return "All endpoints verified";
    case "limited":
      return "Verified with limitations";
    case "incomplete":
      return "Verification incomplete";
    case "failed":
      return "Verification failed";
    case "no_targets":
      return "No endpoints to verify";
    case "disabled":
      return "Endpoint verification off";
    case null:
    case undefined:
      return "Not available";
    default:
      return state;
  }
}

// A limitation reason code → one plain-language line explaining WHY verification was limited.
export function limitationText(code: string | null): string | null {
  switch (code) {
    case "unresponsive_origins":
      return "Some origins did not respond";
    case "insufficient_budget":
      return "The scan budget was exhausted";
    case "timeout":
      return "The verification pass timed out";
    case "output_truncated":
      return "Some results were truncated";
    case "catalog_drift":
      return "The detection catalog changed mid-scan";
    case "parser_incomplete":
      return "Some results could not be attributed";
    case "writer_error":
      return "Some results could not be saved";
    case "execution_error":
      return "The verification pass errored";
    case "configuration_error":
      return "The verification pass was misconfigured";
    case "data_inconsistent":
      return "Verification data was inconsistent — treated conservatively";
    case "unknown":
      return "Verification was interrupted for an unknown reason";
    case null:
    case undefined:
      return null;
    default:
      return code;
  }
}

// All limitation reasons as human lines, most-severe first (backend already ordered them).
export function limitationTexts(codes: string[] | null | undefined): string[] {
  if (!codes) return [];
  return codes.map((c) => limitationText(c)).filter((t): t is string => !!t);
}

// coverage_percent → display string. null (empty set) → an em dash, never "100%".
export function coveragePercentText(percent: number | null): string {
  if (percent === null || percent === undefined) return "—";
  return `${percent}%`;
}

// A colored badge for the endpoint state (used next to the count line).
export function endpointStateBadge(state: string | null): Badge {
  switch (state) {
    case "complete":
      return { label: endpointStateLabel(state), classes: GREEN };
    case "limited":
    case "incomplete":
      return { label: endpointStateLabel(state), classes: AMBER };
    case "failed":
      return { label: endpointStateLabel(state), classes: RED };
    case "no_targets":
    case "disabled":
      return { label: endpointStateLabel(state), classes: GRAY };
    default:
      return { label: endpointStateLabel(state), classes: GRAY };
  }
}
