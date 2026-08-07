// Human-readable labels for the coverage-aware auto-close lifecycle (UI-2).
// Turns the API's machine tokens into operator-facing text — the finding-detail timeline shows
// these, never a raw JSON dump.

export interface StateInfo {
  label: string;
  description: string;
  classes: string;
}

const GREEN = "bg-green-100 text-green-800 dark:bg-green-900/20 dark:text-green-400";
const AMBER = "bg-amber-100 text-amber-800 dark:bg-amber-900/20 dark:text-amber-400";
const GRAY = "bg-gray-100 text-gray-700 dark:bg-gray-700/30 dark:text-gray-300";

// The synthetic auto_close.state → a badge label + a one-line explanation.
export function autoCloseStateInfo(state: string): StateInfo {
  switch (state) {
    case "open":
      return { label: "Open", description: "Automatically monitored", classes: GRAY };
    case "eligible_miss":
      return {
        label: "Awaiting confirmation",
        description: "Not seen on the last covered scan",
        classes: AMBER,
      };
    case "awaiting_confirmation":
      return {
        label: "Awaiting confirmation",
        description: "Reached the close threshold — will auto-fix if still absent next scan",
        classes: AMBER,
      };
    case "auto_fixed":
      return {
        label: "Automatically fixed",
        description: "Closed after consecutive covered misses",
        classes: GREEN,
      };
    case "manually_fixed":
      return { label: "Manually fixed", description: "Marked fixed by a user", classes: GRAY };
    case "suppressed":
      return { label: "Suppressed", description: "Muted by a user", classes: GRAY };
    default:
      return { label: state, description: "", classes: GRAY };
  }
}

// A single timeline event → human text. `reason_code` refines the reopened cause.
export function lifecycleEventText(type: string, reasonCode: string | null): string {
  switch (type) {
    case "detected":
      return "Detected";
    case "eligible_miss":
      return "Covered miss — not seen on a covered scan";
    case "miss_reset":
      return "Miss streak reset";
    case "would_close":
      return "Reached the auto-close threshold";
    case "auto_closed":
      return "Automatically fixed";
    case "reopened":
      if (reasonCode === "manual_reopen") return "Reopened (manual)";
      if (reasonCode === "manual_status_change") return "Status changed from fixed (manual)";
      if (reasonCode === "re_detected") return "Reopened — detected again";
      return "Reopened";
    default:
      return type;
  }
}

export function coverageScopeLabel(scope: string | null): string | null {
  if (scope === "endpoint") return "Endpoint";
  if (scope === "host") return "Host";
  return null;
}
