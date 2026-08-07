// Shared badge presentation for scan runs — used by the runs table and the scan-detail header
// so Tier / Trigger look identical everywhere. Never infer a tier from duration/phases: an
// unknown tier (legacy runs, untiered retests → scan_tier === null) renders explicitly as "Unknown".

export interface Badge {
  label: string; // full label (tooltips, detail view)
  short: string; // compact label for dense tables (e.g. "T1")
  classes: string;
  title?: string; // optional extra tooltip (e.g. the raw custom trigger label)
}

const UNKNOWN_TIER: Badge = {
  label: "Unknown",
  short: "—",
  classes: "bg-gray-100 text-gray-600 dark:bg-gray-700/30 dark:text-gray-400",
};

const TIER_BADGES: Record<number, Badge> = {
  1: {
    label: "T1 Safe Continuous",
    short: "T1",
    classes: "bg-green-100 text-green-800 dark:bg-green-900/20 dark:text-green-400",
  },
  2: {
    label: "T2 Extended",
    short: "T2",
    classes: "bg-amber-100 text-amber-800 dark:bg-amber-900/20 dark:text-amber-400",
  },
  3: {
    label: "T3 Authorized Active",
    short: "T3",
    classes: "bg-red-100 text-red-800 dark:bg-red-900/20 dark:text-red-400",
  },
};

export function tierBadge(scanTier: number | null | undefined): Badge {
  return (scanTier != null && TIER_BADGES[scanTier]) || UNKNOWN_TIER;
}

const TRIGGER_BADGES: Record<string, Badge> = {
  manual: {
    label: "Manual",
    short: "Manual",
    classes: "bg-blue-100 text-blue-800 dark:bg-blue-900/20 dark:text-blue-400",
  },
  scheduled: {
    label: "Scheduled",
    short: "Scheduled",
    classes: "bg-violet-100 text-violet-800 dark:bg-violet-900/20 dark:text-violet-400",
  },
  api: {
    label: "API",
    short: "API",
    classes: "bg-gray-100 text-gray-700 dark:bg-gray-700/30 dark:text-gray-300",
  },
  retest: {
    label: "Retest",
    short: "Retest",
    classes: "bg-indigo-100 text-indigo-800 dark:bg-indigo-900/20 dark:text-indigo-400",
  },
};

// Data-driven from the server-decided `trigger_type` (manual/scheduled/api/retest). The optional
// `trigger_label` is descriptive only and shows in the tooltip. A NULL trigger_type is a legacy
// custom run → "Custom" (label in the tooltip) or "Unknown" — NEVER guessed as "Manual".
export function triggerBadge(
  triggerType: string | null | undefined,
  triggerLabel?: string | null,
): Badge {
  if (triggerType && TRIGGER_BADGES[triggerType]) {
    const badge = TRIGGER_BADGES[triggerType];
    return triggerLabel ? { ...badge, title: triggerLabel } : badge;
  }
  if (triggerLabel) {
    return {
      label: "Custom",
      short: "Custom",
      classes: "bg-gray-100 text-gray-600 dark:bg-gray-700/30 dark:text-gray-400",
      title: triggerLabel,
    };
  }
  return {
    label: "Unknown",
    short: "Unknown",
    classes: "bg-gray-100 text-gray-600 dark:bg-gray-700/30 dark:text-gray-400",
  };
}
