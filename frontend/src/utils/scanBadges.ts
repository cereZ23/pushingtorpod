// Shared badge presentation for scan runs — used by the runs table and the scan-detail header
// so Tier / Trigger look identical everywhere. Never infer a tier from duration/phases: an
// unknown tier (legacy runs, untiered retests → scan_tier === null) renders explicitly as "Unknown".

export interface Badge {
  label: string;
  classes: string;
}

const UNKNOWN_TIER: Badge = {
  label: "Unknown",
  classes: "bg-gray-100 text-gray-600 dark:bg-gray-700/30 dark:text-gray-400",
};

const TIER_BADGES: Record<number, Badge> = {
  1: {
    label: "T1 Safe Continuous",
    classes: "bg-green-100 text-green-800 dark:bg-green-900/20 dark:text-green-400",
  },
  2: {
    label: "T2 Extended",
    classes: "bg-amber-100 text-amber-800 dark:bg-amber-900/20 dark:text-amber-400",
  },
  3: {
    label: "T3 Authorized Active",
    classes: "bg-red-100 text-red-800 dark:bg-red-900/20 dark:text-red-400",
  },
};

export function tierBadge(scanTier: number | null | undefined): Badge {
  return (scanTier != null && TIER_BADGES[scanTier]) || UNKNOWN_TIER;
}

const TRIGGER_BADGES: Record<string, Badge> = {
  manual: {
    label: "Manual",
    classes: "bg-blue-100 text-blue-800 dark:bg-blue-900/20 dark:text-blue-400",
  },
  scheduler: {
    label: "Scheduled",
    classes: "bg-violet-100 text-violet-800 dark:bg-violet-900/20 dark:text-violet-400",
  },
  schedule: {
    label: "Scheduled",
    classes: "bg-violet-100 text-violet-800 dark:bg-violet-900/20 dark:text-violet-400",
  },
  api: {
    label: "API",
    classes: "bg-gray-100 text-gray-700 dark:bg-gray-700/30 dark:text-gray-300",
  },
  retest: {
    label: "Retest",
    classes: "bg-indigo-100 text-indigo-800 dark:bg-indigo-900/20 dark:text-indigo-400",
  },
};

export function triggerBadge(triggeredBy: string | null | undefined): Badge {
  if (triggeredBy && TRIGGER_BADGES[triggeredBy]) return TRIGGER_BADGES[triggeredBy];
  // Unknown/custom trigger label (e.g. an ad-hoc validation tag): show it verbatim, neutral style.
  return {
    label: triggeredBy || "Unknown",
    classes: "bg-gray-100 text-gray-600 dark:bg-gray-700/30 dark:text-gray-400",
  };
}
