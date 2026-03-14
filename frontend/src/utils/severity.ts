/**
 * Shared severity, status, priority, and asset type color mappings.
 *
 * Replaces 8+ duplicated color functions across views.
 * All views MUST import from here instead of defining local copies.
 */

// -- Severity (findings, issues) ------------------------------------------------

/** Badge classes: colored background with contrasting text (light + dark mode) */
export function getSeverityBadgeClass(severity: string): string {
  const classes: Record<string, string> = {
    critical: "bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-300",
    high: "bg-orange-100 text-orange-800 dark:bg-orange-900/30 dark:text-orange-300",
    medium:
      "bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-300",
    low: "bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-300",
    info: "bg-gray-100 text-gray-800 dark:bg-gray-900/30 dark:text-gray-300",
  };
  return classes[severity.toLowerCase()] || classes.info;
}

/** Hex colors for SVG charts (donut, bars, heatmap) */
export const SEVERITY_HEX: Record<string, string> = {
  critical: "#dc2626",
  high: "#ea580c",
  medium: "#eab308",
  low: "#3b82f6",
  info: "#6b7280",
};

/** Ordered severity levels (most severe first) */
export const SEVERITY_ORDER = [
  "critical",
  "high",
  "medium",
  "low",
  "info",
] as const;
export type SeverityLevel = (typeof SEVERITY_ORDER)[number];

// -- Finding Status --------------------------------------------------------------

export function getFindingStatusBadgeClass(status: string): string {
  const classes: Record<string, string> = {
    open: "bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-300",
    suppressed:
      "bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-300",
    fixed:
      "bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-300",
  };
  return (
    classes[status.toLowerCase()] ||
    "bg-gray-100 text-gray-800 dark:bg-gray-900/30 dark:text-gray-300"
  );
}

// -- Issue Status ----------------------------------------------------------------

export function getIssueStatusBadgeClass(status: string): string {
  const classes: Record<string, string> = {
    open: "bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-300",
    triaged:
      "bg-purple-100 text-purple-800 dark:bg-purple-900/30 dark:text-purple-300",
    in_progress:
      "bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-300",
    mitigated:
      "bg-teal-100 text-teal-800 dark:bg-teal-900/30 dark:text-teal-300",
    verifying:
      "bg-indigo-100 text-indigo-800 dark:bg-indigo-900/30 dark:text-indigo-300",
    verified_fixed:
      "bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-300",
    closed: "bg-gray-100 text-gray-600 dark:bg-gray-700/30 dark:text-gray-400",
    false_positive:
      "bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-300",
    accepted_risk:
      "bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-300",
  };
  return (
    classes[status.toLowerCase()] ||
    "bg-gray-100 text-gray-800 dark:bg-gray-900/30 dark:text-gray-300"
  );
}

export function getIssueTransitionButtonClass(status: string): string {
  const classes: Record<string, string> = {
    open: "bg-red-50 text-red-700 border-red-200 hover:bg-red-100 dark:bg-red-900/10 dark:text-red-400 dark:border-red-800 dark:hover:bg-red-900/20",
    triaged:
      "bg-purple-50 text-purple-700 border-purple-200 hover:bg-purple-100 dark:bg-purple-900/10 dark:text-purple-400 dark:border-purple-800 dark:hover:bg-purple-900/20",
    in_progress:
      "bg-blue-50 text-blue-700 border-blue-200 hover:bg-blue-100 dark:bg-blue-900/10 dark:text-blue-400 dark:border-blue-800 dark:hover:bg-blue-900/20",
    mitigated:
      "bg-teal-50 text-teal-700 border-teal-200 hover:bg-teal-100 dark:bg-teal-900/10 dark:text-teal-400 dark:border-teal-800 dark:hover:bg-teal-900/20",
    verifying:
      "bg-indigo-50 text-indigo-700 border-indigo-200 hover:bg-indigo-100 dark:bg-indigo-900/10 dark:text-indigo-400 dark:border-indigo-800 dark:hover:bg-indigo-900/20",
    verified_fixed:
      "bg-green-50 text-green-700 border-green-200 hover:bg-green-100 dark:bg-green-900/10 dark:text-green-400 dark:border-green-800 dark:hover:bg-green-900/20",
    closed:
      "bg-gray-50 text-gray-700 border-gray-200 hover:bg-gray-100 dark:bg-gray-800/30 dark:text-gray-400 dark:border-gray-700 dark:hover:bg-gray-800/50",
    false_positive:
      "bg-yellow-50 text-yellow-700 border-yellow-200 hover:bg-yellow-100 dark:bg-yellow-900/10 dark:text-yellow-400 dark:border-yellow-800 dark:hover:bg-yellow-900/20",
    accepted_risk:
      "bg-orange-50 text-orange-700 border-orange-200 hover:bg-orange-100 dark:bg-orange-900/10 dark:text-orange-400 dark:border-orange-800 dark:hover:bg-orange-900/20",
  };
  return classes[status.toLowerCase()] || classes.closed;
}

// -- Asset Type ------------------------------------------------------------------

export function getAssetTypeBadgeClass(type: string): string {
  const classes: Record<string, string> = {
    domain: "bg-blue-100 text-blue-800 dark:bg-blue-900/20 dark:text-blue-400",
    subdomain:
      "bg-green-100 text-green-800 dark:bg-green-900/20 dark:text-green-400",
    ip: "bg-purple-100 text-purple-800 dark:bg-purple-900/20 dark:text-purple-400",
    url: "bg-yellow-100 text-yellow-800 dark:bg-yellow-900/20 dark:text-yellow-400",
    service: "bg-pink-100 text-pink-800 dark:bg-pink-900/20 dark:text-pink-400",
  };
  return (
    classes[type.toLowerCase()] ||
    "bg-gray-100 text-gray-800 dark:bg-gray-900/20 dark:text-gray-400"
  );
}

export const ASSET_TYPE_HEX: Record<string, string> = {
  domain: "#3b82f6",
  subdomain: "#8b5cf6",
  ip: "#06b6d4",
  url: "#10b981",
  service: "#f59e0b",
};

// -- Priority (assets) -----------------------------------------------------------

export function getPriorityBadgeClass(priority: string): string {
  const classes: Record<string, string> = {
    critical: "bg-red-100 text-red-800 dark:bg-red-900/20 dark:text-red-400",
    high: "bg-orange-100 text-orange-800 dark:bg-orange-900/20 dark:text-orange-400",
    medium:
      "bg-yellow-100 text-yellow-800 dark:bg-yellow-900/20 dark:text-yellow-400",
    low: "bg-blue-100 text-blue-800 dark:bg-blue-900/20 dark:text-blue-400",
  };
  return (
    classes[priority.toLowerCase()] ||
    "bg-gray-100 text-gray-800 dark:bg-gray-900/20 dark:text-gray-400"
  );
}

// -- Issue Status Labels ---------------------------------------------------------

export function formatIssueStatusLabel(status: string): string {
  const labels: Record<string, string> = {
    open: "Open",
    triaged: "Triaged",
    in_progress: "In Progress",
    mitigated: "Mitigated",
    verifying: "Verifying",
    verified_fixed: "Verified Fixed",
    closed: "Closed",
    false_positive: "False Positive",
    accepted_risk: "Accepted Risk",
  };
  return labels[status.toLowerCase()] || status;
}

// -- Risk Score ------------------------------------------------------------------

export interface RiskGrade {
  letter: string;
  color: string;
}

export function getRiskGrade(score: number): RiskGrade {
  if (score <= 20) return { letter: "A", color: "#16a34a" };
  if (score <= 40) return { letter: "B", color: "#65a30d" };
  if (score <= 60) return { letter: "C", color: "#eab308" };
  if (score <= 80) return { letter: "D", color: "#ea580c" };
  return { letter: "F", color: "#dc2626" };
}

export function getRiskScoreClasses(score: number): {
  bg: string;
  text: string;
  ring: string;
  fill: string;
} {
  if (score > 80)
    return {
      bg: "bg-red-500",
      text: "text-red-600 dark:text-red-400",
      ring: "ring-red-500/20",
      fill: "#dc2626",
    };
  if (score > 60)
    return {
      bg: "bg-orange-500",
      text: "text-orange-600 dark:text-orange-400",
      ring: "ring-orange-500/20",
      fill: "#ea580c",
    };
  if (score > 40)
    return {
      bg: "bg-yellow-500",
      text: "text-yellow-600 dark:text-yellow-400",
      ring: "ring-yellow-500/20",
      fill: "#eab308",
    };
  if (score > 20)
    return {
      bg: "bg-blue-500",
      text: "text-blue-600 dark:text-blue-400",
      ring: "ring-blue-500/20",
      fill: "#3b82f6",
    };
  return {
    bg: "bg-green-500",
    text: "text-green-600 dark:text-green-400",
    ring: "ring-green-500/20",
    fill: "#16a34a",
  };
}
