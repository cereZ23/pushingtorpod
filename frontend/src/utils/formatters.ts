/**
 * Shared date/time formatting utilities.
 *
 * Replaces 16 separate `formatDate` implementations across views.
 * All views MUST import from here instead of defining local copies.
 */

/**
 * Format a date string for display.
 *
 * @param dateString - ISO date string or null/undefined
 * @param mode - 'relative' for "5m ago", 'date' for locale date, 'datetime' for date+time
 * @returns Formatted string, or '—' for invalid/missing input
 */
/**
 * Parse an API timestamp into a Date.
 *
 * The backend serialises naive UTC datetimes (no timezone marker, e.g.
 * "2026-08-01T15:37:41"). `new Date()` would parse a marker-less string as
 * LOCAL time, which offsets every displayed time and inflates durations by the
 * viewer's UTC offset (e.g. a 31-minute scan shown as "2h 27m" in CEST). Treat a
 * marker-less string as UTC so times and durations are correct.
 */
export function parseApiDate(dateString: string): Date {
  const hasTz = /(Z|[+-]\d{2}:?\d{2})$/.test(dateString)
  return new Date(hasTz ? dateString : `${dateString}Z`)
}

export function formatDate(dateString: string | null | undefined, mode: 'relative' | 'date' | 'datetime' = 'datetime'): string {
  if (!dateString) return '—'

  const date = parseApiDate(dateString)
  if (isNaN(date.getTime())) return '—'

  if (mode === 'relative') {
    return formatRelativeTime(date)
  }

  if (mode === 'date') {
    return date.toLocaleDateString()
  }

  return date.toLocaleString()
}

/**
 * Format a date as relative time (e.g. "5m ago", "3h ago", "2d ago").
 */
export function formatRelativeTime(date: Date): string {
  const now = new Date()
  const diffMs = now.getTime() - date.getTime()
  const diffSec = Math.floor(diffMs / 1000)

  if (diffSec < 60) return 'just now'
  if (diffSec < 3600) return `${Math.floor(diffSec / 60)}m ago`
  if (diffSec < 86400) return `${Math.floor(diffSec / 3600)}h ago`
  if (diffSec < 604800) return `${Math.floor(diffSec / 86400)}d ago`

  return date.toLocaleDateString()
}

/**
 * Format a date for table columns (compact date only).
 */
export function formatDateShort(dateString: string | null | undefined): string {
  return formatDate(dateString, 'date')
}
