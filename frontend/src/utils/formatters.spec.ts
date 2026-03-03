import { describe, it, expect } from 'vitest'
import { formatDate, formatDateShort, formatRelativeTime } from './formatters'

describe('formatters', () => {
  describe('formatDateShort', () => {
    it('returns a formatted date string for valid ISO input', () => {
      const result = formatDateShort('2026-01-15T10:30:00Z')
      expect(result).toBeTruthy()
      expect(typeof result).toBe('string')
    })

    it('returns dash for null input', () => {
      expect(formatDateShort(null)).toBe('\u2014')
    })

    it('returns dash for undefined input', () => {
      expect(formatDateShort(undefined)).toBe('\u2014')
    })

    it('returns dash for invalid date string', () => {
      expect(formatDateShort('not-a-date')).toBe('\u2014')
    })
  })

  describe('formatDate', () => {
    it('defaults to datetime mode', () => {
      const result = formatDate('2026-01-15T10:30:00Z')
      expect(result).toBeTruthy()
      expect(result).not.toBe('\u2014')
    })

    it('supports relative mode', () => {
      const recent = new Date(Date.now() - 5 * 60 * 1000).toISOString()
      const result = formatDate(recent, 'relative')
      expect(result).toContain('m ago')
    })

    it('supports date mode', () => {
      const result = formatDate('2026-06-15T12:00:00Z', 'date')
      expect(result).toBeTruthy()
      expect(result).not.toBe('\u2014')
    })
  })

  describe('formatRelativeTime', () => {
    it('returns "just now" for very recent dates', () => {
      const now = new Date()
      expect(formatRelativeTime(now)).toBe('just now')
    })

    it('returns minutes ago for recent dates', () => {
      const fiveMinAgo = new Date(Date.now() - 5 * 60 * 1000)
      expect(formatRelativeTime(fiveMinAgo)).toBe('5m ago')
    })

    it('returns hours ago for older dates', () => {
      const threeHoursAgo = new Date(Date.now() - 3 * 3600 * 1000)
      expect(formatRelativeTime(threeHoursAgo)).toBe('3h ago')
    })

    it('returns days ago for dates within a week', () => {
      const twoDaysAgo = new Date(Date.now() - 2 * 86400 * 1000)
      expect(formatRelativeTime(twoDaysAgo)).toBe('2d ago')
    })

    it('returns locale date string for dates older than a week', () => {
      const twoWeeksAgo = new Date(Date.now() - 14 * 86400 * 1000)
      const result = formatRelativeTime(twoWeeksAgo)
      // Should be a locale date string, not a relative time
      expect(result).not.toContain('ago')
    })
  })
})
