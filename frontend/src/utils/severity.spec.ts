import { describe, it, expect } from 'vitest'
import {
  getSeverityBadgeClass,
  getFindingStatusBadgeClass,
  getIssueStatusBadgeClass,
  getIssueTransitionButtonClass,
  getAssetTypeBadgeClass,
  getPriorityBadgeClass,
  formatIssueStatusLabel,
  getRiskGrade,
  getRiskScoreClasses,
  SEVERITY_HEX,
  SEVERITY_ORDER,
  ASSET_TYPE_HEX,
} from '@/utils/severity'
import type { RiskGrade as RiskGradeType } from '@/utils/severity'

// ---------------------------------------------------------------------------
// getSeverityBadgeClass
// ---------------------------------------------------------------------------

describe('getSeverityBadgeClass', () => {
  it('returns red classes for critical severity', () => {
    const result = getSeverityBadgeClass('critical')
    expect(result).toContain('bg-red-100')
    expect(result).toContain('text-red-800')
  })

  it('returns orange classes for high severity', () => {
    const result = getSeverityBadgeClass('high')
    expect(result).toContain('bg-orange-100')
    expect(result).toContain('text-orange-800')
  })

  it('returns yellow classes for medium severity', () => {
    const result = getSeverityBadgeClass('medium')
    expect(result).toContain('bg-yellow-100')
    expect(result).toContain('text-yellow-800')
  })

  it('returns blue classes for low severity', () => {
    const result = getSeverityBadgeClass('low')
    expect(result).toContain('bg-blue-100')
    expect(result).toContain('text-blue-800')
  })

  it('returns gray classes for info severity', () => {
    const result = getSeverityBadgeClass('info')
    expect(result).toContain('bg-gray-100')
    expect(result).toContain('text-gray-800')
  })

  it('is case-insensitive', () => {
    expect(getSeverityBadgeClass('CRITICAL')).toContain('bg-red-100')
    expect(getSeverityBadgeClass('High')).toContain('bg-orange-100')
    expect(getSeverityBadgeClass('MEDIUM')).toContain('bg-yellow-100')
  })

  it('falls back to info for unknown severity', () => {
    const result = getSeverityBadgeClass('unknown')
    expect(result).toBe(getSeverityBadgeClass('info'))
  })

  it('falls back to info for empty string', () => {
    const result = getSeverityBadgeClass('')
    expect(result).toBe(getSeverityBadgeClass('info'))
  })

  it('includes dark mode classes', () => {
    const result = getSeverityBadgeClass('critical')
    expect(result).toContain('dark:bg-red-900/30')
    expect(result).toContain('dark:text-red-300')
  })

  it('returns distinct classes for each severity level', () => {
    const severities = ['critical', 'high', 'medium', 'low', 'info']
    const results = severities.map(getSeverityBadgeClass)
    const unique = new Set(results)
    expect(unique.size).toBe(severities.length)
  })
})

// ---------------------------------------------------------------------------
// SEVERITY_HEX
// ---------------------------------------------------------------------------

describe('SEVERITY_HEX', () => {
  it('has hex colors for all severity levels', () => {
    expect(SEVERITY_HEX.critical).toBe('#dc2626')
    expect(SEVERITY_HEX.high).toBe('#ea580c')
    expect(SEVERITY_HEX.medium).toBe('#eab308')
    expect(SEVERITY_HEX.low).toBe('#3b82f6')
    expect(SEVERITY_HEX.info).toBe('#6b7280')
  })

  it('has exactly 5 entries', () => {
    expect(Object.keys(SEVERITY_HEX)).toHaveLength(5)
  })

  it('all values are valid hex color strings', () => {
    for (const color of Object.values(SEVERITY_HEX)) {
      expect(color).toMatch(/^#[0-9a-f]{6}$/i)
    }
  })
})

// ---------------------------------------------------------------------------
// SEVERITY_ORDER
// ---------------------------------------------------------------------------

describe('SEVERITY_ORDER', () => {
  it('lists severities from most to least severe', () => {
    expect(SEVERITY_ORDER).toEqual(['critical', 'high', 'medium', 'low', 'info'])
  })

  it('has 5 entries', () => {
    expect(SEVERITY_ORDER).toHaveLength(5)
  })
})

// ---------------------------------------------------------------------------
// getFindingStatusBadgeClass
// ---------------------------------------------------------------------------

describe('getFindingStatusBadgeClass', () => {
  it('returns red classes for open status', () => {
    const result = getFindingStatusBadgeClass('open')
    expect(result).toContain('bg-red-100')
    expect(result).toContain('text-red-800')
  })

  it('returns yellow classes for suppressed status', () => {
    const result = getFindingStatusBadgeClass('suppressed')
    expect(result).toContain('bg-yellow-100')
    expect(result).toContain('text-yellow-800')
  })

  it('returns green classes for fixed status', () => {
    const result = getFindingStatusBadgeClass('fixed')
    expect(result).toContain('bg-green-100')
    expect(result).toContain('text-green-800')
  })

  it('is case-insensitive', () => {
    expect(getFindingStatusBadgeClass('OPEN')).toContain('bg-red-100')
    expect(getFindingStatusBadgeClass('Fixed')).toContain('bg-green-100')
  })

  it('falls back to gray for unknown status', () => {
    const result = getFindingStatusBadgeClass('unknown')
    expect(result).toContain('bg-gray-100')
    expect(result).toContain('text-gray-800')
  })

  it('falls back to gray for empty string', () => {
    const result = getFindingStatusBadgeClass('')
    expect(result).toContain('bg-gray-100')
  })

  it('includes dark mode classes', () => {
    const result = getFindingStatusBadgeClass('open')
    expect(result).toContain('dark:')
  })
})

// ---------------------------------------------------------------------------
// getIssueStatusBadgeClass
// ---------------------------------------------------------------------------

describe('getIssueStatusBadgeClass', () => {
  const statusTests: Array<{ status: string; containsColor: string }> = [
    { status: 'open', containsColor: 'red' },
    { status: 'triaged', containsColor: 'purple' },
    { status: 'in_progress', containsColor: 'blue' },
    { status: 'mitigated', containsColor: 'teal' },
    { status: 'verifying', containsColor: 'indigo' },
    { status: 'verified_fixed', containsColor: 'green' },
    { status: 'closed', containsColor: 'gray' },
    { status: 'false_positive', containsColor: 'yellow' },
    { status: 'accepted_risk', containsColor: 'orange' },
  ]

  for (const { status, containsColor } of statusTests) {
    it(`returns ${containsColor} classes for ${status} status`, () => {
      const result = getIssueStatusBadgeClass(status)
      expect(result).toContain(`bg-${containsColor}-`)
    })
  }

  it('is case-insensitive', () => {
    expect(getIssueStatusBadgeClass('OPEN')).toContain('bg-red-')
    expect(getIssueStatusBadgeClass('In_Progress')).toContain('bg-blue-')
  })

  it('falls back to gray for unknown status', () => {
    const result = getIssueStatusBadgeClass('nonexistent')
    expect(result).toContain('bg-gray-100')
  })

  it('returns distinct classes for all 9 statuses', () => {
    const statuses = statusTests.map((t) => t.status)
    const results = statuses.map(getIssueStatusBadgeClass)
    const unique = new Set(results)
    expect(unique.size).toBe(9)
  })
})

// ---------------------------------------------------------------------------
// getIssueTransitionButtonClass
// ---------------------------------------------------------------------------

describe('getIssueTransitionButtonClass', () => {
  const transitionStatuses = [
    'open',
    'triaged',
    'in_progress',
    'mitigated',
    'verifying',
    'verified_fixed',
    'closed',
    'false_positive',
    'accepted_risk',
  ]

  for (const status of transitionStatuses) {
    it(`returns hover classes for ${status} transition`, () => {
      const result = getIssueTransitionButtonClass(status)
      expect(result).toContain('hover:')
      expect(result).toContain('border-')
    })
  }

  it('falls back to closed classes for unknown status', () => {
    const result = getIssueTransitionButtonClass('unknown')
    expect(result).toBe(getIssueTransitionButtonClass('closed'))
  })

  it('returns distinct classes for each status', () => {
    const results = transitionStatuses.map(getIssueTransitionButtonClass)
    const unique = new Set(results)
    expect(unique.size).toBe(transitionStatuses.length)
  })
})

// ---------------------------------------------------------------------------
// getAssetTypeBadgeClass
// ---------------------------------------------------------------------------

describe('getAssetTypeBadgeClass', () => {
  const typeTests: Array<{ type: string; containsColor: string }> = [
    { type: 'domain', containsColor: 'blue' },
    { type: 'subdomain', containsColor: 'green' },
    { type: 'ip', containsColor: 'purple' },
    { type: 'url', containsColor: 'yellow' },
    { type: 'service', containsColor: 'pink' },
  ]

  for (const { type, containsColor } of typeTests) {
    it(`returns ${containsColor} classes for ${type} asset type`, () => {
      const result = getAssetTypeBadgeClass(type)
      expect(result).toContain(`bg-${containsColor}-100`)
    })
  }

  it('is case-insensitive', () => {
    expect(getAssetTypeBadgeClass('DOMAIN')).toContain('bg-blue-100')
    expect(getAssetTypeBadgeClass('IP')).toContain('bg-purple-100')
  })

  it('falls back to gray for unknown type', () => {
    const result = getAssetTypeBadgeClass('unknown')
    expect(result).toContain('bg-gray-100')
  })

  it('falls back to gray for empty string', () => {
    const result = getAssetTypeBadgeClass('')
    expect(result).toContain('bg-gray-100')
  })

  it('includes dark mode classes', () => {
    const result = getAssetTypeBadgeClass('domain')
    expect(result).toContain('dark:bg-blue-900/20')
    expect(result).toContain('dark:text-blue-400')
  })
})

// ---------------------------------------------------------------------------
// ASSET_TYPE_HEX
// ---------------------------------------------------------------------------

describe('ASSET_TYPE_HEX', () => {
  it('has hex colors for all asset types', () => {
    expect(ASSET_TYPE_HEX.domain).toBe('#3b82f6')
    expect(ASSET_TYPE_HEX.subdomain).toBe('#8b5cf6')
    expect(ASSET_TYPE_HEX.ip).toBe('#06b6d4')
    expect(ASSET_TYPE_HEX.url).toBe('#10b981')
    expect(ASSET_TYPE_HEX.service).toBe('#f59e0b')
  })

  it('has exactly 5 entries', () => {
    expect(Object.keys(ASSET_TYPE_HEX)).toHaveLength(5)
  })

  it('all values are valid hex color strings', () => {
    for (const color of Object.values(ASSET_TYPE_HEX)) {
      expect(color).toMatch(/^#[0-9a-f]{6}$/i)
    }
  })
})

// ---------------------------------------------------------------------------
// getPriorityBadgeClass
// ---------------------------------------------------------------------------

describe('getPriorityBadgeClass', () => {
  it('returns red classes for critical priority', () => {
    const result = getPriorityBadgeClass('critical')
    expect(result).toContain('bg-red-100')
    expect(result).toContain('text-red-800')
  })

  it('returns orange classes for high priority', () => {
    const result = getPriorityBadgeClass('high')
    expect(result).toContain('bg-orange-100')
    expect(result).toContain('text-orange-800')
  })

  it('returns yellow classes for medium priority', () => {
    const result = getPriorityBadgeClass('medium')
    expect(result).toContain('bg-yellow-100')
    expect(result).toContain('text-yellow-800')
  })

  it('returns blue classes for low priority', () => {
    const result = getPriorityBadgeClass('low')
    expect(result).toContain('bg-blue-100')
    expect(result).toContain('text-blue-800')
  })

  it('is case-insensitive', () => {
    expect(getPriorityBadgeClass('CRITICAL')).toContain('bg-red-100')
    expect(getPriorityBadgeClass('High')).toContain('bg-orange-100')
  })

  it('falls back to gray for unknown priority', () => {
    const result = getPriorityBadgeClass('unknown')
    expect(result).toContain('bg-gray-100')
  })

  it('falls back to gray for empty string', () => {
    const result = getPriorityBadgeClass('')
    expect(result).toContain('bg-gray-100')
  })

  it('includes dark mode classes', () => {
    const result = getPriorityBadgeClass('critical')
    expect(result).toContain('dark:bg-red-900/20')
    expect(result).toContain('dark:text-red-400')
  })
})

// ---------------------------------------------------------------------------
// formatIssueStatusLabel
// ---------------------------------------------------------------------------

describe('formatIssueStatusLabel', () => {
  const labelTests: Array<{ status: string; expected: string }> = [
    { status: 'open', expected: 'Open' },
    { status: 'triaged', expected: 'Triaged' },
    { status: 'in_progress', expected: 'In Progress' },
    { status: 'mitigated', expected: 'Mitigated' },
    { status: 'verifying', expected: 'Verifying' },
    { status: 'verified_fixed', expected: 'Verified Fixed' },
    { status: 'closed', expected: 'Closed' },
    { status: 'false_positive', expected: 'False Positive' },
    { status: 'accepted_risk', expected: 'Accepted Risk' },
  ]

  for (const { status, expected } of labelTests) {
    it(`formats "${status}" as "${expected}"`, () => {
      expect(formatIssueStatusLabel(status)).toBe(expected)
    })
  }

  it('is case-insensitive', () => {
    expect(formatIssueStatusLabel('OPEN')).toBe('Open')
    expect(formatIssueStatusLabel('In_Progress')).toBe('In Progress')
  })

  it('returns the raw status for unknown values', () => {
    expect(formatIssueStatusLabel('custom_status')).toBe('custom_status')
  })

  it('returns empty string for empty input', () => {
    expect(formatIssueStatusLabel('')).toBe('')
  })
})

// ---------------------------------------------------------------------------
// getRiskGrade
// ---------------------------------------------------------------------------

describe('getRiskGrade', () => {
  it('returns grade A (green) for score <= 20', () => {
    const grade: RiskGradeType = getRiskGrade(0)
    expect(grade.letter).toBe('A')
    expect(grade.color).toBe('#16a34a')
  })

  it('returns grade A for score exactly 20', () => {
    expect(getRiskGrade(20).letter).toBe('A')
  })

  it('returns grade B (lime) for score 21-40', () => {
    const grade = getRiskGrade(21)
    expect(grade.letter).toBe('B')
    expect(grade.color).toBe('#65a30d')
  })

  it('returns grade B for score exactly 40', () => {
    expect(getRiskGrade(40).letter).toBe('B')
  })

  it('returns grade C (yellow) for score 41-60', () => {
    const grade = getRiskGrade(50)
    expect(grade.letter).toBe('C')
    expect(grade.color).toBe('#eab308')
  })

  it('returns grade C for score exactly 60', () => {
    expect(getRiskGrade(60).letter).toBe('C')
  })

  it('returns grade D (orange) for score 61-80', () => {
    const grade = getRiskGrade(70)
    expect(grade.letter).toBe('D')
    expect(grade.color).toBe('#ea580c')
  })

  it('returns grade D for score exactly 80', () => {
    expect(getRiskGrade(80).letter).toBe('D')
  })

  it('returns grade F (red) for score > 80', () => {
    const grade = getRiskGrade(81)
    expect(grade.letter).toBe('F')
    expect(grade.color).toBe('#dc2626')
  })

  it('returns grade F for score 100', () => {
    expect(getRiskGrade(100).letter).toBe('F')
  })

  it('handles score 0 as grade A', () => {
    expect(getRiskGrade(0).letter).toBe('A')
  })

  it('handles negative scores as grade A', () => {
    expect(getRiskGrade(-10).letter).toBe('A')
  })

  it('handles very high scores as grade F', () => {
    expect(getRiskGrade(999).letter).toBe('F')
  })

  it('all grades have valid hex colors', () => {
    const scores = [0, 25, 50, 75, 100]
    for (const score of scores) {
      const grade = getRiskGrade(score)
      expect(grade.color).toMatch(/^#[0-9a-f]{6}$/i)
    }
  })
})

// ---------------------------------------------------------------------------
// getRiskScoreClasses
// ---------------------------------------------------------------------------

describe('getRiskScoreClasses', () => {
  it('returns red classes for score >= 80', () => {
    const classes = getRiskScoreClasses(85)
    expect(classes.bg).toBe('bg-red-500')
    expect(classes.text).toContain('text-red-')
    expect(classes.ring).toContain('ring-red-')
    expect(classes.fill).toBe('#dc2626')
  })

  it('returns orange classes for score 60-79', () => {
    const classes = getRiskScoreClasses(65)
    expect(classes.bg).toBe('bg-orange-500')
    expect(classes.text).toContain('text-orange-')
    expect(classes.fill).toBe('#ea580c')
  })

  it('returns yellow classes for score 40-59', () => {
    const classes = getRiskScoreClasses(45)
    expect(classes.bg).toBe('bg-yellow-500')
    expect(classes.text).toContain('text-yellow-')
    expect(classes.fill).toBe('#eab308')
  })

  it('returns blue classes for score 20-39', () => {
    const classes = getRiskScoreClasses(25)
    expect(classes.bg).toBe('bg-blue-500')
    expect(classes.text).toContain('text-blue-')
    expect(classes.fill).toBe('#3b82f6')
  })

  it('returns green classes for score < 20', () => {
    const classes = getRiskScoreClasses(10)
    expect(classes.bg).toBe('bg-green-500')
    expect(classes.text).toContain('text-green-')
    expect(classes.fill).toBe('#16a34a')
  })

  it('returns green classes for score 0', () => {
    const classes = getRiskScoreClasses(0)
    expect(classes.bg).toBe('bg-green-500')
  })

  it('handles boundary score 80 as red', () => {
    const classes = getRiskScoreClasses(80)
    expect(classes.bg).toBe('bg-red-500')
  })

  it('handles boundary score 60 as orange', () => {
    const classes = getRiskScoreClasses(60)
    expect(classes.bg).toBe('bg-orange-500')
  })

  it('handles boundary score 40 as yellow', () => {
    const classes = getRiskScoreClasses(40)
    expect(classes.bg).toBe('bg-yellow-500')
  })

  it('handles boundary score 20 as blue', () => {
    const classes = getRiskScoreClasses(20)
    expect(classes.bg).toBe('bg-blue-500')
  })

  it('all results include dark mode text classes', () => {
    const scores = [10, 30, 50, 70, 90]
    for (const score of scores) {
      const classes = getRiskScoreClasses(score)
      expect(classes.text).toContain('dark:')
    }
  })

  it('returns an object with exactly bg, text, ring, fill keys', () => {
    const classes = getRiskScoreClasses(50)
    expect(Object.keys(classes).sort()).toEqual(['bg', 'fill', 'ring', 'text'])
  })
})
