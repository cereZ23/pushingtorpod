import { describe, it, expect } from 'vitest'
import { ref } from 'vue'
import { useRiskGauge } from './useRiskGauge'

describe('useRiskGauge', () => {
  // ---------- Arc path ----------

  describe('arc path', () => {
    it('returns empty string for score 0', () => {
      const score = ref(0)
      const { arc } = useRiskGauge(score)

      expect(arc.value).toBe('')
    })

    it('returns a valid SVG path for score 1', () => {
      const score = ref(1)
      const { arc } = useRiskGauge(score)

      expect(arc.value).toMatch(/^M /)
      expect(arc.value).toContain(' A ')
    })

    it('returns a valid SVG path for score 50', () => {
      const score = ref(50)
      const { arc } = useRiskGauge(score)

      expect(arc.value).toMatch(/^M /)
      expect(arc.value).toContain(' A ')
    })

    it('returns a valid SVG path for score 100', () => {
      const score = ref(100)
      const { arc } = useRiskGauge(score)

      expect(arc.value).toMatch(/^M /)
      expect(arc.value).toContain(' A ')
    })

    it('arc path contains radius value', () => {
      const score = ref(50)
      const { arc } = useRiskGauge(score, 40)

      // The arc command "A rx ry ..." should contain the radius
      expect(arc.value).toContain('A 40 40')
    })

    it('arc path uses custom radius', () => {
      const score = ref(50)
      const { arc } = useRiskGauge(score, 30)

      expect(arc.value).toContain('A 30 30')
    })

    it('arc for score 50 uses largeArc=0 (angle=135 < 180)', () => {
      const score = ref(50)
      const { arc } = useRiskGauge(score)

      // 50/100 * 270 = 135 degrees, which is < 180 => largeArc = 0
      // Format: A rx ry x-rotation largeArc sweep x2 y2
      expect(arc.value).toMatch(/A \d+ \d+ 0 0 1/)
    })

    it('arc for score 70 uses largeArc=0 (angle=189 > 180)', () => {
      const score = ref(70)
      const { arc } = useRiskGauge(score)

      // 70/100 * 270 = 189 degrees, which is > 180 => largeArc = 1
      expect(arc.value).toMatch(/A \d+ \d+ 0 1 1/)
    })

    it('arc for score 100 uses largeArc=1 (angle=270 > 180)', () => {
      const score = ref(100)
      const { arc } = useRiskGauge(score)

      // 100/100 * 270 = 270 degrees, which is > 180 => largeArc = 1
      expect(arc.value).toMatch(/A \d+ \d+ 0 1 1/)
    })

    it('higher score produces longer arc (different endpoint)', () => {
      const score25 = ref(25)
      const score75 = ref(75)
      const { arc: arc25 } = useRiskGauge(score25)
      const { arc: arc75 } = useRiskGauge(score75)

      // They should be different arcs
      expect(arc25.value).not.toBe(arc75.value)
    })
  })

  // ---------- Clamping ----------

  describe('clamping', () => {
    it('clamps negative score to 0', () => {
      const score = ref(-10)
      const { clampedScore, arc } = useRiskGauge(score)

      expect(clampedScore.value).toBe(0)
      expect(arc.value).toBe('')
    })

    it('clamps score > 100 to 100', () => {
      const score = ref(150)
      const { clampedScore } = useRiskGauge(score)

      expect(clampedScore.value).toBe(100)
    })

    it('score exactly 0 is not clamped', () => {
      const score = ref(0)
      const { clampedScore } = useRiskGauge(score)

      expect(clampedScore.value).toBe(0)
    })

    it('score exactly 100 is not clamped', () => {
      const score = ref(100)
      const { clampedScore } = useRiskGauge(score)

      expect(clampedScore.value).toBe(100)
    })
  })

  // ---------- Grade ----------

  describe('grade', () => {
    it('returns grade A for score 0', () => {
      const score = ref(0)
      const { grade } = useRiskGauge(score)

      expect(grade.value.letter).toBe('A')
    })

    it('returns grade A for score 20', () => {
      const score = ref(20)
      const { grade } = useRiskGauge(score)

      expect(grade.value.letter).toBe('A')
    })

    it('returns grade B for score 21', () => {
      const score = ref(21)
      const { grade } = useRiskGauge(score)

      expect(grade.value.letter).toBe('B')
    })

    it('returns grade C for score 50', () => {
      const score = ref(50)
      const { grade } = useRiskGauge(score)

      expect(grade.value.letter).toBe('C')
    })

    it('returns grade D for score 75', () => {
      const score = ref(75)
      const { grade } = useRiskGauge(score)

      expect(grade.value.letter).toBe('D')
    })

    it('returns grade F for score 100', () => {
      const score = ref(100)
      const { grade } = useRiskGauge(score)

      expect(grade.value.letter).toBe('F')
    })

    it('grade has a valid hex color', () => {
      const score = ref(50)
      const { grade } = useRiskGauge(score)

      expect(grade.value.color).toMatch(/^#[0-9a-fA-F]{6}$/)
    })
  })

  // ---------- Classes ----------

  describe('classes', () => {
    it('returns bg, text, ring, fill for low score', () => {
      const score = ref(10)
      const { classes } = useRiskGauge(score)

      expect(classes.value).toHaveProperty('bg')
      expect(classes.value).toHaveProperty('text')
      expect(classes.value).toHaveProperty('ring')
      expect(classes.value).toHaveProperty('fill')
    })

    it('returns green classes for score < 20', () => {
      const score = ref(10)
      const { classes } = useRiskGauge(score)

      expect(classes.value.bg).toContain('green')
    })

    it('returns red classes for score >= 80', () => {
      const score = ref(90)
      const { classes } = useRiskGauge(score)

      expect(classes.value.bg).toContain('red')
    })

    it('fill is a valid hex color', () => {
      const score = ref(50)
      const { classes } = useRiskGauge(score)

      expect(classes.value.fill).toMatch(/^#[0-9a-fA-F]{6}$/)
    })
  })

  // ---------- Reactivity ----------

  describe('reactivity', () => {
    it('recomputes arc when score changes', () => {
      const score = ref(0)
      const { arc } = useRiskGauge(score)

      expect(arc.value).toBe('')

      score.value = 50
      expect(arc.value).toMatch(/^M /)
    })

    it('recomputes grade when score changes', () => {
      const score = ref(10)
      const { grade } = useRiskGauge(score)

      expect(grade.value.letter).toBe('A')

      score.value = 90
      expect(grade.value.letter).toBe('F')
    })

    it('recomputes clampedScore when score goes out of bounds', () => {
      const score = ref(50)
      const { clampedScore } = useRiskGauge(score)

      expect(clampedScore.value).toBe(50)

      score.value = 200
      expect(clampedScore.value).toBe(100)

      score.value = -50
      expect(clampedScore.value).toBe(0)
    })
  })
})
