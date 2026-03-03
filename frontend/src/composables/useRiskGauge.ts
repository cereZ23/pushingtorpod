/**
 * Shared SVG risk gauge arc computation.
 *
 * Replaces duplicated arc math between DashboardView and AssetDetailView.
 */
import { computed, type Ref } from 'vue'
import { getRiskGrade, getRiskScoreClasses } from '@/utils/severity'

/**
 * Composable for rendering a risk score gauge as an SVG arc.
 *
 * @param score - reactive ref with the risk score (0-100)
 * @param radius - circle radius (default 40)
 */
export function useRiskGauge(score: Ref<number>, radius = 40) {
  const clampedScore = computed(() => Math.min(100, Math.max(0, score.value)))

  const arc = computed(() => {
    const s = clampedScore.value
    if (s === 0) return ''

    const angle = (s / 100) * 270  // 270-degree arc
    const startAngle = 135           // bottom-left start
    const endAngle = startAngle + angle
    const r = radius
    const cx = 50
    const cy = 50
    const startRad = (startAngle * Math.PI) / 180
    const endRad = (endAngle * Math.PI) / 180
    const x1 = cx + r * Math.cos(startRad)
    const y1 = cy + r * Math.sin(startRad)
    const x2 = cx + r * Math.cos(endRad)
    const y2 = cy + r * Math.sin(endRad)
    const largeArc = angle > 180 ? 1 : 0
    return `M ${x1} ${y1} A ${r} ${r} 0 ${largeArc} 1 ${x2} ${y2}`
  })

  const grade = computed(() => getRiskGrade(clampedScore.value))
  const classes = computed(() => getRiskScoreClasses(clampedScore.value))

  return {
    arc,
    grade,
    classes,
    clampedScore,
  }
}
