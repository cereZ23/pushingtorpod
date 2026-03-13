"""
Explainable Risk Scoring Engine

Three-level scoring:
- Issue Score (0-100): base_severity * confidence * exposure_factor * (1 + kev_boost + epss_boost)
- Asset Score (0-100): Weighted sum with geometric decay (0.85^index) * criticality_weight
- Organization Score (0-100): Top-weighted average (top 20 assets = 60%)

Grade Mapping: A(0-20), B(21-40), C(41-60), D(61-80), F(81-100)
"""

from dataclasses import dataclass, field
from typing import Optional

# Severity base scores
SEVERITY_BASES: dict[str, int] = {
    'critical': 40, 'high': 25, 'medium': 12, 'low': 5, 'info': 1
}

# Criticality weights
CRITICALITY_WEIGHTS: dict[str, float] = {
    'critical': 1.5, 'high': 1.2, 'standard': 1.0, 'low': 0.8
}


# Canonical grade thresholds — shared across:
#   - app/services/risk_engine.py (score_to_grade)
#   - app/services/risk_scoring.py (RiskScoringEngine docstring)
#   - app/api/routers/graph.py (_risk_to_criticality)
#   - frontend/src/utils/severity.ts (getRiskGrade, getRiskScoreClasses)
GRADE_THRESHOLDS = {
    'A': (0, 20),    # Minimal / Info
    'B': (21, 40),   # Low
    'C': (41, 60),   # Medium
    'D': (61, 80),   # High
    'F': (81, 100),  # Critical
}


def score_to_grade(score: float) -> str:
    """Map a numeric risk score (0-100) to a letter grade.

    Uses GRADE_THRESHOLDS — keep in sync with frontend severity.ts.
    """
    if score <= 20:
        return 'A'
    if score <= 40:
        return 'B'
    if score <= 60:
        return 'C'
    if score <= 80:
        return 'D'
    return 'F'


@dataclass
class IssueScoreInput:
    """Input parameters for computing a single issue risk score."""

    severity: str
    confidence: float
    exposure_factor: float = 1.0  # 1.0=internet no-auth, 0.6=auth, 0.3=internal
    is_kev: bool = False
    epss_score: float = 0.0
    is_cdn_fronted: bool = False
    mitigation_factor: float = 0.0  # 0.0-0.5


@dataclass
class IssueScoreResult:
    """Explainable result from issue score computation."""

    score: float
    components: dict


@dataclass
class AssetScoreInput:
    """Input parameters for computing an asset-level risk score."""

    asset_id: int
    criticality: str = 'standard'
    issue_scores: list[float] = field(default_factory=list)


@dataclass
class AssetScoreResult:
    """Explainable result from asset score computation."""

    score: float
    grade: str
    components: dict
    top_drivers: list[dict]


@dataclass
class OrgScoreResult:
    """Explainable result from organization score computation."""

    score: float
    grade: str
    top_drivers: list[dict]
    previous_score: Optional[float] = None
    delta: Optional[float] = None


def compute_issue_score(input: IssueScoreInput) -> IssueScoreResult:
    """Compute issue risk score with explainable components.

    The formula is::

        raw = base_severity * confidence * exposure_factor
              * (1 + kev_boost + epss_boost)
              * cdn_discount * (1 - mitigation_factor)

    Args:
        input: Parameters describing the issue characteristics.

    Returns:
        Scored result clamped to 0-100 with a breakdown of each component.
    """
    base = SEVERITY_BASES.get(input.severity, 1)

    kev_boost = 0.5 if input.is_kev else 0.0
    epss_boost = min(0.3, input.epss_score)

    raw = base * input.confidence * input.exposure_factor * (1 + kev_boost + epss_boost)

    # CDN discount
    if input.is_cdn_fronted:
        raw *= 0.7  # from settings.risk_cdn_discount

    # Mitigation factor
    raw *= (1 - min(input.mitigation_factor, 0.5))

    score = min(100, raw)

    return IssueScoreResult(
        score=round(score, 2),
        components={
            'base_severity': base,
            'confidence': input.confidence,
            'exposure_factor': input.exposure_factor,
            'kev_boost': kev_boost,
            'epss_boost': epss_boost,
            'cdn_discount': 0.7 if input.is_cdn_fronted else 1.0,
            'mitigation_factor': input.mitigation_factor,
        }
    )


def compute_asset_score(input: AssetScoreInput) -> AssetScoreResult:
    """Compute asset score from sorted issue scores with geometric decay.

    .. note:: This function is part of the explainable risk engine but is
       **not called in the production pipeline**.  The pipeline uses
       ``risk_scoring.recalculate_asset_risk`` instead.  Kept for the
       correlation engine and potential future use.

    Issues are sorted descending and weighted by ``0.85^index`` so the
    most severe issue dominates.  The weighted sum is then multiplied by
    the asset's criticality weight.

    Args:
        input: Asset identifier, criticality tier, and its issue scores.

    Returns:
        Scored result clamped to 0-100 with grade and component breakdown.
    """
    if not input.issue_scores:
        return AssetScoreResult(score=0, grade='A', components={}, top_drivers=[])

    sorted_scores = sorted(input.issue_scores, reverse=True)
    weighted_sum = sum(score * (0.85 ** i) for i, score in enumerate(sorted_scores))
    criticality_weight = CRITICALITY_WEIGHTS.get(input.criticality, 1.0)
    raw = weighted_sum * criticality_weight
    score = min(100, raw)

    return AssetScoreResult(
        score=round(score, 2),
        grade=score_to_grade(score),
        components={
            'issue_count': len(sorted_scores),
            'criticality': input.criticality,
            'criticality_weight': criticality_weight,
            'top_issue_score': sorted_scores[0] if sorted_scores else 0,
        },
        top_drivers=[]  # Filled by caller with issue descriptions
    )


def compute_org_score(
    asset_scores: list[float],
    previous_score: Optional[float] = None,
) -> OrgScoreResult:
    """Compute organization score from asset scores with dampening.

    Scoring strategy:
    - Top 20 assets contribute 60 % of the score (averaged).
    - A breadth penalty adds up to 20 points based on assets with score > 50.
    - Remaining (tail) assets contribute 20 % (averaged).
    - Score change is dampened to +/-15 points per computation cycle.

    Args:
        asset_scores: List of numeric asset risk scores.
        previous_score: Previous org score for dampening calculation.

    Returns:
        Scored result clamped to 0-100 with grade, delta, and driver info.
    """
    if not asset_scores:
        return OrgScoreResult(score=0, grade='A', top_drivers=[])

    sorted_scores = sorted(asset_scores, reverse=True)

    # Top 20 assets contribute 60%.  Scale the weight up for small portfolios
    # so that a single high-risk asset isn't understated (e.g. 1 asset at 80
    # should produce grade D, not C).
    top_20 = sorted_scores[:20]
    n = len(top_20)
    top_weight = min(1.0, 0.6 + 0.4 * (1 - n / 20)) if n < 20 else 0.6
    top_contribution = (sum(top_20) / n) * top_weight

    # Breadth penalty
    high_risk_count = sum(1 for s in sorted_scores if s > 50)
    breadth_penalty = min(20, high_risk_count * 0.5)

    # Tail contribution
    tail = sorted_scores[20:] if len(sorted_scores) > 20 else []
    tail_contribution = (sum(tail) / max(len(tail), 1)) * 0.2 if tail else 0

    raw = top_contribution + breadth_penalty + tail_contribution

    score = min(100, raw)

    # Dampening: cap change at +/-15 points per cycle for gradual drift.
    # Bypass dampening when any asset exceeds the D-grade threshold (score > 60)
    # so that acute events (new critical CVE, KEV) are reflected immediately.
    max_asset = sorted_scores[0] if sorted_scores else 0
    acute_event = max_asset > 60

    if previous_score is not None and not acute_event:
        delta = score - previous_score
        dampening = 15.0  # from settings.risk_score_dampening
        if abs(delta) > dampening:
            score = previous_score + (dampening if delta > 0 else -dampening)

    score = max(0, min(100, round(score, 2)))
    delta = round(score - previous_score, 2) if previous_score is not None else None

    return OrgScoreResult(
        score=score,
        grade=score_to_grade(score),
        top_drivers=[],
        previous_score=previous_score,
        delta=delta,
    )
