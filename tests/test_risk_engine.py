"""Tests for the explainable risk engine (app/services/risk_engine.py).

Covers pure computation functions — no DB, no external deps.
"""

from __future__ import annotations

import pytest

from app.services.risk_engine import (
    AssetScoreInput,
    AssetScoreResult,
    CRITICALITY_WEIGHTS,
    GRADE_THRESHOLDS,
    IssueScoreInput,
    IssueScoreResult,
    OrgScoreResult,
    SEVERITY_BASES,
    compute_asset_score,
    compute_issue_score,
    compute_org_score,
    score_to_grade,
)


class TestScoreToGrade:
    @pytest.mark.parametrize(
        "score,expected",
        [
            (0, "A"),
            (10, "A"),
            (20, "A"),
            (21, "B"),
            (30, "B"),
            (40, "B"),
            (41, "C"),
            (55, "C"),
            (60, "C"),
            (61, "D"),
            (75, "D"),
            (80, "D"),
            (81, "F"),
            (95, "F"),
            (100, "F"),
        ],
    )
    def test_grade_boundaries(self, score, expected):
        assert score_to_grade(score) == expected

    def test_float_scores(self):
        assert score_to_grade(20.5) == "B"
        assert score_to_grade(60.9) == "D"

    def test_grade_thresholds_constant_present(self):
        # Sanity: ensure shared constant exists and has all 5 grades
        assert set(GRADE_THRESHOLDS.keys()) == {"A", "B", "C", "D", "F"}


class TestComputeIssueScore:
    def test_minimum_severity(self):
        input = IssueScoreInput(severity="info", confidence=1.0)
        result = compute_issue_score(input)
        assert isinstance(result, IssueScoreResult)
        assert result.score == SEVERITY_BASES["info"]

    def test_critical_severity_base(self):
        result = compute_issue_score(IssueScoreInput(severity="critical", confidence=1.0))
        assert result.score == SEVERITY_BASES["critical"]

    def test_unknown_severity_fallback(self):
        # Unknown severity defaults to 1 via .get(..., 1)
        result = compute_issue_score(IssueScoreInput(severity="unknown", confidence=1.0))
        assert result.score == 1

    def test_confidence_scales_score(self):
        full = compute_issue_score(IssueScoreInput(severity="high", confidence=1.0)).score
        half = compute_issue_score(IssueScoreInput(severity="high", confidence=0.5)).score
        assert half == pytest.approx(full * 0.5)

    def test_exposure_factor_scales_score(self):
        internet = compute_issue_score(IssueScoreInput(severity="high", confidence=1.0, exposure_factor=1.0)).score
        internal = compute_issue_score(IssueScoreInput(severity="high", confidence=1.0, exposure_factor=0.3)).score
        assert internet > internal

    def test_kev_boosts_score(self):
        no_kev = compute_issue_score(IssueScoreInput(severity="medium", confidence=1.0, is_kev=False)).score
        kev = compute_issue_score(IssueScoreInput(severity="medium", confidence=1.0, is_kev=True)).score
        assert kev > no_kev
        # Components reflect the boost
        kev_res = compute_issue_score(IssueScoreInput(severity="medium", confidence=1.0, is_kev=True))
        assert kev_res.components["kev_boost"] == 0.5

    def test_epss_boost_capped_at_0_3(self):
        big = compute_issue_score(IssueScoreInput(severity="medium", confidence=1.0, epss_score=0.9))
        assert big.components["epss_boost"] == 0.3

    def test_cdn_discount(self):
        no_cdn = compute_issue_score(IssueScoreInput(severity="high", confidence=1.0, is_cdn_fronted=False))
        cdn = compute_issue_score(IssueScoreInput(severity="high", confidence=1.0, is_cdn_fronted=True))
        assert cdn.score < no_cdn.score
        assert cdn.components["cdn_discount"] == 0.7
        assert no_cdn.components["cdn_discount"] == 1.0

    def test_mitigation_factor(self):
        no_mit = compute_issue_score(IssueScoreInput(severity="high", confidence=1.0, mitigation_factor=0.0)).score
        half_mit = compute_issue_score(IssueScoreInput(severity="high", confidence=1.0, mitigation_factor=0.5)).score
        assert half_mit == pytest.approx(no_mit * 0.5)

    def test_mitigation_capped_at_0_5(self):
        # mitigation > 0.5 is clamped to 0.5
        over = compute_issue_score(IssueScoreInput(severity="high", confidence=1.0, mitigation_factor=0.9)).score
        cap = compute_issue_score(IssueScoreInput(severity="high", confidence=1.0, mitigation_factor=0.5)).score
        assert over == cap

    def test_score_clamped_to_100(self):
        result = compute_issue_score(
            IssueScoreInput(severity="critical", confidence=1.0, exposure_factor=1.0, is_kev=True, epss_score=1.0)
        )
        assert result.score <= 100

    def test_components_fields(self):
        result = compute_issue_score(IssueScoreInput(severity="high", confidence=0.8))
        expected_keys = {
            "base_severity",
            "confidence",
            "exposure_factor",
            "kev_boost",
            "epss_boost",
            "cdn_discount",
            "mitigation_factor",
        }
        assert expected_keys.issubset(result.components.keys())


class TestComputeAssetScore:
    def test_empty_issues_returns_zero(self):
        result = compute_asset_score(AssetScoreInput(asset_id=1))
        assert result.score == 0
        assert result.grade == "A"
        assert result.top_drivers == []

    def test_single_issue_below_100(self):
        result = compute_asset_score(AssetScoreInput(asset_id=1, issue_scores=[50.0]))
        assert result.score > 0
        assert result.score <= 100
        assert result.components["issue_count"] == 1
        assert result.components["top_issue_score"] == 50

    def test_multiple_issues_sorted_descending(self):
        # With decay factor 0.85^i, higher issues are weighted more
        result = compute_asset_score(AssetScoreInput(asset_id=1, issue_scores=[10.0, 40.0, 20.0]))
        # Top issue should be the max
        assert result.components["top_issue_score"] == 40

    def test_criticality_multiplier(self):
        low_crit = compute_asset_score(AssetScoreInput(asset_id=1, criticality="low", issue_scores=[30.0]))
        critical = compute_asset_score(AssetScoreInput(asset_id=1, criticality="critical", issue_scores=[30.0]))
        assert critical.score > low_crit.score
        assert critical.components["criticality_weight"] == CRITICALITY_WEIGHTS["critical"]
        assert low_crit.components["criticality_weight"] == CRITICALITY_WEIGHTS["low"]

    def test_unknown_criticality_falls_to_standard(self):
        result = compute_asset_score(AssetScoreInput(asset_id=1, criticality="nonexistent", issue_scores=[30.0]))
        # Unknown maps to 1.0 via .get default
        assert result.components["criticality_weight"] == 1.0

    def test_score_clamped_to_100(self):
        many_high = [100.0] * 20
        result = compute_asset_score(AssetScoreInput(asset_id=1, issue_scores=many_high))
        assert result.score == 100

    def test_grade_is_set(self):
        result = compute_asset_score(AssetScoreInput(asset_id=1, issue_scores=[5.0]))
        assert result.grade in {"A", "B", "C", "D", "F"}


class TestComputeOrgScore:
    def test_empty_assets_returns_zero(self):
        result = compute_org_score([])
        assert isinstance(result, OrgScoreResult)
        assert result.score == 0
        assert result.grade == "A"
        assert result.delta is None

    def test_single_high_asset(self):
        # Small portfolio: 1 asset at 80 should yield a significant org score
        result = compute_org_score([80.0])
        assert result.score > 0

    def test_delta_computed_from_previous(self):
        result = compute_org_score([30.0, 30.0, 30.0], previous_score=20.0)
        assert result.previous_score == 20.0
        assert result.delta is not None

    def test_dampening_caps_increase(self):
        # A big jump (0 → expected large) is dampened to +/-15
        result = compute_org_score([50.0] * 5, previous_score=0.0)
        # With dampening, delta bounded to 15
        assert result.score <= 15.0 + 0.01

    def test_acute_event_bypasses_dampening(self):
        # Any asset > 60 is acute — dampening is skipped
        result = compute_org_score([85.0, 20.0, 20.0], previous_score=0.0)
        # Score may exceed 15 because acute_event=True
        assert result.score > 15.0

    def test_score_bounded_0_to_100(self):
        result = compute_org_score([100.0] * 50)
        assert 0 <= result.score <= 100

    def test_breadth_penalty_with_many_high_risk(self):
        # 40 assets all at 80 → many > 50 → breadth penalty adds up to 20
        many = [80.0] * 40
        result = compute_org_score(many)
        assert result.score > 0
        assert result.grade in {"D", "F"}

    def test_grade_matches_score(self):
        result = compute_org_score([85.0], previous_score=None)
        assert result.grade == score_to_grade(result.score)
