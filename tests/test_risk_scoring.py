"""
Tests for the risk scoring engine (app/services/risk_scoring.py).

Covers:
- Finding-level scoring (CVSS, severity fallback, EPSS, KEV)
- Asset-level scoring (highest finding + modifiers)
- recalculate_asset_risk and recalculate_tenant_risk top-level functions
- Edge cases (no findings, no CVSS, missing data)
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest

from app.models.database import (
    Asset,
    AssetType,
    Finding,
    FindingSeverity,
    FindingStatus,
    Service,
    Tenant,
)
from app.services.risk_scoring import (
    EXPIRED_CERT_BONUS,
    INTERNET_EXPOSED_BONUS,
    KEV_BONUS,
    NEW_ASSET_BONUS,
    SEVERITY_FALLBACK_SCORE,
    RiskScoringEngine,
    _get_risk_level,
    _is_asset_new,
    _normalize_severity,
    compute_finding_score,
    recalculate_asset_risk,
    recalculate_tenant_risk,
    batch_calculate_risk_scores,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_finding(
    asset_id: int = 1,
    severity: FindingSeverity = FindingSeverity.HIGH,
    cvss: float | None = None,
    cve_id: str | None = None,
    evidence: dict | None = None,
    status: FindingStatus = FindingStatus.OPEN,
) -> Finding:
    """Build a Finding ORM object without touching the DB."""
    f = Finding(
        asset_id=asset_id,
        name="Test Finding",
        severity=severity,
        cvss_score=cvss,
        cve_id=cve_id,
        evidence=evidence,
        status=status,
        source="nuclei",
        template_id="test-template",
    )
    return f


# ---------------------------------------------------------------------------
# compute_finding_score unit tests
# ---------------------------------------------------------------------------


class TestComputeFindingScore:
    """Unit tests for the pure finding-level scoring function."""

    def test_cvss_only(self):
        """CVSS 7.5 -> base score 75.0, no EPSS/KEV -> 75.0."""
        f = _make_finding(cvss=7.5)
        assert compute_finding_score(f) == 75.0

    def test_cvss_max(self):
        """CVSS 10.0 -> base 100 -> capped at 100."""
        f = _make_finding(cvss=10.0)
        assert compute_finding_score(f) == 100.0

    def test_cvss_zero_uses_fallback(self):
        """CVSS 0.0 should use severity fallback."""
        f = _make_finding(severity=FindingSeverity.MEDIUM, cvss=0.0)
        assert compute_finding_score(f) == SEVERITY_FALLBACK_SCORE['medium']

    def test_no_cvss_uses_severity_fallback(self):
        """No CVSS -> severity fallback score."""
        f = _make_finding(severity=FindingSeverity.CRITICAL, cvss=None)
        assert compute_finding_score(f) == SEVERITY_FALLBACK_SCORE['critical']

    def test_severity_fallback_low(self):
        f = _make_finding(severity=FindingSeverity.LOW, cvss=None)
        assert compute_finding_score(f) == SEVERITY_FALLBACK_SCORE['low']

    def test_severity_fallback_info(self):
        f = _make_finding(severity=FindingSeverity.INFO, cvss=None)
        assert compute_finding_score(f) == SEVERITY_FALLBACK_SCORE['info']

    def test_epss_above_50_percent(self):
        """EPSS > 0.5 -> +15 bonus."""
        f = _make_finding(cvss=5.0)
        score = compute_finding_score(f, epss_score=0.6)
        assert score == 50.0 + 15.0  # 65.0

    def test_epss_above_10_percent(self):
        """EPSS > 0.1 but <= 0.5 -> +10 bonus."""
        f = _make_finding(cvss=5.0)
        score = compute_finding_score(f, epss_score=0.2)
        assert score == 50.0 + 10.0  # 60.0

    def test_epss_above_1_percent(self):
        """EPSS > 0.01 but <= 0.1 -> +5 bonus."""
        f = _make_finding(cvss=5.0)
        score = compute_finding_score(f, epss_score=0.05)
        assert score == 50.0 + 5.0  # 55.0

    def test_epss_below_1_percent(self):
        """EPSS <= 0.01 -> no bonus."""
        f = _make_finding(cvss=5.0)
        score = compute_finding_score(f, epss_score=0.005)
        assert score == 50.0

    def test_kev_bonus(self):
        """KEV flag -> +20 bonus."""
        f = _make_finding(cvss=5.0)
        score = compute_finding_score(f, is_kev=True)
        assert score == 50.0 + KEV_BONUS  # 70.0

    def test_epss_plus_kev(self):
        """Both EPSS > 0.5 and KEV should stack."""
        f = _make_finding(cvss=6.0)
        score = compute_finding_score(f, epss_score=0.7, is_kev=True)
        # base 60 + 15 EPSS + 20 KEV = 95
        assert score == 95.0

    def test_cap_at_100(self):
        """Score should never exceed 100."""
        f = _make_finding(cvss=9.0)  # base 90
        score = compute_finding_score(f, epss_score=0.8, is_kev=True)
        # 90 + 15 + 20 = 125 -> capped at 100
        assert score == 100.0

    def test_no_severity_defaults_to_info(self):
        """Finding with None severity defaults to info fallback."""
        f = _make_finding(severity=FindingSeverity.INFO, cvss=None)
        assert compute_finding_score(f) == 5.0


# ---------------------------------------------------------------------------
# _normalize_severity
# ---------------------------------------------------------------------------


class TestNormalizeSeverity:
    def test_enum_value(self):
        assert _normalize_severity(FindingSeverity.HIGH) == 'high'

    def test_string_value(self):
        assert _normalize_severity('CRITICAL') == 'critical'

    def test_none_returns_info(self):
        assert _normalize_severity(None) == 'info'


# ---------------------------------------------------------------------------
# _get_risk_level
# ---------------------------------------------------------------------------


class TestGetRiskLevel:
    def test_critical(self):
        assert _get_risk_level(85.0) == 'critical'

    def test_high(self):
        assert _get_risk_level(55.0) == 'high'

    def test_medium(self):
        assert _get_risk_level(30.0) == 'medium'

    def test_low(self):
        assert _get_risk_level(10.0) == 'low'

    def test_boundary_71(self):
        assert _get_risk_level(71.0) == 'critical'

    def test_boundary_41(self):
        assert _get_risk_level(41.0) == 'high'

    def test_boundary_21(self):
        assert _get_risk_level(21.0) == 'medium'

    def test_zero(self):
        assert _get_risk_level(0.0) == 'low'


# ---------------------------------------------------------------------------
# _is_asset_new
# ---------------------------------------------------------------------------


class TestIsAssetNew:
    def test_new_asset(self):
        asset = Asset(first_seen=datetime.now(timezone.utc) - timedelta(days=3))
        assert _is_asset_new(asset) is True

    def test_old_asset(self):
        asset = Asset(first_seen=datetime.now(timezone.utc) - timedelta(days=30))
        assert _is_asset_new(asset) is False

    def test_exactly_7_days(self):
        asset = Asset(first_seen=datetime.now(timezone.utc) - timedelta(days=7))
        assert _is_asset_new(asset) is True

    def test_no_first_seen(self):
        asset = Asset(first_seen=None)
        assert _is_asset_new(asset) is False

    def test_naive_datetime(self):
        """Naive datetime (no tzinfo) should still work."""
        asset = Asset(first_seen=datetime.utcnow() - timedelta(days=2))
        assert _is_asset_new(asset) is True


# ---------------------------------------------------------------------------
# RiskScoringEngine.calculate_asset_risk (integration-style with DB)
# ---------------------------------------------------------------------------


class TestCalculateAssetRisk:
    """Tests that exercise the engine with a real DB session."""

    def test_asset_not_found(self, db_session):
        engine = RiskScoringEngine(db_session)
        result = engine.calculate_asset_risk(999999)
        assert result['risk_score'] == 0.0
        assert result['error'] == 'asset_not_found'

    def test_asset_no_findings_score_zero(self, db_session, tenant):
        """Asset with no findings and no modifiers -> score 0."""
        asset = Asset(
            tenant_id=tenant.id,
            identifier="clean.example.com",
            type=AssetType.SUBDOMAIN,
            is_active=True,
            first_seen=datetime.now(timezone.utc) - timedelta(days=30),
        )
        db_session.add(asset)
        db_session.flush()

        engine = RiskScoringEngine(db_session)
        result = engine.calculate_asset_risk(asset.id)

        assert result['risk_score'] == 0.0
        assert result['risk_level'] == 'low'
        assert result['components']['max_finding_score'] == 0.0

    def test_asset_with_critical_finding(self, db_session, tenant):
        """Asset with a critical CVSS 9.8 finding -> high base score."""
        asset = Asset(
            tenant_id=tenant.id,
            identifier="vuln.example.com",
            type=AssetType.SUBDOMAIN,
            is_active=True,
            first_seen=datetime.now(timezone.utc) - timedelta(days=30),
        )
        db_session.add(asset)
        db_session.flush()

        finding = Finding(
            asset_id=asset.id,
            name="CVE-2024-9999",
            severity=FindingSeverity.CRITICAL,
            cvss_score=9.8,
            cve_id="CVE-2024-9999",
            status=FindingStatus.OPEN,
            source="nuclei",
        )
        db_session.add(finding)
        db_session.flush()

        engine = RiskScoringEngine(db_session)
        result = engine.calculate_asset_risk(asset.id)

        # Base: 9.8 * 10 = 98.0, no EPSS/KEV
        assert result['risk_score'] == 98.0
        assert result['risk_level'] == 'critical'
        assert result['components']['max_finding_score'] == 98.0

    def test_highest_finding_wins(self, db_session, tenant):
        """Asset-level score should be driven by the highest finding score."""
        asset = Asset(
            tenant_id=tenant.id,
            identifier="multi.example.com",
            type=AssetType.SUBDOMAIN,
            is_active=True,
            first_seen=datetime.now(timezone.utc) - timedelta(days=30),
        )
        db_session.add(asset)
        db_session.flush()

        # Low finding (CVSS 3.0 -> score 30)
        db_session.add(Finding(
            asset_id=asset.id, name="Low vuln",
            severity=FindingSeverity.LOW, cvss_score=3.0,
            status=FindingStatus.OPEN, source="nuclei",
        ))
        # High finding (CVSS 7.5 -> score 75)
        db_session.add(Finding(
            asset_id=asset.id, name="High vuln",
            severity=FindingSeverity.HIGH, cvss_score=7.5,
            status=FindingStatus.OPEN, source="nuclei",
        ))
        db_session.flush()

        engine = RiskScoringEngine(db_session)
        result = engine.calculate_asset_risk(asset.id)

        assert result['components']['max_finding_score'] == 75.0
        assert result['risk_score'] == 75.0

    def test_suppressed_findings_excluded(self, db_session, tenant):
        """Suppressed/fixed findings should NOT count."""
        asset = Asset(
            tenant_id=tenant.id,
            identifier="suppressed.example.com",
            type=AssetType.SUBDOMAIN,
            is_active=True,
            first_seen=datetime.now(timezone.utc) - timedelta(days=30),
        )
        db_session.add(asset)
        db_session.flush()

        # Suppressed critical
        db_session.add(Finding(
            asset_id=asset.id, name="Suppressed",
            severity=FindingSeverity.CRITICAL, cvss_score=9.0,
            status=FindingStatus.SUPPRESSED, source="nuclei",
        ))
        # Fixed high
        db_session.add(Finding(
            asset_id=asset.id, name="Fixed",
            severity=FindingSeverity.HIGH, cvss_score=7.0,
            status=FindingStatus.FIXED, source="nuclei",
        ))
        db_session.flush()

        engine = RiskScoringEngine(db_session)
        result = engine.calculate_asset_risk(asset.id)

        assert result['risk_score'] == 0.0
        assert result['components']['finding_count'] == 0

    def test_internet_exposed_bonus(self, db_session, tenant):
        """Port 443 service adds internet-exposed bonus."""
        asset = Asset(
            tenant_id=tenant.id,
            identifier="web.example.com",
            type=AssetType.SUBDOMAIN,
            is_active=True,
            first_seen=datetime.now(timezone.utc) - timedelta(days=30),
        )
        db_session.add(asset)
        db_session.flush()

        # HTTPS service on port 443
        db_session.add(Service(
            asset_id=asset.id, port=443, protocol="https", has_tls=True,
        ))
        # One medium finding (CVSS 5.0 -> score 50)
        db_session.add(Finding(
            asset_id=asset.id, name="Medium vuln",
            severity=FindingSeverity.MEDIUM, cvss_score=5.0,
            status=FindingStatus.OPEN, source="nuclei",
        ))
        db_session.flush()

        engine = RiskScoringEngine(db_session)
        result = engine.calculate_asset_risk(asset.id)

        # 50 (finding) + 5 (internet exposed) = 55
        assert result['risk_score'] == 55.0
        assert result['components']['internet_exposed_bonus'] == INTERNET_EXPOSED_BONUS

    def test_new_asset_bonus(self, db_session, tenant):
        """New asset (first_seen < 7 days) adds bonus."""
        asset = Asset(
            tenant_id=tenant.id,
            identifier="new.example.com",
            type=AssetType.SUBDOMAIN,
            is_active=True,
            first_seen=datetime.now(timezone.utc) - timedelta(days=2),
        )
        db_session.add(asset)
        db_session.flush()

        # Low finding (severity fallback: low = 20)
        db_session.add(Finding(
            asset_id=asset.id, name="Low vuln",
            severity=FindingSeverity.LOW, cvss_score=None,
            status=FindingStatus.OPEN, source="nuclei",
        ))
        db_session.flush()

        engine = RiskScoringEngine(db_session)
        result = engine.calculate_asset_risk(asset.id)

        # 20 (finding) + 10 (new asset) = 30
        assert result['risk_score'] == 30.0
        assert result['components']['new_asset_bonus'] == NEW_ASSET_BONUS

    def test_finding_with_cached_threat_intel(self, db_session, tenant):
        """Finding with cached EPSS/KEV in evidence field."""
        asset = Asset(
            tenant_id=tenant.id,
            identifier="kev.example.com",
            type=AssetType.SUBDOMAIN,
            is_active=True,
            first_seen=datetime.now(timezone.utc) - timedelta(days=30),
        )
        db_session.add(asset)
        db_session.flush()

        finding = Finding(
            asset_id=asset.id,
            name="CVE-2024-1234",
            severity=FindingSeverity.HIGH,
            cvss_score=7.0,
            cve_id="CVE-2024-1234",
            status=FindingStatus.OPEN,
            source="nuclei",
            evidence={
                "threat_intel": {
                    "epss_score": 0.8,
                    "is_kev": True,
                }
            },
        )
        db_session.add(finding)
        db_session.flush()

        engine = RiskScoringEngine(db_session)
        result = engine.calculate_asset_risk(asset.id)

        # CVSS 7.0 * 10 = 70, EPSS > 0.5 -> +15, KEV -> +20 = 105 -> capped 100
        assert result['risk_score'] == 100.0
        assert result['components']['threat_intel']['kev_count'] == 1
        assert result['components']['threat_intel']['high_epss_count'] == 1

    def test_combined_modifiers_cap_at_100(self, db_session, tenant):
        """All bonuses combined should not exceed 100."""
        asset = Asset(
            tenant_id=tenant.id,
            identifier="maxed.example.com",
            type=AssetType.SUBDOMAIN,
            is_active=True,
            first_seen=datetime.now(timezone.utc) - timedelta(days=1),
        )
        db_session.add(asset)
        db_session.flush()

        db_session.add(Service(
            asset_id=asset.id, port=443, protocol="https", has_tls=True,
        ))
        db_session.add(Finding(
            asset_id=asset.id, name="Critical",
            severity=FindingSeverity.CRITICAL, cvss_score=9.5,
            cve_id="CVE-2024-0001", status=FindingStatus.OPEN,
            source="nuclei",
            evidence={"threat_intel": {"epss_score": 0.9, "is_kev": True}},
        ))
        db_session.flush()

        engine = RiskScoringEngine(db_session)
        result = engine.calculate_asset_risk(asset.id)

        # 95 + 15 + 20 = 130 (capped to 100 at finding level)
        # Then +5 internet + 10 new = 115 -> capped at 100
        assert result['risk_score'] == 100.0


# ---------------------------------------------------------------------------
# recalculate_asset_risk (top-level function)
# ---------------------------------------------------------------------------


class TestRecalculateAssetRisk:

    def test_persists_score_to_asset(self, db_session, tenant):
        """recalculate_asset_risk should update Asset.risk_score in DB."""
        asset = Asset(
            tenant_id=tenant.id,
            identifier="persist.example.com",
            type=AssetType.SUBDOMAIN,
            is_active=True,
            risk_score=0.0,
            first_seen=datetime.now(timezone.utc) - timedelta(days=30),
        )
        db_session.add(asset)
        db_session.flush()

        db_session.add(Finding(
            asset_id=asset.id, name="Medium",
            severity=FindingSeverity.MEDIUM, cvss_score=5.0,
            status=FindingStatus.OPEN, source="nuclei",
        ))
        db_session.flush()

        result = recalculate_asset_risk(asset.id, db_session)

        assert result['risk_score'] == 50.0
        # Verify persisted to Asset row
        db_session.refresh(asset)
        assert asset.risk_score == 50.0

    def test_nonexistent_asset_returns_error(self, db_session):
        result = recalculate_asset_risk(999999, db_session)
        assert result['risk_score'] == 0.0
        assert 'error' in result


# ---------------------------------------------------------------------------
# recalculate_tenant_risk (batch function)
# ---------------------------------------------------------------------------


class TestRecalculateTenantRisk:

    def test_empty_tenant(self, db_session, tenant):
        """Tenant with no assets should return zero counts."""
        result = recalculate_tenant_risk(tenant.id, db_session)
        assert result['total_assets'] == 0
        assert result['updated'] == 0
        assert result['average_risk_score'] == 0.0

    def test_multiple_assets_scored(self, db_session, tenant):
        """All active assets in the tenant should be scored."""
        for i in range(3):
            asset = Asset(
                tenant_id=tenant.id,
                identifier=f"asset{i}.example.com",
                type=AssetType.SUBDOMAIN,
                is_active=True,
                risk_score=0.0,
                first_seen=datetime.now(timezone.utc) - timedelta(days=30),
            )
            db_session.add(asset)
            db_session.flush()

            db_session.add(Finding(
                asset_id=asset.id,
                name=f"Vuln {i}",
                severity=FindingSeverity.MEDIUM,
                cvss_score=4.0 + i,  # 4.0, 5.0, 6.0
                status=FindingStatus.OPEN,
                source="nuclei",
            ))

        db_session.flush()

        result = recalculate_tenant_risk(tenant.id, db_session)

        assert result['total_assets'] == 3
        assert result['updated'] == 3
        assert result['failed'] == 0
        assert result['average_risk_score'] > 0
        assert result['max_risk_score'] == 60.0  # 6.0 * 10

    def test_inactive_assets_excluded(self, db_session, tenant):
        """Inactive assets should NOT be processed."""
        active = Asset(
            tenant_id=tenant.id,
            identifier="active.example.com",
            type=AssetType.SUBDOMAIN,
            is_active=True,
            first_seen=datetime.now(timezone.utc) - timedelta(days=30),
        )
        inactive = Asset(
            tenant_id=tenant.id,
            identifier="inactive.example.com",
            type=AssetType.SUBDOMAIN,
            is_active=False,
            first_seen=datetime.now(timezone.utc) - timedelta(days=30),
        )
        db_session.add_all([active, inactive])
        db_session.flush()

        result = recalculate_tenant_risk(tenant.id, db_session)

        assert result['total_assets'] == 1
        assert result['updated'] == 1

    def test_score_distribution(self, db_session, tenant):
        """Score distribution in return value should match scored assets."""
        asset = Asset(
            tenant_id=tenant.id,
            identifier="distro.example.com",
            type=AssetType.SUBDOMAIN,
            is_active=True,
            first_seen=datetime.now(timezone.utc) - timedelta(days=30),
        )
        db_session.add(asset)
        db_session.flush()

        db_session.add(Finding(
            asset_id=asset.id, name="High",
            severity=FindingSeverity.HIGH, cvss_score=8.0,
            status=FindingStatus.OPEN, source="nuclei",
        ))
        db_session.flush()

        result = recalculate_tenant_risk(tenant.id, db_session)

        # 80 -> critical
        assert result['score_distribution']['critical'] == 1


# ---------------------------------------------------------------------------
# batch_calculate_risk_scores backward compatibility
# ---------------------------------------------------------------------------


class TestBatchCalculateRiskScores:

    def test_backward_compatible_return_shape(self, db_session, tenant):
        """Legacy callers expect tenant_id, total_assets, processed, updated."""
        result = batch_calculate_risk_scores(db_session, tenant.id)
        assert 'tenant_id' in result
        assert 'total_assets' in result
        assert 'processed' in result
        assert 'updated' in result


# ---------------------------------------------------------------------------
# Tenant scorecard
# ---------------------------------------------------------------------------


class TestTenantScorecard:

    def test_empty_tenant(self, db_session, tenant):
        engine = RiskScoringEngine(db_session)
        result = engine.calculate_tenant_risk_scorecard(tenant.id)
        assert result['total_assets'] == 0
        assert result['average_risk_score'] == 0.0

    def test_scorecard_aggregation(self, db_session, tenant):
        """Scorecard should reflect persisted asset risk_scores."""
        for i, score in enumerate([20.0, 50.0, 80.0]):
            asset = Asset(
                tenant_id=tenant.id,
                identifier=f"sc{i}.example.com",
                type=AssetType.SUBDOMAIN,
                is_active=True,
                risk_score=score,
            )
            db_session.add(asset)

        db_session.flush()

        engine = RiskScoringEngine(db_session)
        result = engine.calculate_tenant_risk_scorecard(tenant.id)

        assert result['total_assets'] == 3
        assert result['average_risk_score'] == 50.0
        assert result['risk_distribution']['critical'] == 1  # 80
        assert result['risk_distribution']['high'] == 1      # 50
        assert result['risk_distribution']['low'] == 1       # 20
        assert len(result['high_risk_assets']) == 1
        assert result['high_risk_assets'][0]['risk_score'] == 80.0
