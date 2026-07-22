"""Tests for the weekly exposure digest composition."""

from datetime import datetime, timedelta, timezone

from app.models.database import Asset, AssetType, Finding, FindingSeverity, FindingStatus
from app.models.risk import RiskScore
from app.services.exposure_digest import build_digest, render_digest_html

NOW = datetime.now(timezone.utc)
OLD = NOW - timedelta(days=10)


def _seed(db, tenant_id):
    asset = Asset(tenant_id=tenant_id, identifier="new.example.com", type=AssetType.SUBDOMAIN, first_seen=NOW)
    old_asset = Asset(tenant_id=tenant_id, identifier="old.example.com", type=AssetType.SUBDOMAIN, first_seen=OLD)
    db.add_all([asset, old_asset])
    db.commit()
    db.refresh(asset)
    db.refresh(old_asset)

    # exposure went from 78 (10d ago) to 41 (now)
    db.add(RiskScore(tenant_id=tenant_id, scope_type="organization", score=78.0, grade="D", scored_at=OLD))
    db.add(RiskScore(tenant_id=tenant_id, scope_type="organization", score=41.0, grade="C", scored_at=NOW))

    # a new critical (this week), an old finding, one resolved this week
    db.add(
        Finding(
            asset_id=asset.id,
            name="New RCE",
            severity=FindingSeverity.CRITICAL,
            status=FindingStatus.OPEN,
            first_seen=NOW,
            last_seen=NOW,
            source="nuclei",
        )
    )
    db.add(
        Finding(
            asset_id=old_asset.id,
            name="Old issue",
            severity=FindingSeverity.LOW,
            status=FindingStatus.OPEN,
            first_seen=OLD,
            last_seen=OLD,
            source="nuclei",
        )
    )
    db.add(
        Finding(
            asset_id=asset.id,
            name="Fixed thing",
            severity=FindingSeverity.MEDIUM,
            status=FindingStatus.FIXED,
            first_seen=OLD,
            last_seen=NOW,
            source="nuclei",
        )
    )
    db.commit()


class TestBuildDigest:
    def test_composes_exposure_narrative(self, db_session, tenant):
        _seed(db_session, tenant.id)
        d = build_digest(db_session, tenant.id, days=7)

        assert d["score"] == 41.0
        assert d["score_delta"] == -37.0  # exposure went DOWN
        assert d["new_findings_total"] == 1  # only the new critical (old one excluded)
        assert d["new_dangerous"] == 1
        assert d["resolved_count"] == 1
        assert d["new_assets"] == 1
        assert d["has_noteworthy"] is True
        assert d["top_new"][0]["name"] == "New RCE"

    def test_empty_tenant_not_noteworthy(self, db_session, tenant):
        d = build_digest(db_session, tenant.id, days=7)
        assert d["new_findings_total"] == 0
        assert d["has_noteworthy"] is False


class TestRenderDigest:
    def test_html_mentions_decrease(self):
        html = render_digest_html(
            {
                "score": 41.0,
                "score_delta": -37.0,
                "grade": "C",
                "days": 7,
                "new_findings_total": 1,
                "new_dangerous": 1,
                "resolved_count": 1,
                "new_assets": 1,
                "top_new": [{"name": "New RCE", "severity": "critical", "cve_id": None}],
            },
            "IFO",
        )
        assert "decreased" in html
        assert "New RCE" in html
        assert "IFO" in html
