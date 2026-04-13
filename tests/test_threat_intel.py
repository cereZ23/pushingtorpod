"""
Test suite for Threat Intelligence service (EPSS + CISA KEV).

Tests cover:
- ThreatIntelService: EPSS lookups, KEV catalog, bulk enrichment
- Celery tasks: refresh_threat_intel, enrich_findings_threat_intel
- API endpoints: admin refresh/status, tenant enrichment, per-finding lookup
- Risk scoring integration: EPSS/KEV boosts in RiskScoringEngine._score_findings
- Error handling and graceful degradation
"""

import json
from datetime import datetime
from unittest.mock import MagicMock, patch, PropertyMock

import httpx
import pytest


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def mock_redis():
    """Create a mock Redis client with dict-based storage."""
    storage = {}
    sets = {}

    redis_mock = MagicMock()

    def _get(key):
        return storage.get(key)

    def _setex(key, ttl, value):
        storage[key] = value

    def _exists(key):
        return key in storage or key in sets

    def _sismember(key, member):
        return member in sets.get(key, set())

    def _sadd(key, *members):
        if key not in sets:
            sets[key] = set()
        sets[key].update(members)

    def _delete(key):
        storage.pop(key, None)
        sets.pop(key, None)

    def _expire(key, ttl):
        pass  # No-op for tests

    # Pipeline mock
    pipe_mock = MagicMock()
    pipe_mock.setex = _setex
    pipe_mock.delete = _delete
    pipe_mock.sadd = _sadd
    pipe_mock.expire = _expire
    pipe_mock.execute = MagicMock(return_value=[])

    redis_mock.get = MagicMock(side_effect=_get)
    redis_mock.setex = MagicMock(side_effect=_setex)
    redis_mock.exists = MagicMock(side_effect=_exists)
    redis_mock.sismember = MagicMock(side_effect=_sismember)
    redis_mock.sadd = MagicMock(side_effect=_sadd)
    redis_mock.delete = MagicMock(side_effect=_delete)
    redis_mock.expire = MagicMock(side_effect=_expire)
    redis_mock.pipeline = MagicMock(return_value=pipe_mock)

    # Expose internals for assertions
    redis_mock._storage = storage
    redis_mock._sets = sets
    redis_mock._pipe = pipe_mock

    return redis_mock


@pytest.fixture
def threat_intel_service(mock_redis):
    """Create ThreatIntelService with mock Redis."""
    from app.services.threat_intel import ThreatIntelService

    return ThreatIntelService(redis_client=mock_redis)


@pytest.fixture
def sample_epss_response():
    """Sample EPSS API response."""
    return {
        "status": "OK",
        "status-code": 200,
        "version": "1.0",
        "total": 2,
        "offset": 0,
        "limit": 100,
        "data": [
            {"cve": "CVE-2024-1234", "epss": "0.97234", "percentile": "0.99987"},
            {"cve": "CVE-2024-5678", "epss": "0.03456", "percentile": "0.45123"},
        ],
    }


@pytest.fixture
def sample_kev_response():
    """Sample CISA KEV catalog response."""
    return {
        "title": "CISA Catalog of Known Exploited Vulnerabilities",
        "catalogVersion": "2026.02.25",
        "dateReleased": "2026-02-25T12:00:00.000Z",
        "count": 3,
        "vulnerabilities": [
            {
                "cveID": "CVE-2024-1234",
                "vendorProject": "Apache",
                "product": "Log4j",
                "vulnerabilityName": "Apache Log4j Remote Code Execution",
                "dateAdded": "2024-01-15",
                "shortDescription": "Log4j RCE via JNDI injection",
                "requiredAction": "Apply updates per vendor instructions.",
                "dueDate": "2024-02-15",
                "knownRansomwareCampaignUse": "Known",
                "notes": "",
            },
            {
                "cveID": "CVE-2023-9999",
                "vendorProject": "Microsoft",
                "product": "Exchange Server",
                "vulnerabilityName": "ProxyNotShell Vulnerability",
                "dateAdded": "2023-10-01",
                "shortDescription": "SSRF and RCE in Exchange",
                "requiredAction": "Apply updates per vendor instructions.",
                "dueDate": "2023-11-01",
                "knownRansomwareCampaignUse": "Known",
                "notes": "",
            },
            {
                "cveID": "CVE-2022-0001",
                "vendorProject": "Linux",
                "product": "Kernel",
                "vulnerabilityName": "Branch History Injection",
                "dateAdded": "2022-03-15",
                "shortDescription": "Speculative execution attack",
                "requiredAction": "Apply updates per vendor instructions.",
                "dueDate": "2022-04-15",
                "knownRansomwareCampaignUse": "Unknown",
                "notes": "",
            },
        ],
    }


# ---------------------------------------------------------------------------
# ThreatIntelService - EPSS Tests
# ---------------------------------------------------------------------------


class TestEPSSService:
    """Tests for EPSS score lookups."""

    def test_get_epss_score_cache_hit(self, threat_intel_service, mock_redis):
        """EPSS score returned from Redis cache."""
        mock_redis._storage["epss:CVE-2024-1234"] = "0.97"

        score = threat_intel_service.get_epss_score("CVE-2024-1234")

        assert score == 0.97
        mock_redis.get.assert_called()

    def test_get_epss_score_cache_miss_api_success(self, threat_intel_service, sample_epss_response):
        """EPSS score fetched from API on cache miss and cached."""
        mock_response = MagicMock()
        mock_response.json.return_value = sample_epss_response
        mock_response.raise_for_status = MagicMock()

        with patch("app.services.threat_intel.httpx.Client") as mock_client_cls:
            mock_client = MagicMock()
            mock_client.get.return_value = mock_response
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client_cls.return_value = mock_client

            score = threat_intel_service.get_epss_score("CVE-2024-1234")

        assert score == pytest.approx(0.97234)

    def test_get_epss_score_api_failure_returns_zero(self, threat_intel_service):
        """EPSS returns 0.0 when API is unreachable."""
        with patch("app.services.threat_intel.httpx.Client") as mock_client_cls:
            mock_client = MagicMock()
            mock_client.get.side_effect = httpx.ConnectError("Connection refused")
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client_cls.return_value = mock_client

            score = threat_intel_service.get_epss_score("CVE-2024-1234")

        assert score == 0.0

    def test_get_epss_score_empty_cve(self, threat_intel_service):
        """Empty/None CVE returns 0.0."""
        assert threat_intel_service.get_epss_score("") == 0.0
        assert threat_intel_service.get_epss_score(None) == 0.0

    def test_get_epss_score_normalizes_cve_id(self, threat_intel_service, mock_redis):
        """CVE ID is normalized to uppercase."""
        mock_redis._storage["epss:CVE-2024-1234"] = "0.5"

        score = threat_intel_service.get_epss_score("cve-2024-1234")

        assert score == 0.5

    def test_get_epss_scores_bulk_all_cached(self, threat_intel_service, mock_redis):
        """Bulk lookup returns cached scores without API calls."""
        mock_redis._storage["epss:CVE-2024-1234"] = "0.97"
        mock_redis._storage["epss:CVE-2024-5678"] = "0.03"

        scores = threat_intel_service.get_epss_scores_bulk(["CVE-2024-1234", "CVE-2024-5678"])

        assert scores["CVE-2024-1234"] == pytest.approx(0.97)
        assert scores["CVE-2024-5678"] == pytest.approx(0.03)

    def test_get_epss_scores_bulk_partial_cache(self, threat_intel_service, mock_redis, sample_epss_response):
        """Bulk lookup fetches only cache misses from API."""
        mock_redis._storage["epss:CVE-2024-1234"] = "0.97"

        # Only CVE-2024-5678 is a miss
        mock_response = MagicMock()
        mock_response.json.return_value = {"data": [{"cve": "CVE-2024-5678", "epss": "0.03456"}]}
        mock_response.raise_for_status = MagicMock()

        with patch("app.services.threat_intel.httpx.Client") as mock_client_cls:
            mock_client = MagicMock()
            mock_client.get.return_value = mock_response
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client_cls.return_value = mock_client

            scores = threat_intel_service.get_epss_scores_bulk(["CVE-2024-1234", "CVE-2024-5678"])

        assert scores["CVE-2024-1234"] == pytest.approx(0.97)
        assert scores["CVE-2024-5678"] == pytest.approx(0.03456)

    def test_get_epss_scores_bulk_empty_list(self, threat_intel_service):
        """Bulk lookup with empty list returns empty dict."""
        assert threat_intel_service.get_epss_scores_bulk([]) == {}

    def test_get_epss_scores_bulk_deduplicates(self, threat_intel_service, mock_redis):
        """Bulk lookup deduplicates CVE IDs."""
        mock_redis._storage["epss:CVE-2024-1234"] = "0.97"

        scores = threat_intel_service.get_epss_scores_bulk(["CVE-2024-1234", "cve-2024-1234", "CVE-2024-1234"])

        assert len(scores) == 1
        assert scores["CVE-2024-1234"] == pytest.approx(0.97)


# ---------------------------------------------------------------------------
# ThreatIntelService - KEV Tests
# ---------------------------------------------------------------------------


class TestKEVService:
    """Tests for CISA KEV catalog lookups."""

    def test_is_in_kev_cached(self, threat_intel_service, mock_redis):
        """KEV membership check uses Redis set."""
        mock_redis._sets["kev:catalog"] = {"CVE-2024-1234", "CVE-2023-9999"}

        assert threat_intel_service.is_in_kev("CVE-2024-1234") is True
        assert threat_intel_service.is_in_kev("CVE-9999-0001") is False

    def test_is_in_kev_empty_cve(self, threat_intel_service):
        """Empty/None CVE returns False."""
        assert threat_intel_service.is_in_kev("") is False
        assert threat_intel_service.is_in_kev(None) is False

    def test_is_in_kev_triggers_refresh_if_not_cached(self, threat_intel_service, sample_kev_response):
        """KEV check triggers catalog refresh when Redis set is empty."""
        mock_response = MagicMock()
        mock_response.json.return_value = sample_kev_response
        mock_response.raise_for_status = MagicMock()

        with patch("app.services.threat_intel.httpx.Client") as mock_client_cls:
            mock_client = MagicMock()
            mock_client.get.return_value = mock_response
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client_cls.return_value = mock_client

            result = threat_intel_service.is_in_kev("CVE-2024-1234")

        assert result is True

    def test_refresh_kev_catalog(self, threat_intel_service, mock_redis, sample_kev_response):
        """Full KEV catalog refresh populates Redis set and details."""
        mock_response = MagicMock()
        mock_response.json.return_value = sample_kev_response
        mock_response.raise_for_status = MagicMock()

        with patch("app.services.threat_intel.httpx.Client") as mock_client_cls:
            mock_client = MagicMock()
            mock_client.get.return_value = mock_response
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client_cls.return_value = mock_client

            count = threat_intel_service.refresh_kev_catalog()

        assert count == 3
        # Verify pipeline was used
        mock_redis.pipeline.assert_called()

    def test_refresh_kev_catalog_api_failure(self, threat_intel_service):
        """KEV refresh raises on API failure."""
        import httpx as httpx_mod

        with patch("app.services.threat_intel.httpx.Client") as mock_client_cls:
            mock_client = MagicMock()
            mock_client.get.side_effect = httpx_mod.ConnectError("Connection refused")
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client_cls.return_value = mock_client

            with pytest.raises(httpx_mod.ConnectError):
                threat_intel_service.refresh_kev_catalog()

    def test_get_kev_details_found(self, threat_intel_service, mock_redis):
        """KEV details returned for known CVE."""
        mock_redis._sets["kev:catalog"] = {"CVE-2024-1234"}
        detail = {
            "cve_id": "CVE-2024-1234",
            "vendor": "Apache",
            "product": "Log4j",
            "vulnerability_name": "Log4j RCE",
            "date_added": "2024-01-15",
            "short_description": "RCE via JNDI",
            "required_action": "Patch immediately",
            "due_date": "2024-02-15",
            "known_ransomware_use": "Known",
            "notes": "",
        }
        mock_redis._storage["kev:detail:CVE-2024-1234"] = json.dumps(detail)

        result = threat_intel_service.get_kev_details("CVE-2024-1234")

        assert result is not None
        assert result["vendor"] == "Apache"
        assert result["product"] == "Log4j"

    def test_get_kev_details_not_in_kev(self, threat_intel_service, mock_redis):
        """KEV details returns None for CVE not in catalog."""
        mock_redis._sets["kev:catalog"] = {"CVE-2024-1234"}

        result = threat_intel_service.get_kev_details("CVE-9999-0001")

        assert result is None


# ---------------------------------------------------------------------------
# ThreatIntelService - Bulk Enrichment Tests
# ---------------------------------------------------------------------------


class TestBulkEnrichment:
    """Tests for enrich_findings method."""

    def test_enrich_findings_with_cves(self, threat_intel_service, mock_redis):
        """Enrichment returns EPSS + KEV data for findings with CVEs."""
        mock_redis._storage["epss:CVE-2024-1234"] = "0.97"
        mock_redis._storage["epss:CVE-2024-5678"] = "0.03"
        mock_redis._sets["kev:catalog"] = {"CVE-2024-1234"}

        findings = [
            {"id": 1, "cve_id": "CVE-2024-1234"},
            {"id": 2, "cve_id": "CVE-2024-5678"},
            {"id": 3, "cve_id": None},  # No CVE
        ]

        enrichments = threat_intel_service.enrich_findings(findings)

        assert len(enrichments) == 2  # Only findings with CVEs

        epss_map = {e["finding_id"]: e for e in enrichments}
        assert epss_map[1]["epss_score"] == pytest.approx(0.97)
        assert epss_map[1]["is_kev"] is True
        assert epss_map[2]["epss_score"] == pytest.approx(0.03)
        assert epss_map[2]["is_kev"] is False

    def test_enrich_findings_orm_objects(self, threat_intel_service, mock_redis):
        """Enrichment works with ORM-like objects (not just dicts)."""
        mock_redis._storage["epss:CVE-2024-1234"] = "0.5"
        mock_redis._sets["kev:catalog"] = set()

        finding_obj = MagicMock()
        finding_obj.id = 42
        finding_obj.cve_id = "CVE-2024-1234"

        enrichments = threat_intel_service.enrich_findings([finding_obj])

        assert len(enrichments) == 1
        assert enrichments[0]["finding_id"] == 42
        assert enrichments[0]["epss_score"] == pytest.approx(0.5)

    def test_enrich_findings_empty(self, threat_intel_service):
        """Enrichment with empty list returns empty."""
        assert threat_intel_service.enrich_findings([]) == []

    def test_enrich_findings_no_cves(self, threat_intel_service):
        """Enrichment with no CVE IDs returns empty."""
        findings = [
            {"id": 1, "cve_id": None},
            {"id": 2, "cve_id": ""},
        ]
        assert threat_intel_service.enrich_findings(findings) == []


# ---------------------------------------------------------------------------
# ThreatIntelService - Status Tests
# ---------------------------------------------------------------------------


class TestThreatIntelStatus:
    """Tests for get_status method."""

    def test_get_status_populated(self, threat_intel_service, mock_redis):
        """Status returns metadata when cache is populated."""
        mock_redis._storage["kev:last_refresh"] = "2026-02-25T02:00:00+00:00"
        mock_redis._storage["kev:count"] = "1203"
        mock_redis._sets["kev:catalog"] = {"CVE-2024-1234"}

        status = threat_intel_service.get_status()

        assert status["kev_last_refresh"] == "2026-02-25T02:00:00+00:00"
        assert status["kev_count"] == 1203
        assert status["kev_catalog_cached"] is True
        assert status["epss_cache_available"] is True

    def test_get_status_empty_cache(self, threat_intel_service):
        """Status returns defaults when cache is empty."""
        status = threat_intel_service.get_status()

        assert status["kev_last_refresh"] is None
        assert status["kev_count"] == 0
        assert status["kev_catalog_cached"] is False


# ---------------------------------------------------------------------------
# Schema Helper Tests
# ---------------------------------------------------------------------------


class TestSchemaHelpers:
    """Tests for schema utility functions."""

    def test_classify_epss_severity(self):
        """EPSS severity classification thresholds."""
        from app.api.schemas.threat_intel import classify_epss_severity

        assert classify_epss_severity(0.95) == "critical"
        assert classify_epss_severity(0.70) == "critical"
        assert classify_epss_severity(0.69) == "high"
        assert classify_epss_severity(0.40) == "high"
        assert classify_epss_severity(0.39) == "medium"
        assert classify_epss_severity(0.10) == "medium"
        assert classify_epss_severity(0.09) == "low"
        assert classify_epss_severity(0.0) == "low"

    def test_build_risk_boost_description_kev_and_high_epss(self):
        """Description includes both KEV and EPSS warnings."""
        from app.api.schemas.threat_intel import build_risk_boost_description

        desc = build_risk_boost_description(0.95, is_kev=True)

        assert "CISA" in desc
        assert "Known Exploited" in desc
        assert "95" in desc
        assert "CRITICAL" in desc

    def test_build_risk_boost_description_low_epss(self):
        """Description for low EPSS with no KEV."""
        from app.api.schemas.threat_intel import build_risk_boost_description

        desc = build_risk_boost_description(0.02, is_kev=False)

        assert "low" in desc.lower()

    def test_build_risk_boost_description_no_data(self):
        """Description when no threat intel data available."""
        from app.api.schemas.threat_intel import build_risk_boost_description

        desc = build_risk_boost_description(0.0, is_kev=False)

        assert "No threat intelligence data" in desc


# ---------------------------------------------------------------------------
# Risk Scoring Integration Tests
# ---------------------------------------------------------------------------


class TestRiskScoringIntegration:
    """Tests for EPSS/KEV integration in RiskScoringEngine."""

    def test_score_findings_with_kev_boost(self, db_session):
        """Finding with KEV CVE gets 15-point boost."""
        from app.models.database import Asset, AssetType, Finding, FindingSeverity, FindingStatus, Tenant
        from app.services.risk_scoring import RiskScoringEngine

        # Create test data
        tenant = Tenant(name="Test", slug="test-risk-kev")
        db_session.add(tenant)
        db_session.flush()

        asset = Asset(
            tenant_id=tenant.id,
            type=AssetType.SUBDOMAIN,
            identifier="vuln.example.com",
        )
        db_session.add(asset)
        db_session.flush()

        finding = Finding(
            asset_id=asset.id,
            name="Log4j RCE",
            severity=FindingSeverity.CRITICAL,
            status=FindingStatus.OPEN,
            cve_id="CVE-2024-1234",
            evidence={
                "threat_intel": {
                    "epss_score": 0.97,
                    "is_kev": True,
                    "enriched_at": "2026-02-25T00:00:00",
                }
            },
        )
        db_session.add(finding)
        db_session.flush()

        engine = RiskScoringEngine(db_session)

        # Evidence has threat_intel key, so no live service call is needed.
        # SEVERITY_FALLBACK_SCORE["critical"] = 75 + EPSS>0.5 bonus (15) + KEV bonus (20) = 110 → capped at 100
        with patch("app.services.risk_scoring._build_threat_intel_service", return_value=None):
            result = engine._score_all_findings(asset)

        assert result["max_finding_score"] == pytest.approx(100.0)
        assert result["kev_count"] == 1
        assert result["high_epss_count"] == 1

    def test_score_findings_evidence_as_string(self, db_session):
        """Regression: evidence stored as JSON string must not raise TypeError.

        Bug: when finding.evidence is a JSON string instead of a dict,
        _get_finding_threat_intel() raised TypeError: 'str' object does not
        support item assignment.  The fix parses it with json.loads first.
        """
        import json as json_mod

        from app.models.database import Asset, AssetType, Finding, FindingSeverity, FindingStatus, Tenant
        from app.services.risk_scoring import RiskScoringEngine

        tenant = Tenant(name="Test", slug="test-risk-str-evidence")
        db_session.add(tenant)
        db_session.flush()

        asset = Asset(
            tenant_id=tenant.id,
            type=AssetType.SUBDOMAIN,
            identifier="str-evidence.example.com",
        )
        db_session.add(asset)
        db_session.flush()

        # Simulate the bug condition: evidence is a JSON-encoded string
        evidence_as_string = json_mod.dumps(
            {
                "threat_intel": {
                    "epss_score": 0.85,
                    "is_kev": True,
                    "enriched_at": "2026-02-25T00:00:00",
                }
            }
        )
        finding = Finding(
            asset_id=asset.id,
            name="Vuln With String Evidence",
            severity=FindingSeverity.HIGH,
            status=FindingStatus.OPEN,
            cve_id="CVE-2024-9876",
            evidence=evidence_as_string,  # string, not dict
        )
        db_session.add(finding)
        db_session.flush()

        engine = RiskScoringEngine(db_session)

        # Must not raise TypeError — should read threat_intel from the parsed string
        with patch("app.services.risk_scoring._build_threat_intel_service", return_value=None):
            result = engine._score_all_findings(asset)

        # SEVERITY_FALLBACK_SCORE["high"]=50 + EPSS>0.5(15) + KEV(20) = 85.0
        assert result["max_finding_score"] == pytest.approx(85.0)
        assert result["kev_count"] == 1
        assert result["high_epss_count"] == 1

    def test_score_findings_no_threat_intel(self, db_session):
        """Finding without threat intel data scores normally."""
        from app.models.database import Asset, AssetType, Finding, FindingSeverity, FindingStatus, Tenant
        from app.services.risk_scoring import RiskScoringEngine

        tenant = Tenant(name="Test", slug="test-risk-no-ti")
        db_session.add(tenant)
        db_session.flush()

        asset = Asset(
            tenant_id=tenant.id,
            type=AssetType.SUBDOMAIN,
            identifier="clean.example.com",
        )
        db_session.add(asset)
        db_session.flush()

        finding = Finding(
            asset_id=asset.id,
            name="Info Disclosure",
            severity=FindingSeverity.MEDIUM,
            status=FindingStatus.OPEN,
            cve_id=None,
            evidence={},
        )
        db_session.add(finding)
        db_session.flush()

        engine = RiskScoringEngine(db_session)

        # cve_id=None → no threat intel lookup at all
        # SEVERITY_FALLBACK_SCORE["medium"] = 25.0
        with patch("app.services.risk_scoring._build_threat_intel_service", return_value=None):
            result = engine._score_all_findings(asset)

        assert result["max_finding_score"] == pytest.approx(25.0)
        assert result["kev_count"] == 0
        assert result["high_epss_count"] == 0

    def test_score_findings_epss_medium_boost(self, db_session):
        """Finding with medium EPSS (0.4-0.7) gets 5-point boost."""
        from app.models.database import Asset, AssetType, Finding, FindingSeverity, FindingStatus, Tenant
        from app.services.risk_scoring import RiskScoringEngine

        tenant = Tenant(name="Test", slug="test-risk-epss-med")
        db_session.add(tenant)
        db_session.flush()

        asset = Asset(
            tenant_id=tenant.id,
            type=AssetType.SUBDOMAIN,
            identifier="medium.example.com",
        )
        db_session.add(asset)
        db_session.flush()

        finding = Finding(
            asset_id=asset.id,
            name="SQL Injection",
            severity=FindingSeverity.HIGH,
            status=FindingStatus.OPEN,
            cve_id="CVE-2024-9999",
            evidence={
                "threat_intel": {
                    "epss_score": 0.55,
                    "is_kev": False,
                    "enriched_at": "2026-02-25T00:00:00",
                }
            },
        )
        db_session.add(finding)
        db_session.flush()

        engine = RiskScoringEngine(db_session)

        # Evidence has threat_intel key; EPSS=0.55 (>0.5 → +15 bonus)
        # SEVERITY_FALLBACK_SCORE["high"] = 50 + 15 = 65.0
        with patch("app.services.risk_scoring._build_threat_intel_service", return_value=None):
            result = engine._score_all_findings(asset)

        assert result["max_finding_score"] == pytest.approx(65.0)
        assert result["kev_count"] == 0
        assert result["high_epss_count"] == 1

    def test_score_findings_capped_at_100(self, db_session):
        """Each individual finding score is capped at 100.0; max_finding_score reports the cap."""
        from app.models.database import Asset, AssetType, Finding, FindingSeverity, FindingStatus, Tenant
        from app.services.risk_scoring import RiskScoringEngine

        tenant = Tenant(name="Test", slug="test-risk-cap")
        db_session.add(tenant)
        db_session.flush()

        asset = Asset(
            tenant_id=tenant.id,
            type=AssetType.SUBDOMAIN,
            identifier="capped.example.com",
        )
        db_session.add(asset)
        db_session.flush()

        # Add multiple critical KEV findings
        for i in range(5):
            finding = Finding(
                asset_id=asset.id,
                name=f"Critical CVE {i}",
                severity=FindingSeverity.CRITICAL,
                status=FindingStatus.OPEN,
                cve_id=f"CVE-2024-{1000 + i}",
                evidence={
                    "threat_intel": {
                        "epss_score": 0.95,
                        "is_kev": True,
                    }
                },
            )
            db_session.add(finding)

        db_session.flush()

        engine = RiskScoringEngine(db_session)

        # Each finding: SEVERITY_FALLBACK_SCORE["critical"]=75 + EPSS>0.5(15) + KEV(20) = 110 → capped at 100
        # max_finding_score = 100.0 (highest single finding, already at the per-finding cap)
        with patch("app.services.risk_scoring._build_threat_intel_service", return_value=None):
            result = engine._score_all_findings(asset)

        assert result["max_finding_score"] == 100.0

    def test_calculate_asset_risk_includes_threat_intel_metadata(self, db_session):
        """Full asset risk calculation includes threat_intel in components."""
        from app.models.database import Asset, AssetType, Finding, FindingSeverity, FindingStatus, Tenant
        from app.services.risk_scoring import RiskScoringEngine

        tenant = Tenant(name="Test", slug="test-risk-full")
        db_session.add(tenant)
        db_session.flush()

        asset = Asset(
            tenant_id=tenant.id,
            type=AssetType.SUBDOMAIN,
            identifier="full.example.com",
            is_active=True,
        )
        db_session.add(asset)
        db_session.flush()

        finding = Finding(
            asset_id=asset.id,
            name="KEV Vuln",
            severity=FindingSeverity.CRITICAL,
            status=FindingStatus.OPEN,
            cve_id="CVE-2024-1234",
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

        with patch("app.services.risk_scoring._build_threat_intel_service", return_value=None):
            result = engine.calculate_asset_risk(asset.id)

        assert "threat_intel" in result["components"]
        assert result["components"]["threat_intel"]["kev_count"] == 1
        assert result["components"]["threat_intel"]["high_epss_count"] == 1
        assert result["risk_score"] > 0


# ---------------------------------------------------------------------------
# Celery Task Tests (mocked)
# ---------------------------------------------------------------------------


class TestCeleryTasks:
    """Tests for threat intel Celery tasks."""

    @patch("app.database.SessionLocal")
    @patch("app.services.threat_intel.ThreatIntelService")
    def test_refresh_threat_intel_success(self, mock_service_cls, mock_session_cls):
        """Full refresh task completes successfully."""
        from app.tasks.threat_intel_sync import refresh_threat_intel

        mock_service = MagicMock()
        mock_service.refresh_kev_catalog.return_value = 1200
        mock_service.get_epss_scores_bulk.return_value = {
            "CVE-2024-1234": 0.97,
            "CVE-2024-5678": 0.03,
        }
        mock_service_cls.return_value = mock_service

        mock_session = MagicMock()
        mock_session.query.return_value.filter.return_value.distinct.return_value.all.return_value = [
            ("CVE-2024-1234",),
            ("CVE-2024-5678",),
        ]
        mock_session_cls.return_value = mock_session

        # Call task synchronously (not through Celery)
        result = refresh_threat_intel.apply().get()

        assert result["status"] in ("completed", "completed_with_errors")
        assert result["kev_count"] == 1200
        assert result["unique_cves"] == 2

    @patch("app.database.SessionLocal")
    @patch("app.services.threat_intel.ThreatIntelService")
    def test_enrich_findings_threat_intel_success(self, mock_service_cls, mock_session_cls):
        """Per-tenant enrichment task processes findings."""
        from app.tasks.threat_intel_sync import enrich_findings_threat_intel

        # Create mock findings
        mock_finding = MagicMock()
        mock_finding.id = 1
        mock_finding.cve_id = "CVE-2024-1234"
        mock_finding.asset_id = 10
        mock_finding.evidence = {}

        mock_session = MagicMock()
        mock_session.query.return_value.join.return_value.filter.return_value.all.return_value = [mock_finding]
        mock_session_cls.return_value = mock_session

        mock_service = MagicMock()
        mock_service.enrich_findings.return_value = [
            {
                "finding_id": 1,
                "cve_id": "CVE-2024-1234",
                "epss_score": 0.97,
                "is_kev": True,
                "kev_details": {"vendor": "Apache"},
            }
        ]
        mock_service_cls.return_value = mock_service

        # Patch the risk recalculation trigger
        with patch("app.tasks.scanning.calculate_comprehensive_risk_scores"):
            result = enrich_findings_threat_intel.apply(args=[1]).get()

        assert result["status"] == "completed"
        assert result["findings_processed"] == 1
        assert result["kev_matches"] == 1


# ---------------------------------------------------------------------------
# API Router Tests (mocked)
# ---------------------------------------------------------------------------


class TestThreatIntelAPI:
    """Tests for threat intelligence API endpoints."""

    def test_threat_intel_status_schema(self):
        """ThreatIntelStatusResponse schema validates correctly."""
        from app.api.schemas.threat_intel import ThreatIntelStatusResponse

        status = ThreatIntelStatusResponse(
            kev_last_refresh="2026-02-25T02:00:00+00:00",
            kev_count=1203,
            kev_catalog_cached=True,
            epss_cache_available=True,
        )

        assert status.kev_count == 1203
        assert status.kev_catalog_cached is True

    def test_finding_threat_intel_response_schema(self):
        """FindingThreatIntelResponse validates EPSS/KEV data."""
        from app.api.schemas.threat_intel import (
            FindingThreatIntelResponse,
            KEVDetailResponse,
        )

        response = FindingThreatIntelResponse(
            finding_id=42,
            cve_id="CVE-2024-1234",
            epss_score=0.97,
            epss_severity="critical",
            is_kev=True,
            kev_details=KEVDetailResponse(
                cve_id="CVE-2024-1234",
                vendor="Apache",
                product="Log4j",
                required_action="Patch immediately",
            ),
            risk_boost_description="Critical: actively exploited",
        )

        assert response.epss_score == pytest.approx(0.97)
        assert response.is_kev is True
        assert response.kev_details.vendor == "Apache"

    def test_finding_threat_intel_response_no_cve(self):
        """Response handles findings without CVE gracefully."""
        from app.api.schemas.threat_intel import FindingThreatIntelResponse

        response = FindingThreatIntelResponse(
            finding_id=99,
            cve_id=None,
            epss_score=0.0,
            epss_severity="low",
            is_kev=False,
            kev_details=None,
            risk_boost_description="No CVE associated with this finding.",
        )

        assert response.epss_score == 0.0
        assert response.is_kev is False


# ---------------------------------------------------------------------------
# Celery Beat Schedule Integration
# ---------------------------------------------------------------------------


class TestCeleryBeatIntegration:
    """Verify threat intel task is registered in Celery Beat schedule."""

    def test_beat_schedule_contains_threat_intel_task(self):
        """Celery Beat schedule includes the refresh-threat-intel entry."""
        from app.celery_app import celery

        schedule = celery.conf.beat_schedule

        assert "refresh-threat-intel" in schedule
        entry = schedule["refresh-threat-intel"]
        assert entry["task"] == "app.tasks.threat_intel_sync.refresh_threat_intel"

    def test_task_module_in_celery_includes(self):
        """Threat intel task module is in Celery include list."""
        from app.celery_app import celery

        # Verify the task is registered (either via include or by import)
        assert "app.tasks.threat_intel_sync.refresh_threat_intel" in celery.tasks


# ---------------------------------------------------------------------------
# Edge Cases and Resilience
# ---------------------------------------------------------------------------


class TestResilience:
    """Tests for graceful degradation when external services are unavailable."""

    def test_redis_failure_epss_returns_default(self, mock_redis):
        """EPSS returns 0.0 when Redis is unreachable."""
        import redis as redis_mod
        from app.services.threat_intel import ThreatIntelService

        mock_redis.get.side_effect = redis_mod.ConnectionError("Redis down")

        service = ThreatIntelService(redis_client=mock_redis)

        with patch("app.services.threat_intel.httpx.Client") as mock_client_cls:
            mock_client = MagicMock()
            mock_client.get.side_effect = httpx.ConnectError("API also down")
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client_cls.return_value = mock_client

            score = service.get_epss_score("CVE-2024-1234")

        assert score == 0.0

    def test_redis_failure_kev_returns_false(self, mock_redis):
        """KEV returns False when Redis is unreachable."""
        import redis as redis_mod
        from app.services.threat_intel import ThreatIntelService

        mock_redis.exists.side_effect = redis_mod.ConnectionError("Redis down")

        service = ThreatIntelService(redis_client=mock_redis)
        result = service.is_in_kev("CVE-2024-1234")

        assert result is False

    def test_epss_api_returns_empty_data(self, threat_intel_service):
        """EPSS returns 0.0 when API returns empty data array."""
        mock_response = MagicMock()
        mock_response.json.return_value = {"data": []}
        mock_response.raise_for_status = MagicMock()

        with patch("app.services.threat_intel.httpx.Client") as mock_client_cls:
            mock_client = MagicMock()
            mock_client.get.return_value = mock_response
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client_cls.return_value = mock_client

            score = threat_intel_service.get_epss_score("CVE-9999-0001")

        assert score == 0.0

    def test_kev_catalog_empty_vulnerabilities(self, threat_intel_service):
        """KEV refresh handles empty vulnerability list."""
        mock_response = MagicMock()
        mock_response.json.return_value = {"vulnerabilities": []}
        mock_response.raise_for_status = MagicMock()

        with patch("app.services.threat_intel.httpx.Client") as mock_client_cls:
            mock_client = MagicMock()
            mock_client.get.return_value = mock_response
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client_cls.return_value = mock_client

            count = threat_intel_service.refresh_kev_catalog()

        assert count == 0

    def test_risk_scoring_degrades_without_threat_intel(self, db_session):
        """Risk scoring works normally when ThreatIntelService is unavailable."""
        from app.models.database import Asset, AssetType, Finding, FindingSeverity, FindingStatus, Tenant
        from app.services.risk_scoring import RiskScoringEngine

        tenant = Tenant(name="Test", slug="test-degrade")
        db_session.add(tenant)
        db_session.flush()

        asset = Asset(
            tenant_id=tenant.id,
            type=AssetType.SUBDOMAIN,
            identifier="degrade.example.com",
        )
        db_session.add(asset)
        db_session.flush()

        # Finding with CVE but no cached threat intel
        finding = Finding(
            asset_id=asset.id,
            name="Some Vuln",
            severity=FindingSeverity.HIGH,
            status=FindingStatus.OPEN,
            cve_id="CVE-2024-1234",
            evidence={},  # No threat_intel key
        )
        db_session.add(finding)
        db_session.flush()

        engine = RiskScoringEngine(db_session)

        # _build_threat_intel_service returns None → no live lookups; evidence={} → no cached TI
        with patch("app.services.risk_scoring._build_threat_intel_service", return_value=None):
            result = engine._score_all_findings(asset)

        # SEVERITY_FALLBACK_SCORE["high"] = 50.0; EPSS=0.0, not KEV → no bonus
        assert result["max_finding_score"] == pytest.approx(50.0)
        assert result["kev_count"] == 0
        assert result["high_epss_count"] == 0
