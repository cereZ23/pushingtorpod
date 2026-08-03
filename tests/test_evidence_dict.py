"""Finding.evidence must survive as a dict end-to-end.

bulk_upsert used to json.dumps a dict into the JSON column, storing a double-encoded
STRING; readers that call .get() on evidence (e.g. correlation) then raised
'str' object has no attribute 'get'. Two-level fix: a defensive evidence_dict() reader
(tolerates legacy string rows) + the writer no longer double-encodes.
"""

from __future__ import annotations

from app.tasks.correlation import evidence_dict


def test_dict_passes_through():
    d = {"type": "http", "k": "v"}
    assert evidence_dict(d) is d


def test_json_object_string_is_decoded():
    assert evidence_dict('{"type": "network", "port": 22}') == {"type": "network", "port": 22}


def test_json_list_or_scalar_string_is_empty():
    assert evidence_dict("[1, 2, 3]") == {}
    assert evidence_dict('"just a string"') == {}
    assert evidence_dict("42") == {}


def test_invalid_string_is_empty():
    assert evidence_dict("not json at all") == {}
    assert evidence_dict("") == {}


def test_none_and_non_json_types_are_empty():
    assert evidence_dict(None) == {}
    assert evidence_dict(123) == {}
    assert evidence_dict([1, 2]) == {}


def test_bulk_upsert_stores_and_reads_evidence_as_dict(db_session, test_tenant):
    from app.models.database import Asset, AssetType, Finding
    from app.repositories.finding_repository import FindingRepository

    asset = Asset(tenant_id=test_tenant.id, identifier="ev.test.com", type=AssetType.SUBDOMAIN, is_active=True)
    db_session.add(asset)
    db_session.commit()

    FindingRepository(db_session).bulk_upsert_findings(
        [
            {
                "asset_id": asset.id,
                "template_id": "CVE-EV",
                "name": "e",
                "severity": "high",
                "evidence": {"type": "http", "k": "v"},
            }
        ],
        tenant_id=test_tenant.id,
    )

    f = db_session.query(Finding).filter(Finding.asset_id == asset.id).first()
    assert isinstance(f.evidence, dict)  # NOT a json-encoded string
    assert f.evidence.get("type") == "http"


def test_correlation_survives_stringified_evidence(db_session, test_tenant, monkeypatch):
    # A legacy finding whose evidence column holds a JSON *string* must not crash correlation
    # ('str' object has no attribute 'get') — it must still be grouped into an issue.
    from sqlalchemy import update

    import app.tasks.correlation as corr
    from app.models.database import Asset, AssetType, Finding, FindingSeverity, FindingStatus

    monkeypatch.setattr(corr, "SessionLocal", lambda: db_session)
    monkeypatch.setattr(db_session, "close", lambda: None)

    asset = Asset(tenant_id=test_tenant.id, identifier="corr.test.com", type=AssetType.SUBDOMAIN, is_active=True)
    db_session.add(asset)
    f = Finding(
        asset_id=asset.id,
        source="nuclei",
        template_id="CVE-CORR",
        name="corr finding",
        severity=FindingSeverity.HIGH,
        status=FindingStatus.OPEN,
    )
    db_session.add(f)
    db_session.commit()

    # Force the legacy double-encoded shape: a core update bypasses the ORM validator, so the
    # JSON column ends up holding a JSON *string* (read back as a Python str).
    db_session.execute(update(Finding).where(Finding.id == f.id).values(evidence='{"type": "network"}'))
    db_session.commit()
    db_session.expire(f)
    assert isinstance(f.evidence, str)  # confirm the legacy state is reproduced

    result = corr.run_correlation(test_tenant.id, scan_run_id=None)
    assert "error" not in result  # did NOT raise on the stringified evidence
    assert result.get("issues_created", 0) + result.get("issues_updated", 0) >= 1
