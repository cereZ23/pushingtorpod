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


def test_bulk_upsert_evidence_is_not_double_encoded(db_session, test_tenant):
    # Regression: bulk_upsert json.dumps'd a dict AND SQLAlchemy's JSON serializer dumped it again
    # → a *double*-encoded row that read back as a str-wrapping-a-str, so every reader that calls
    # .get() on evidence (e.g. correlation) raised 'str' object has no attribute 'get'.
    #
    # NOTE: findings.evidence is currently a TEXT column (schema drift — the model declares JSON but
    # the initial migration created Text; create_all() never alters it), and on postgres SQLAlchemy
    # trusts psycopg2 to parse JSON, which it does NOT for a TEXT column. So evidence legitimately
    # round-trips as a *single*-encoded JSON string today. What matters — and what this asserts — is
    # that ONE decode recovers the dict, never two. (A TEXT→JSONB migration, tracked separately,
    # will let it round-trip as a real dict; this test stays green either way.)
    import json

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
    # A defensive reader recovers the dict whether the column holds a real dict (post-migration) or a
    # single-encoded JSON string (current TEXT column).
    assert evidence_dict(f.evidence) == {"type": "http", "k": "v"}
    # And it is NOT double-encoded: a single json.loads of the stored string yields the dict — not
    # another string (which is exactly what the old double-dump produced).
    if isinstance(f.evidence, str):
        assert json.loads(f.evidence) == {"type": "http", "k": "v"}


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
    db_session.commit()  # populate asset.id BEFORE the finding references it (asset_id is NOT NULL)
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

    # Force the legacy stringified shape: a core update bypasses the ORM validator, so evidence
    # reads back as a Python str instead of a dict.
    db_session.execute(update(Finding).where(Finding.id == f.id).values(evidence='{"type": "network"}'))
    db_session.commit()
    db_session.expire(f)
    assert isinstance(f.evidence, str)  # confirm the legacy state is reproduced

    result = corr.run_correlation(test_tenant.id, scan_run_id=None)
    assert "error" not in result  # did NOT raise on the stringified evidence
    assert result.get("issues_created", 0) + result.get("issues_updated", 0) >= 1


def test_update_finding_status_keeps_evidence_recoverable_with_notes(db_session, test_tenant):
    # update_finding_status appends a status note into evidence. It must parse whatever shape
    # evidence is in (dict OR legacy string) and write it back single-encoded, so the note is
    # retained and the row is not double-encoded.
    import json

    from app.models.database import Asset, AssetType, Finding
    from app.repositories.finding_repository import FindingRepository

    asset = Asset(tenant_id=test_tenant.id, identifier="notes.test.com", type=AssetType.SUBDOMAIN, is_active=True)
    db_session.add(asset)
    db_session.commit()

    repo = FindingRepository(db_session)
    repo.bulk_upsert_findings(
        [
            {
                "asset_id": asset.id,
                "template_id": "CVE-NOTE",
                "name": "n",
                "severity": "high",
                "evidence": {"type": "http", "k": "v"},
            }
        ],
        tenant_id=test_tenant.id,
    )
    f = db_session.query(Finding).filter(Finding.asset_id == asset.id).first()

    repo.update_finding_status(f.id, "suppressed", notes="false positive")

    db_session.expire(f)
    ev = evidence_dict(f.evidence)
    assert ev.get("type") == "http"  # original evidence preserved
    assert ev.get("status_notes") and ev["status_notes"][-1]["notes"] == "false positive"
    if isinstance(f.evidence, str):
        assert isinstance(json.loads(f.evidence), dict)  # single decode → dict (not double-encoded)
