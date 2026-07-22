"""API tests for scan-authorization management."""

from app.models.authorization import ScanAuthorization  # noqa: F401 (ensure table registered)


def _url(tenant_id: int) -> str:
    return f"/api/v1/tenants/{tenant_id}/scan-authorizations"


class TestScanAuthorizationApi:
    def test_create_list_revoke(self, authenticated_client, test_tenant):
        tid = test_tenant.id
        payload = {
            "name": "Client X engagement",
            "scope_entries": [{"type": "domain", "value": "example.com"}],
            "authorized_by": "CISO",
            "authorization_ref": "SOW-42",
        }
        created = authenticated_client.post(_url(tid), json=payload)
        assert created.status_code == 201, created.text
        data = created.json()
        assert data["name"] == "Client X engagement"
        assert data["scope_entries"] == [{"type": "domain", "value": "example.com"}]
        assert data["is_active"] is True
        auth_id = data["id"]

        listed = authenticated_client.get(_url(tid))
        assert listed.status_code == 200
        assert any(a["id"] == auth_id for a in listed.json())

        revoked = authenticated_client.delete(f"{_url(tid)}/{auth_id}")
        assert revoked.status_code == 204

        # After revoke it is inactive (still listed, is_active False)
        after = authenticated_client.get(_url(tid)).json()
        assert all((a["id"] != auth_id) or (a["is_active"] is False) for a in after)

    def test_scope_entries_required(self, authenticated_client, test_tenant):
        resp = authenticated_client.post(_url(test_tenant.id), json={"name": "x", "scope_entries": []})
        assert resp.status_code == 422  # min_length=1

    def test_invalid_scope_type_rejected(self, authenticated_client, test_tenant):
        resp = authenticated_client.post(
            _url(test_tenant.id),
            json={"name": "x", "scope_entries": [{"type": "regex", "value": ".*"}]},
        )
        assert resp.status_code == 422
