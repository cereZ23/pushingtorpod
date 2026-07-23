"""The isolation guard must NOT cover auth/access-control tables (cross-tenant by design)."""

from app.core.tenant_guard import _build_scoped_registry


def test_auth_tables_excluded_but_data_tables_covered():
    names = {c.__name__ for c in _build_scoped_registry()}
    # data tables stay guarded
    assert "Asset" in names
    assert "Finding" in names
    # access-control tables are excluded (login reads memberships cross-tenant)
    assert "TenantMembership" not in names
    assert "APIKey" not in names
    assert "UserInvitation" not in names
