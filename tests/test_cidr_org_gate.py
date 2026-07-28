"""Phase 1c only expands netblocks that belong to the target org, not the
hosting provider's range (the 792-provider-IP explosion)."""

from __future__ import annotations

from types import SimpleNamespace

from app.tasks.pipeline_phases.discovery import _org_matches_target, _target_org_tokens


# _target_org_tokens compares a.type against AssetType enum members.
from app.models.database import AssetType  # noqa: E402


def _asset(identifier, atype):
    return SimpleNamespace(identifier=identifier, type=atype)


def test_tokens_from_domains_and_subdomains():
    assets = [
        _asset("itsright.it", AssetType.DOMAIN),
        _asset("www.itsright.it", AssetType.SUBDOMAIN),
        _asset("mail.itsright.it", AssetType.SUBDOMAIN),
        _asset("89.188.129.5", AssetType.IP),  # ignored
    ]
    assert _target_org_tokens(assets) == {"itsright"}


def test_multi_domain_tokens():
    assets = [
        _asset("acme.com", AssetType.DOMAIN),
        _asset("shop.example.co.uk", AssetType.SUBDOMAIN),
    ]
    assert _target_org_tokens(assets) == {"acme", "example"}


def test_provider_org_does_not_match():
    tokens = {"itsright"}
    # the hosting provider's netblock org — must NOT expand
    assert _org_matches_target("Aruba S.p.A.", tokens) is False
    assert _org_matches_target("SomeItalianHosting SRL", tokens) is False
    assert _org_matches_target(None, tokens) is False
    assert _org_matches_target("", tokens) is False


def test_target_owned_netblock_matches():
    tokens = {"itsright"}
    assert _org_matches_target("ItsRight Technologies SRL", tokens) is True
    assert _org_matches_target("ITSRIGHT", tokens) is True


def test_no_tokens_never_matches():
    assert _org_matches_target("Anything", set()) is False
