"""Tests for live DMARC/DKIM email-auth controls (EML-003, EML-004)."""

from unittest.mock import MagicMock, patch

from app.models.database import Asset, AssetType
from app.services.dns_lookup import resolve_txt
from app.tasks.misconfig import check_eml_003, check_eml_004


def _domain(identifier="example.com"):
    return Asset(identifier=identifier, type=AssetType.DOMAIN)


class TestDnsLookup:
    def test_resolve_txt_joins_strings(self):
        rdata = MagicMock()
        rdata.strings = [b"v=spf1 ", b"-all"]
        resolver = MagicMock()
        resolver.resolve.return_value = [rdata]
        with patch("dns.resolver.Resolver", return_value=resolver):
            assert resolve_txt("example.com") == ["v=spf1 -all"]

    def test_resolve_txt_swallows_errors(self):
        resolver = MagicMock()
        resolver.resolve.side_effect = Exception("NXDOMAIN")
        with patch("dns.resolver.Resolver", return_value=resolver):
            assert resolve_txt("example.com") == []


class TestDmarc:
    def test_missing_dmarc_flagged(self):
        with patch("app.tasks.misconfig.resolve_txt", return_value=[]):
            findings = check_eml_003(_domain(), [], [], db=MagicMock())
        assert len(findings) == 1
        assert findings[0]["control_id"] == "EML-003"
        assert findings[0]["severity"] == "medium"

    def test_weak_policy_p_none_flagged_low(self):
        with patch("app.tasks.misconfig.resolve_txt", return_value=["v=DMARC1; p=none; rua=mailto:x@y.com"]):
            findings = check_eml_003(_domain(), [], [], db=MagicMock())
        assert len(findings) == 1
        assert findings[0]["severity"] == "low"
        assert "monitor-only" in findings[0]["name"]

    def test_enforcing_policy_not_flagged(self):
        with patch("app.tasks.misconfig.resolve_txt", return_value=["v=DMARC1; p=reject"]):
            findings = check_eml_003(_domain(), [], [], db=MagicMock())
        assert findings == []


class TestDkim:
    def test_non_mail_domain_skipped(self):
        with patch("app.tasks.misconfig.has_mx", return_value=False):
            findings = check_eml_004(_domain(), [], [], db=MagicMock())
        assert findings == []

    def test_mail_domain_without_dkim_is_presumptive(self):
        with (
            patch("app.tasks.misconfig.has_mx", return_value=True),
            patch("app.tasks.misconfig.resolve_txt", return_value=[]),
        ):
            findings = check_eml_004(_domain(), [], [], db=MagicMock())
        assert len(findings) == 1
        assert findings[0]["control_id"] == "EML-004"
        assert findings[0]["evidence"]["confidence"] == "presumptive"

    def test_dkim_present_not_flagged(self):
        with (
            patch("app.tasks.misconfig.has_mx", return_value=True),
            patch("app.tasks.misconfig.resolve_txt", return_value=["v=DKIM1; k=rsa; p=MIGf..."]),
        ):
            findings = check_eml_004(_domain(), [], [], db=MagicMock())
        assert findings == []
