"""Network/service findings sharing a resolved IP collapse to one."""

from __future__ import annotations

from types import SimpleNamespace

from app.tasks.correlation import _network_dupe_groups


def _f(fid, asset_id, template_id, host):
    return SimpleNamespace(id=fid, asset_id=asset_id, template_id=template_id, host=host)


def test_same_template_same_ip_collapses():
    findings = [
        _f(1, 10, "ftp-detect", "itsright.it"),
        _f(2, 11, "ftp-detect", "www.itsright.it"),
    ]
    ip_by_asset = {10: {"1.2.3.4"}, 11: {"1.2.3.4"}}
    groups = _network_dupe_groups(findings, ip_by_asset)
    assert len(groups) == 1
    keep, dupes = groups[0]
    assert keep.id == 1  # lowest id kept
    assert [d.id for d in dupes] == [2]


def test_three_hosts_one_ip_one_kept_two_dupes():
    findings = [
        _f(3, 20, "ssh-detect", "a.ex.com"),
        _f(1, 21, "ssh-detect", "b.ex.com"),
        _f(2, 22, "ssh-detect", "c.ex.com"),
    ]
    ip_by_asset = {20: {"9.9.9.9"}, 21: {"9.9.9.9"}, 22: {"9.9.9.9"}}
    groups = _network_dupe_groups(findings, ip_by_asset)
    assert len(groups) == 1
    keep, dupes = groups[0]
    assert keep.id == 1
    assert sorted(d.id for d in dupes) == [2, 3]


def test_different_template_not_grouped():
    findings = [
        _f(1, 10, "ftp-detect", "a"),
        _f(2, 11, "ssh-detect", "b"),
    ]
    ip_by_asset = {10: {"1.1.1.1"}, 11: {"1.1.1.1"}}
    assert _network_dupe_groups(findings, ip_by_asset) == []


def test_different_ip_not_grouped():
    findings = [
        _f(1, 10, "ftp-detect", "a"),
        _f(2, 11, "ftp-detect", "b"),
    ]
    ip_by_asset = {10: {"1.1.1.1"}, 11: {"2.2.2.2"}}
    assert _network_dupe_groups(findings, ip_by_asset) == []


def test_finding_without_ip_is_skipped():
    findings = [
        _f(1, 10, "ftp-detect", "a"),
        _f(2, 11, "ftp-detect", "b"),  # no IP mapping
    ]
    ip_by_asset = {10: {"1.1.1.1"}}
    assert _network_dupe_groups(findings, ip_by_asset) == []


from app.tasks.correlation import _is_dedupable_by_ip


def _nf(ftype, template_id="x"):
    return SimpleNamespace(evidence={"type": ftype}, template_id=template_id)


class TestIsDedupableByIp:
    def test_tcp_and_network_are_dedupable(self):
        assert _is_dedupable_by_ip(_nf("tcp")) is True
        assert _is_dedupable_by_ip(_nf("network")) is True

    def test_http_is_not_dedupable(self):
        assert _is_dedupable_by_ip(_nf("http")) is False

    def test_ssl_server_config_is_dedupable(self):
        assert _is_dedupable_by_ip(_nf("ssl", "ssl/weak-cipher-suites")) is True
        assert _is_dedupable_by_ip(_nf("ssl", "ssl/tls-version")) is True
        assert _is_dedupable_by_ip(_nf("ssl", "ssl/deprecated-tls")) is True
        assert _is_dedupable_by_ip(_nf("ssl", "ssl/ssl-dh-params")) is True

    def test_ssl_cert_specific_is_not_dedupable(self):
        # cert findings differ per SNI/hostname — keep per-host
        assert _is_dedupable_by_ip(_nf("ssl", "ssl/expired-ssl")) is False
        assert _is_dedupable_by_ip(_nf("ssl", "ssl/self-signed-ssl")) is False
        assert _is_dedupable_by_ip(_nf("ssl", "ssl/mismatched-ssl")) is False

    def test_no_evidence_type_is_not_dedupable(self):
        assert _is_dedupable_by_ip(SimpleNamespace(evidence=None, template_id="x")) is False
