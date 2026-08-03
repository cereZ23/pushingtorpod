"""In-scope guard for Katana endpoints fed to nuclei.

Katana follows off-site links, so the crawled endpoint set contains third-party hosts.
Scanning those is out of scope / unauthorised — host_in_scope must keep only the tenant's
own hosts (exact asset or under a tenant registrable domain) and refuse everything else.
"""

from __future__ import annotations

from app.tasks.scanning import host_in_scope

_ROOTS = {"edizionicurci.it"}
_HOSTS = {"www.edizionicurci.it"}


def test_exact_asset_host_is_in_scope():
    assert host_in_scope("www.edizionicurci.it", _HOSTS, _ROOTS)


def test_subdomain_under_tenant_root_is_in_scope():
    assert host_in_scope("staging.musicandbooks.edizionicurci.it", _HOSTS, _ROOTS)


def test_case_insensitive():
    assert host_in_scope("WWW.Edizionicurci.IT", _HOSTS, _ROOTS)


def test_external_hosts_are_out_of_scope():
    for h in (
        "www.youtube.com",
        "github.com",
        "cdnjs.cloudflare.com",
        "fonts.googleapis.com",
        "www.facebook.com",
        "gnu.org",
        "malsup.com",
    ):
        assert not host_in_scope(h, _HOSTS, _ROOTS), f"{h} must be out of scope"


def test_lookalike_suffix_is_out_of_scope():
    # a host that merely ENDS with the root string but is a different domain
    assert not host_in_scope("notedizionicurci.it", _HOSTS, _ROOTS)
    assert not host_in_scope("edizionicurci.it.evil.com", _HOSTS, _ROOTS)


def test_empty_host_is_out_of_scope():
    assert not host_in_scope("", _HOSTS, _ROOTS)
