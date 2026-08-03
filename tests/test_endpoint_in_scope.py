"""In-scope guard for Katana endpoints fed to nuclei.

The authorisation boundary must come from EXPLICIT authorization (the tenant's asset hosts
+ its seed root domains), NOT be inferred from a discovered asset's registrable domain —
otherwise a discovered host on shared infrastructure (azurewebsites.net, github.io, CDNs)
would authorise scanning OTHER tenants' hosts. Off-site crawled links are refused.
"""

from __future__ import annotations

from app.tasks.scanning import host_in_scope, normalize_host

# authorised assets (exact) + explicitly-authorised seed roots
_HOSTS = {"www.edizionicurci.it", "cliente.azurewebsites.net"}
_ROOTS = {"edizionicurci.it"}


def test_exact_asset_host_is_in_scope():
    assert host_in_scope("www.edizionicurci.it", _HOSTS, _ROOTS)
    # exact asset is authorised even when it sits on shared hosting
    assert host_in_scope("cliente.azurewebsites.net", _HOSTS, _ROOTS)


def test_subdomain_under_explicit_root_is_in_scope():
    assert host_in_scope("staging.musicandbooks.edizionicurci.it", _HOSTS, _ROOTS)
    assert host_in_scope("edizionicurci.it", _HOSTS, _ROOTS)  # the root itself


def test_shared_host_sibling_is_out_of_scope():
    # cliente.azurewebsites.net is ours, but that must NOT authorise a sibling tenant on the
    # same shared suffix — the classic scope-expansion trap.
    assert not host_in_scope("vittima.azurewebsites.net", _HOSTS, _ROOTS)
    assert not host_in_scope("azurewebsites.net", _HOSTS, _ROOTS)


def test_discovered_asset_does_not_widen_scope():
    # azurewebsites.net is not a seed root, so nothing under it beyond the exact asset is in.
    assert not host_in_scope("other.azurewebsites.net", _HOSTS, _ROOTS)


def test_external_hosts_are_out_of_scope():
    for h in ("www.youtube.com", "github.com", "cdnjs.cloudflare.com", "www.facebook.com", "gnu.org", "malsup.com"):
        assert not host_in_scope(h, _HOSTS, _ROOTS), f"{h} must be out of scope"


def test_lookalike_suffix_is_out_of_scope():
    # ends with the root STRING but is a different label / different domain
    assert not host_in_scope("notedizionicurci.it", _HOSTS, _ROOTS)
    assert not host_in_scope("edizionicurci.it.evil.com", _HOSTS, _ROOTS)


def test_fail_closed_without_roots():
    # no authorised roots → exact-match only (fail-closed): subdomains are refused
    assert host_in_scope("www.edizionicurci.it", _HOSTS, set())
    assert not host_in_scope("staging.edizionicurci.it", _HOSTS, set())


def test_case_and_trailing_dot_are_normalised():
    assert host_in_scope("WWW.Edizionicurci.IT.", _HOSTS, _ROOTS)
    assert host_in_scope("Cliente.AzureWebsites.NET", _HOSTS, _ROOTS)
    assert normalize_host("WWW.Edizionicurci.IT.") == "www.edizionicurci.it"


def test_idna_is_normalised():
    # a unicode host normalises to punycode consistently, and matches a punycode root
    uni = "café.example"
    puny = uni.encode("idna").decode("ascii")
    assert normalize_host(uni) == puny
    assert host_in_scope("shop." + uni, set(), {puny})


def test_empty_or_none_host_is_out_of_scope():
    assert not host_in_scope("", _HOSTS, _ROOTS)
    assert not host_in_scope(None, _HOSTS, _ROOTS)
