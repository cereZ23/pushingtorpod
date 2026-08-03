"""In-scope guard for Katana endpoints fed to nuclei.

The authorisation boundary is EXPLICIT: the pass's own asset hosts (exact match) plus the
tenant's ACTIVE ScanAuthorization scope entries (domain covers subdomains, ip/cidr for IPs).
It is NEVER inferred from a discovered asset's registrable domain — otherwise a discovered
host on shared infra (azurewebsites.net, github.io, CDNs) would authorise OTHER tenants.
Off-site crawled links are refused.
"""

from __future__ import annotations

from app.tasks.scanning import host_in_scope, normalize_host

# authorised assets received by THIS pass (exact) + an ACTIVE authorization for one domain
_HOSTS = {"www.edizionicurci.it", "cliente.azurewebsites.net"}
_SCOPE = [{"type": "domain", "value": "edizionicurci.it"}]


def test_exact_pass_asset_is_in_scope():
    assert host_in_scope("www.edizionicurci.it", _HOSTS, _SCOPE)
    # exact asset is authorised even on shared hosting
    assert host_in_scope("cliente.azurewebsites.net", _HOSTS, _SCOPE)


def test_subdomain_under_authorised_domain_is_in_scope():
    assert host_in_scope("staging.musicandbooks.edizionicurci.it", _HOSTS, _SCOPE)
    assert host_in_scope("edizionicurci.it", _HOSTS, _SCOPE)  # the authorised domain itself


def test_shared_host_sibling_is_out_of_scope():
    # our cliente.azurewebsites.net must NOT authorise a sibling tenant on the shared suffix
    assert not host_in_scope("vittima.azurewebsites.net", _HOSTS, _SCOPE)
    assert not host_in_scope("other.azurewebsites.net", _HOSTS, _SCOPE)
    assert not host_in_scope("azurewebsites.net", _HOSTS, _SCOPE)


def test_external_hosts_are_out_of_scope():
    for h in ("www.youtube.com", "github.com", "cdnjs.cloudflare.com", "www.facebook.com", "gnu.org", "malsup.com"):
        assert not host_in_scope(h, _HOSTS, _SCOPE), f"{h} must be out of scope"


def test_lookalike_suffix_is_out_of_scope():
    assert not host_in_scope("notedizionicurci.it", _HOSTS, _SCOPE)
    assert not host_in_scope("edizionicurci.it.evil.com", _HOSTS, _SCOPE)


def test_fail_closed_without_authorization():
    # no active scope entries → exact-match only (fail-closed): subdomains refused
    assert host_in_scope("www.edizionicurci.it", _HOSTS, [])
    assert not host_in_scope("staging.edizionicurci.it", _HOSTS, [])


def test_ip_cidr_scope_entry():
    scope = [{"type": "cidr", "value": "10.0.0.0/8"}]
    assert host_in_scope("10.1.2.3", set(), scope)
    assert not host_in_scope("11.0.0.1", set(), scope)


def test_case_and_trailing_dot_are_normalised():
    assert host_in_scope("WWW.Edizionicurci.IT.", _HOSTS, _SCOPE)
    assert host_in_scope("Cliente.AzureWebsites.NET", _HOSTS, _SCOPE)
    assert normalize_host("WWW.Edizionicurci.IT.") == "www.edizionicurci.it"


def test_idna_is_normalised():
    uni = "café.example"
    puny = uni.encode("idna").decode("ascii")
    assert normalize_host(uni) == puny
    assert host_in_scope("shop." + uni, set(), [{"type": "domain", "value": puny}])


def test_empty_or_none_host_is_out_of_scope():
    assert not host_in_scope("", _HOSTS, _SCOPE)
    assert not host_in_scope(None, _HOSTS, _SCOPE)
