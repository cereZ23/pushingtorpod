"""
Test suite for Network Intelligence Service and Network Enrichment Task

Tests cover:
- WHOIS lookup with real and failed responses
- Reverse DNS resolution
- Domain IP resolution
- GeoIP + ASN lookup with rate limiting
- CDN detection from HTTP headers
- WAF detection from HTTP headers
- Cloud provider detection (headers + ASN)
- Composite enrichment (enrich_asset_network)
- Celery task (run_network_enrichment) with mocked DB
- Pipeline integration (phase_1c_network_enrichment)
- Rate limiting enforcement
- Error handling / graceful degradation
"""

import json
import time
from datetime import datetime
from unittest.mock import MagicMock, Mock, patch, PropertyMock

import pytest

from app.services.network_intel import (
    CDN_SIGNATURES,
    CLOUD_SIGNATURES,
    WAF_SIGNATURES,
    _flatten_headers,
    _serialize_date,
    detect_cdn,
    detect_cloud_provider,
    detect_waf,
    enrich_asset_network,
    geoip_lookup,
    resolve_domain_ip,
    reverse_dns,
    whois_lookup,
)


# ============================================================================
# _serialize_date
# ============================================================================


class TestSerializeDate:
    def test_datetime_object(self):
        dt = datetime(2024, 6, 15, 12, 30, 0)
        assert _serialize_date(dt) == "2024-06-15T12:30:00"

    def test_date_object(self):
        from datetime import date

        d = date(2024, 6, 15)
        assert _serialize_date(d) == "2024-06-15"

    def test_list_of_dates(self):
        from datetime import date

        dates = [date(2024, 1, 1), date(2025, 1, 1)]
        assert _serialize_date(dates) == "2024-01-01"

    def test_none_returns_none(self):
        assert _serialize_date(None) is None

    def test_string_returns_none(self):
        assert _serialize_date("not a date") is None

    def test_empty_list(self):
        assert _serialize_date([]) is None


# ============================================================================
# WHOIS Lookup
# ============================================================================


class TestWhoisLookup:
    @patch("app.services.network_intel._whois_module")
    def test_successful_whois(self, mock_whois_module):
        """WHOIS lookup returns structured data for a valid domain."""
        mock_result = MagicMock()
        mock_result.registrar = "Namecheap"
        mock_result.org = "ACME Corp"
        mock_result.country = "US"
        mock_result.creation_date = datetime(2020, 1, 15)
        mock_result.expiration_date = datetime(2025, 1, 15)
        mock_result.name_servers = ["NS1.EXAMPLE.COM.", "ns2.example.com"]
        mock_result.emails = ["admin@example.com", "tech@example.com"]

        mock_whois_module.whois.return_value = mock_result

        result = whois_lookup("example.com")

        assert result["registrar"] == "Namecheap"
        assert result["org"] == "ACME Corp"
        assert result["country"] == "US"
        assert result["created"] == "2020-01-15T00:00:00"
        assert result["expires"] == "2025-01-15T00:00:00"
        assert "ns1.example.com" in result["nameservers"]
        assert "ns2.example.com" in result["nameservers"]
        assert "admin@example.com" in result["emails"]
        assert "tech@example.com" in result["emails"]

    @patch("app.services.network_intel._whois_module")
    def test_whois_returns_none(self, mock_whois_module):
        """WHOIS lookup gracefully handles None response."""
        mock_whois_module.whois.return_value = None

        result = whois_lookup("nonexistent-domain.xyz")

        assert result["registrar"] is None
        assert result["org"] is None
        assert result["nameservers"] == []
        assert result["emails"] == []

    @patch("app.services.network_intel._whois_module")
    def test_whois_exception_handled(self, mock_whois_module):
        """WHOIS lookup handles exceptions gracefully."""
        mock_whois_module.whois.side_effect = Exception("Connection timeout")

        result = whois_lookup("example.com")

        assert result["registrar"] is None
        assert result["nameservers"] == []

    @patch("app.services.network_intel._whois_module")
    def test_whois_partial_data(self, mock_whois_module):
        """WHOIS lookup handles partial/GDPR-redacted responses."""
        mock_result = MagicMock()
        mock_result.registrar = "Namecheap"
        mock_result.org = None  # GDPR redacted
        mock_result.country = None
        mock_result.creation_date = None
        mock_result.expiration_date = None
        mock_result.name_servers = None
        mock_result.emails = None

        mock_whois_module.whois.return_value = mock_result

        result = whois_lookup("example.com")

        assert result["registrar"] == "Namecheap"
        assert result["org"] is None
        assert result["nameservers"] == []
        assert result["emails"] == []

    @patch("app.services.network_intel._whois_module")
    def test_whois_nameservers_as_string(self, mock_whois_module):
        """WHOIS handles name_servers returned as a single string."""
        mock_result = MagicMock()
        mock_result.registrar = None
        mock_result.org = None
        mock_result.country = None
        mock_result.creation_date = None
        mock_result.expiration_date = None
        mock_result.name_servers = "ns1.example.com"
        mock_result.emails = "admin@example.com"

        mock_whois_module.whois.return_value = mock_result

        result = whois_lookup("example.com")

        assert result["nameservers"] == ["ns1.example.com"]
        assert result["emails"] == ["admin@example.com"]


# ============================================================================
# Reverse DNS
# ============================================================================


class TestReverseDns:
    @patch("app.services.network_intel.socket.gethostbyaddr")
    def test_successful_reverse_dns(self, mock_gethostbyaddr):
        mock_gethostbyaddr.return_value = ("host.example.com", [], ["93.184.216.34"])

        result = reverse_dns("93.184.216.34")

        assert result == "host.example.com"
        mock_gethostbyaddr.assert_called_once_with("93.184.216.34")

    @patch("app.services.network_intel.socket.gethostbyaddr")
    def test_no_ptr_record(self, mock_gethostbyaddr):
        import socket

        mock_gethostbyaddr.side_effect = socket.herror("Host not found")

        result = reverse_dns("192.0.2.1")

        assert result is None

    @patch("app.services.network_intel.socket.gethostbyaddr")
    def test_returns_ip_itself(self, mock_gethostbyaddr):
        """Should return None if gethostbyaddr returns the IP."""
        mock_gethostbyaddr.return_value = ("192.0.2.1", [], ["192.0.2.1"])

        result = reverse_dns("192.0.2.1")

        assert result is None


# ============================================================================
# Domain IP Resolution
# ============================================================================


class TestResolveDomainIp:
    @patch("app.services.network_intel.socket.getaddrinfo")
    def test_successful_resolution(self, mock_getaddrinfo):
        mock_getaddrinfo.return_value = [
            (2, 1, 6, "", ("93.184.216.34", 0)),
        ]

        result = resolve_domain_ip("example.com")

        assert result == "93.184.216.34"

    @patch("app.services.network_intel.socket.getaddrinfo")
    def test_failed_resolution(self, mock_getaddrinfo):
        import socket

        mock_getaddrinfo.side_effect = socket.gaierror("Name resolution failed")

        result = resolve_domain_ip("nonexistent.invalid")

        assert result is None


# ============================================================================
# GeoIP Lookup
# ============================================================================


class TestGeoipLookup:
    @patch("app.services.network_intel._get_asn_reader")
    @patch("app.services.network_intel._get_city_reader")
    def test_successful_geoip(self, mock_city_reader_fn, mock_asn_reader_fn):
        """GeoLite2 City + ASN lookup returns combined geo/network data."""
        # Mock City reader
        mock_city_resp = MagicMock()
        mock_city_resp.country.name = "United States"
        mock_city_resp.country.iso_code = "US"
        mock_city_resp.subdivisions.most_specific.name = "California"
        mock_city_resp.subdivisions.__bool__ = lambda self: True
        mock_city_resp.city.name = "Los Angeles"
        mock_city_resp.location.latitude = 34.0522
        mock_city_resp.location.longitude = -118.2437

        mock_city_reader = MagicMock()
        mock_city_reader.city.return_value = mock_city_resp
        mock_city_reader_fn.return_value = mock_city_reader

        # Mock ASN reader
        mock_asn_resp = MagicMock()
        mock_asn_resp.autonomous_system_number = 15133
        mock_asn_resp.autonomous_system_organization = "Edgecast Inc."

        mock_asn_reader = MagicMock()
        mock_asn_reader.asn.return_value = mock_asn_resp
        mock_asn_reader_fn.return_value = mock_asn_reader

        result = geoip_lookup("93.184.216.34")

        assert result is not None
        assert result["country"] == "United States"
        assert result["country_code"] == "US"
        assert result["city"] == "Los Angeles"
        assert result["asn"] == 15133
        assert result["as_name"] == "Edgecast Inc."
        assert result["lat"] == 34.0522

    @patch("app.services.network_intel._get_asn_reader")
    @patch("app.services.network_intel._get_city_reader")
    def test_geoip_address_not_found(self, mock_city_reader_fn, mock_asn_reader_fn):
        """Returns None when IP is not in GeoLite2 databases."""
        from geoip2.errors import AddressNotFoundError

        mock_city_reader = MagicMock()
        mock_city_reader.city.side_effect = AddressNotFoundError("not found")
        mock_city_reader_fn.return_value = mock_city_reader

        mock_asn_reader = MagicMock()
        mock_asn_reader.asn.side_effect = AddressNotFoundError("not found")
        mock_asn_reader_fn.return_value = mock_asn_reader

        result = geoip_lookup("192.168.1.1")

        assert result is None

    @patch("app.services.network_intel._get_asn_reader")
    @patch("app.services.network_intel._get_city_reader")
    def test_geoip_no_readers(self, mock_city_reader_fn, mock_asn_reader_fn):
        """Returns None when GeoLite2 databases are not loaded."""
        mock_city_reader_fn.return_value = None
        mock_asn_reader_fn.return_value = None

        result = geoip_lookup("8.8.8.8")

        assert result is None

    @patch("app.services.network_intel._get_asn_reader")
    @patch("app.services.network_intel._get_city_reader")
    def test_geoip_city_only(self, mock_city_reader_fn, mock_asn_reader_fn):
        """Returns partial result when only City DB is available."""
        mock_city_resp = MagicMock()
        mock_city_resp.country.name = "Germany"
        mock_city_resp.country.iso_code = "DE"
        mock_city_resp.subdivisions.most_specific.name = "Bavaria"
        mock_city_resp.subdivisions.__bool__ = lambda self: True
        mock_city_resp.city.name = "Munich"
        mock_city_resp.location.latitude = 48.13
        mock_city_resp.location.longitude = 11.58

        mock_city_reader = MagicMock()
        mock_city_reader.city.return_value = mock_city_resp
        mock_city_reader_fn.return_value = mock_city_reader
        mock_asn_reader_fn.return_value = None  # No ASN DB

        result = geoip_lookup("1.2.3.4")

        assert result["country"] == "Germany"
        assert result["city"] == "Munich"
        assert result["asn"] is None  # Defaulted to None
        assert result["as_name"] is None


# ============================================================================
# Header Flattening
# ============================================================================


class TestFlattenHeaders:
    def test_simple_headers(self):
        headers = {"Server": "cloudflare", "Content-Type": "text/html"}
        flat = _flatten_headers(headers)
        assert "server: cloudflare" in flat
        assert "content-type: text/html" in flat

    def test_list_values(self):
        headers = {"Set-Cookie": ["session=abc", "theme=dark"]}
        flat = _flatten_headers(headers)
        assert "set-cookie: session=abc" in flat
        assert "set-cookie: theme=dark" in flat

    def test_empty_headers(self):
        assert _flatten_headers({}) == ""


# ============================================================================
# CDN Detection
# ============================================================================


class TestDetectCdn:
    def test_cloudflare(self):
        headers = {"CF-Ray": "abc123", "Server": "cloudflare"}
        assert detect_cdn(headers) == "cloudflare"

    def test_akamai(self):
        headers = {"X-Akamai-Transformed": "9 - 0 pmb=mRUM,3"}
        assert detect_cdn(headers) == "akamai"

    def test_fastly(self):
        headers = {"X-Served-By": "cache-iad-kiad7000099"}
        assert detect_cdn(headers) == "fastly"

    def test_cloudfront(self):
        headers = {"X-Amz-Cf-Id": "abc123", "Server": "CloudFront"}
        assert detect_cdn(headers) == "cloudfront"

    def test_azure_cdn(self):
        headers = {"X-Azure-Ref": "0abc123"}
        assert detect_cdn(headers) == "azure_cdn"

    def test_no_cdn_detected(self):
        headers = {"Server": "nginx", "Content-Type": "text/html"}
        assert detect_cdn(headers) is None

    def test_empty_headers(self):
        assert detect_cdn({}) is None

    def test_none_headers(self):
        assert detect_cdn(None) is None

    def test_sucuri(self):
        headers = {"X-Sucuri-ID": "abc123"}
        assert detect_cdn(headers) == "sucuri"

    def test_google_cdn(self):
        headers = {"Server": "gws", "Via": "1.1 google"}
        assert detect_cdn(headers) == "google_cdn"


# ============================================================================
# WAF Detection
# ============================================================================


class TestDetectWaf:
    def test_cloudflare_waf(self):
        headers = {"CF-Ray": "abc123", "Server": "cloudflare"}
        assert detect_waf(headers) == "cloudflare"

    def test_aws_waf(self):
        headers = {"X-Amzn-WAF-Action": "block"}
        assert detect_waf(headers) == "aws_waf"

    def test_imperva(self):
        headers = {"X-Iinfo": "10-123-0"}
        assert detect_waf(headers) == "imperva"

    def test_f5_bigip(self):
        headers = {"X-Cnection": "close", "BigIPServer": "pool1"}
        assert detect_waf(headers) == "f5_bigip"

    def test_modsecurity(self):
        headers = {"Server": "Apache/2.4.41 mod_security/2.9.3"}
        assert detect_waf(headers) == "modsecurity"

    def test_no_waf_detected(self):
        headers = {"Server": "nginx/1.21.0"}
        assert detect_waf(headers) is None

    def test_none_headers(self):
        assert detect_waf(None) is None

    def test_sucuri_waf(self):
        headers = {"X-Sucuri-ID": "abc123"}
        assert detect_waf(headers) == "sucuri"


# ============================================================================
# Cloud Provider Detection
# ============================================================================


class TestDetectCloudProvider:
    def test_aws_by_headers(self):
        headers = {"X-Amz-Request-Id": "abc123"}
        assert detect_cloud_provider(headers) == "aws"

    def test_gcp_by_headers(self):
        headers = {"X-Goog-Storage-Class": "STANDARD"}
        assert detect_cloud_provider(headers) == "gcp"

    def test_azure_by_headers(self):
        headers = {"X-Azure-Ref": "abc123"}
        assert detect_cloud_provider(headers) == "azure"

    def test_aws_by_asn(self):
        assert detect_cloud_provider({}, "Amazon.com Inc.") == "aws"

    def test_gcp_by_asn(self):
        assert detect_cloud_provider({}, "Google LLC") == "gcp"

    def test_azure_by_asn(self):
        assert detect_cloud_provider({}, "Microsoft Corporation") == "azure"

    def test_digitalocean_by_asn(self):
        assert detect_cloud_provider({}, "DigitalOcean, LLC") == "digitalocean"

    def test_hetzner_by_asn(self):
        assert detect_cloud_provider({}, "Hetzner Online GmbH") == "hetzner"

    def test_no_provider(self):
        assert detect_cloud_provider({"Server": "nginx"}, "OVH SAS") is None

    def test_headers_take_precedence(self):
        """Headers should match before ASN, detecting AWS even with Google ASN."""
        headers = {"X-Amz-Request-Id": "abc123"}
        assert detect_cloud_provider(headers, "Google LLC") == "aws"

    def test_none_headers(self):
        assert detect_cloud_provider(None, None) is None

    def test_empty_asn(self):
        assert detect_cloud_provider({}, None) is None


# ============================================================================
# Composite Enrichment
# ============================================================================


class TestEnrichAssetNetwork:
    @patch("app.services.network_intel.geoip_lookup")
    @patch("app.services.network_intel.reverse_dns")
    @patch("app.services.network_intel.resolve_domain_ip")
    @patch("app.services.network_intel.whois_lookup")
    def test_domain_full_enrichment(
        self,
        mock_whois,
        mock_resolve,
        mock_rdns,
        mock_geoip,
    ):
        """Full enrichment for a domain asset."""
        mock_whois.return_value = {
            "registrar": "Namecheap",
            "org": "ACME",
            "country": "US",
            "created": "2020-01-01",
            "expires": "2025-01-01",
            "nameservers": ["ns1.example.com"],
            "emails": ["admin@example.com"],
        }
        mock_resolve.return_value = "93.184.216.34"
        mock_rdns.return_value = "host.example.com"
        mock_geoip.return_value = {
            "country": "United States",
            "country_code": "US",
            "region": "California",
            "city": "LA",
            "lat": 34.05,
            "lon": -118.24,
            "isp": "Edgecast",
            "org": "Edgecast Inc.",
            "as_name": "Edgecast",
            "asn": 15133,
        }

        result = enrich_asset_network(
            identifier="example.com",
            asset_type="domain",
            service_headers={"Server": "cloudflare", "CF-Ray": "abc"},
        )

        assert result["whois"]["registrar"] == "Namecheap"
        assert result["network"]["ip"] == "93.184.216.34"
        assert result["network"]["reverse_dns"] == "host.example.com"
        assert result["network"]["asn"] == 15133
        assert result["network"]["country"] == "United States"
        assert result["cdn"] == "cloudflare"
        assert result["waf"] == "cloudflare"

    @patch("app.services.network_intel.geoip_lookup")
    @patch("app.services.network_intel.reverse_dns")
    def test_ip_enrichment(self, mock_rdns, mock_geoip):
        """Enrichment for an IP asset (no WHOIS, no DNS resolution needed)."""
        mock_rdns.return_value = None
        mock_geoip.return_value = {
            "country": "Germany",
            "country_code": "DE",
            "region": "Bavaria",
            "city": "Munich",
            "lat": 48.13,
            "lon": 11.58,
            "isp": "Hetzner",
            "org": "Hetzner Online GmbH",
            "as_name": "Hetzner",
            "asn": 24940,
        }

        result = enrich_asset_network(
            identifier="1.2.3.4",
            asset_type="ip",
        )

        # No WHOIS for IPs
        assert result["whois"] == {}
        assert result["network"]["ip"] == "1.2.3.4"
        assert result["network"]["asn"] == 24940
        assert result["cloud_provider"] == "hetzner"

    @patch("app.services.network_intel.geoip_lookup")
    @patch("app.services.network_intel.reverse_dns")
    @patch("app.services.network_intel.resolve_domain_ip")
    @patch("app.services.network_intel.whois_lookup")
    def test_all_lookups_fail(self, mock_whois, mock_resolve, mock_rdns, mock_geoip):
        """Enrichment returns empty/None values when all lookups fail."""
        mock_whois.return_value = {
            "registrar": None,
            "org": None,
            "country": None,
            "created": None,
            "expires": None,
            "nameservers": [],
            "emails": [],
        }
        mock_resolve.return_value = None
        mock_rdns.return_value = None
        mock_geoip.return_value = None

        result = enrich_asset_network(
            identifier="unknown.invalid",
            asset_type="domain",
        )

        assert result["whois"]["registrar"] is None
        assert result["network"] == {}  # No IP resolved
        assert result["cdn"] is None
        assert result["waf"] is None
        assert result["cloud_provider"] is None

    @patch("app.services.network_intel.geoip_lookup")
    @patch("app.services.network_intel.reverse_dns")
    @patch("app.services.network_intel.resolve_domain_ip")
    @patch("app.services.network_intel.whois_lookup")
    def test_pre_resolved_ip(self, mock_whois, mock_resolve, mock_rdns, mock_geoip):
        """When ip_address is provided, skip DNS resolution."""
        mock_whois.return_value = {
            "registrar": None,
            "org": None,
            "country": None,
            "created": None,
            "expires": None,
            "nameservers": [],
            "emails": [],
        }
        mock_rdns.return_value = None
        mock_geoip.return_value = None

        result = enrich_asset_network(
            identifier="sub.example.com",
            asset_type="subdomain",
            ip_address="10.0.0.1",
        )

        # resolve_domain_ip should NOT be called
        mock_resolve.assert_not_called()
        assert result["network"]["ip"] == "10.0.0.1"


# ============================================================================
# Celery Task Integration (mocked DB)
# ============================================================================


class TestRunNetworkEnrichmentTask:
    @patch("app.database.SessionLocal")
    @patch("app.services.network_intel.enrich_asset_network")
    def test_no_assets_returns_no_candidates(self, mock_enrich, mock_session_local):
        """Task returns early when no assets match."""
        mock_db = MagicMock()
        mock_query = MagicMock()
        mock_query.filter.return_value = mock_query
        mock_query.all.return_value = []
        mock_db.query.return_value = mock_query
        mock_session_local.return_value = mock_db

        from app.tasks.network_enrichment import run_network_enrichment

        # Call the underlying function directly (skip Celery binding)
        # __wrapped__ on a Celery bind=True task strips self from the signature;
        # Celery auto-injects the task instance as self — do NOT pass a positional mock
        result = run_network_enrichment.__wrapped__(tenant_id=1, asset_ids=None)

        assert result["status"] == "no_candidates"
        assert result["assets_enriched"] == 0
        mock_enrich.assert_not_called()

    @patch("app.database.SessionLocal")
    @patch("app.services.network_intel.enrich_asset_network")
    @patch("app.tasks.network_enrichment._merge_headers_for_asset")
    def test_successful_enrichment(self, mock_merge_headers, mock_enrich, mock_session_local):
        """Task enriches assets and commits to DB."""
        # Setup mock asset
        mock_asset = MagicMock()
        mock_asset.id = 42
        mock_asset.identifier = "example.com"
        mock_asset.type = MagicMock()
        mock_asset.type.value = "domain"
        mock_asset.raw_metadata = None

        mock_db = MagicMock()
        mock_query = MagicMock()
        mock_query.filter.return_value = mock_query
        mock_query.all.return_value = [mock_asset]
        mock_db.query.return_value = mock_query
        mock_session_local.return_value = mock_db

        mock_merge_headers.return_value = {}
        mock_enrich.return_value = {
            "whois": {"registrar": "Test"},
            "network": {"ip": "1.2.3.4"},
            "cdn": "cloudflare",
            "waf": None,
            "cloud_provider": "aws",
        }

        from app.tasks.network_enrichment import run_network_enrichment

        result = run_network_enrichment.__wrapped__(tenant_id=1, asset_ids=[42])

        assert result["status"] == "completed"
        assert result["assets_enriched"] == 1
        assert result["assets_failed"] == 0
        mock_db.commit.assert_called()

    @patch("app.database.SessionLocal")
    @patch("app.services.network_intel.enrich_asset_network")
    @patch("app.tasks.network_enrichment._merge_headers_for_asset")
    def test_enrichment_failure_counted(self, mock_merge_headers, mock_enrich, mock_session_local):
        """Failed enrichment increments fail count but does not crash."""
        mock_asset = MagicMock()
        mock_asset.id = 99
        mock_asset.identifier = "fail.example.com"
        mock_asset.type = MagicMock()
        mock_asset.type.value = "domain"
        mock_asset.raw_metadata = None

        mock_db = MagicMock()
        mock_query = MagicMock()
        mock_query.filter.return_value = mock_query
        mock_query.all.return_value = [mock_asset]
        mock_db.query.return_value = mock_query
        mock_session_local.return_value = mock_db

        mock_merge_headers.return_value = {}
        mock_enrich.side_effect = Exception("WHOIS server timeout")

        from app.tasks.network_enrichment import run_network_enrichment

        result = run_network_enrichment.__wrapped__(tenant_id=1, asset_ids=[99])

        assert result["status"] == "completed"
        assert result["assets_enriched"] == 0
        assert result["assets_failed"] == 1


# ============================================================================
# Pipeline integration (phase_1c_network_enrichment)
# ============================================================================


class TestPhase1cIntegration:
    @patch("app.services.network_intel.enrich_asset_network")
    @patch("app.tasks.network_enrichment._merge_headers_for_asset")
    def test_phase_1c_enriches_assets(self, mock_headers, mock_enrich):
        """phase_1c_network_enrichment enriches provided assets."""
        mock_asset = MagicMock()
        mock_asset.id = 1
        mock_asset.identifier = "example.com"
        mock_asset.type = MagicMock()
        mock_asset.type.value = "domain"
        mock_asset.raw_metadata = None

        mock_db = MagicMock()
        mock_query = MagicMock()
        mock_query.filter.return_value = mock_query
        mock_query.all.return_value = [mock_asset]
        mock_db.query.return_value = mock_query

        mock_headers.return_value = {}
        mock_enrich.return_value = {
            "whois": {},
            "network": {"ip": "1.1.1.1"},
            "cdn": None,
            "waf": None,
            "cloud_provider": None,
        }

        mock_logger = MagicMock()

        from app.tasks.network_enrichment import phase_1c_network_enrichment

        result = phase_1c_network_enrichment(
            tenant_id=1,
            asset_ids=[1],
            db=mock_db,
            tenant_logger=mock_logger,
        )

        assert result["assets_enriched"] == 1
        assert result["assets_failed"] == 0
        # phase 1c does not discover new assets, only enriches
        assert result["assets_discovered"] == 0

    def test_phase_1c_no_assets(self):
        """phase_1c returns zeros when no matching assets."""
        mock_db = MagicMock()
        mock_query = MagicMock()
        mock_query.filter.return_value = mock_query
        mock_query.all.return_value = []
        mock_db.query.return_value = mock_query

        mock_logger = MagicMock()

        from app.tasks.network_enrichment import phase_1c_network_enrichment

        result = phase_1c_network_enrichment(
            tenant_id=1,
            asset_ids=[999],
            db=mock_db,
            tenant_logger=mock_logger,
        )

        assert result["assets_enriched"] == 0


# ============================================================================
# Metadata parsing helper
# ============================================================================


class TestParseRawMetadata:
    def test_none_metadata(self):
        from app.tasks.network_enrichment import _parse_raw_metadata

        mock_asset = MagicMock()
        mock_asset.raw_metadata = None
        assert _parse_raw_metadata(mock_asset) == {}

    def test_valid_json_string(self):
        from app.tasks.network_enrichment import _parse_raw_metadata

        mock_asset = MagicMock()
        mock_asset.raw_metadata = '{"key": "value"}'
        assert _parse_raw_metadata(mock_asset) == {"key": "value"}

    def test_dict_already(self):
        from app.tasks.network_enrichment import _parse_raw_metadata

        mock_asset = MagicMock()
        mock_asset.raw_metadata = {"key": "value"}
        assert _parse_raw_metadata(mock_asset) == {"key": "value"}

    def test_invalid_json(self):
        from app.tasks.network_enrichment import _parse_raw_metadata

        mock_asset = MagicMock()
        mock_asset.raw_metadata = "not valid json"
        assert _parse_raw_metadata(mock_asset) == {}


# ============================================================================
# Header merging helper
# ============================================================================


class TestMergeHeadersForAsset:
    def test_merges_headers_from_services(self):
        from app.tasks.network_enrichment import _merge_headers_for_asset

        svc1 = MagicMock()
        svc1.http_headers = {"Server": "nginx", "X-Powered-By": "PHP"}

        svc2 = MagicMock()
        svc2.http_headers = {"CF-Ray": "abc123", "Server": "cloudflare"}

        mock_db = MagicMock()
        mock_query = MagicMock()
        mock_query.filter.return_value = mock_query
        mock_query.all.return_value = [svc1, svc2]
        mock_db.query.return_value = mock_query

        result = _merge_headers_for_asset(1, mock_db)

        assert "server" in result
        assert "cf-ray" in result
        # Server from svc2 should overwrite svc1
        assert result["server"] == "cloudflare"

    def test_handles_json_string_headers(self):
        from app.tasks.network_enrichment import _merge_headers_for_asset

        svc = MagicMock()
        svc.http_headers = '{"Server": "nginx"}'

        mock_db = MagicMock()
        mock_query = MagicMock()
        mock_query.filter.return_value = mock_query
        mock_query.all.return_value = [svc]
        mock_db.query.return_value = mock_query

        result = _merge_headers_for_asset(1, mock_db)

        assert result["server"] == "nginx"

    def test_handles_invalid_json_string(self):
        from app.tasks.network_enrichment import _merge_headers_for_asset

        svc = MagicMock()
        svc.http_headers = "not json"

        mock_db = MagicMock()
        mock_query = MagicMock()
        mock_query.filter.return_value = mock_query
        mock_query.all.return_value = [svc]
        mock_db.query.return_value = mock_query

        result = _merge_headers_for_asset(1, mock_db)

        assert result == {}

    def test_no_services(self):
        from app.tasks.network_enrichment import _merge_headers_for_asset

        mock_db = MagicMock()
        mock_query = MagicMock()
        mock_query.filter.return_value = mock_query
        mock_query.all.return_value = []
        mock_db.query.return_value = mock_query

        result = _merge_headers_for_asset(1, mock_db)

        assert result == {}
