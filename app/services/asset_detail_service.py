"""Asset detail aggregation service.

Extracts heavy DB queries and serialization logic from the assets router
to keep the router thin (request -> service -> response).
"""

from __future__ import annotations

import json
import logging
from typing import Optional

from sqlalchemy.orm import Session

from app.api.schemas.asset import AssetResponse
from app.models.database import Asset, AssetType, Service, Finding
from app.models.enrichment import Certificate, Endpoint

logger = logging.getLogger(__name__)


# Well-known cloud / CDN IP prefixes (first two octets) for heuristic detection.
# This is intentionally simplified; production systems would use MaxMind or
# cloud provider IP range JSON feeds.
_CLOUD_HINTS: dict[str, list[str]] = {
    "AWS": ["3.", "13.", "15.", "18.", "34.", "35.", "44.", "46.", "50.", "52.", "54.", "99.", "100."],
    "GCP": ["34.", "35.", "104.", "108.", "142."],
    "Azure": ["13.", "20.", "23.", "40.", "51.", "52.", "65.", "104."],
    "Cloudflare": [
        "104.16.",
        "104.17.",
        "104.18.",
        "104.19.",
        "104.20.",
        "104.21.",
        "104.22.",
        "104.23.",
        "104.24.",
        "104.25.",
        "172.64.",
        "172.65.",
        "172.66.",
        "172.67.",
        "162.158.",
        "141.101.",
    ],
    "Akamai": ["23.", "104.", "184."],
}


class AssetDetailService:
    """Aggregates asset detail data (services, certs, endpoints, findings,
    DNS info, tech stack, summary) for the GET /{asset_id} endpoint."""

    def __init__(self, db: Session):
        self.db = db

    def get_detail(self, tenant_id: int, asset_id: int) -> dict:
        """Fetch asset with all enrichment data (services, certs, endpoints, findings, screenshots).

        Raises:
            None -- returns None when the asset is not found (caller raises 404).
        """
        asset = self.db.query(Asset).filter(Asset.id == asset_id, Asset.tenant_id == tenant_id).first()

        if not asset:
            return None

        # Query certificates and endpoints directly (bypassing broken relationships)
        certificates = self.db.query(Certificate).filter(Certificate.asset_id == asset_id).all()

        endpoints = (
            self.db.query(Endpoint)
            .filter(Endpoint.asset_id == asset_id)
            .order_by(Endpoint.last_seen.desc())
            .limit(100)
            .all()
        )

        # Build base response
        response_data = AssetResponse.model_validate(asset).model_dump()

        # ------------------------------------------------------------------ #
        # Services serialization
        # ------------------------------------------------------------------ #
        response_data["services"] = [
            {
                "id": s.id,
                "asset_id": s.asset_id,
                "port": s.port,
                "protocol": s.protocol,
                "product": s.product,
                "version": s.version,
                "tls_fingerprint": s.tls_fingerprint,
                "http_title": s.http_title,
                "http_status": s.http_status,
                "technologies": s.technologies,
                "web_server": s.web_server,
                "has_tls": s.has_tls,
                "tls_version": s.tls_version,
                "http_technologies": s.http_technologies,
                "response_time_ms": s.response_time_ms,
                "content_length": s.content_length,
                "redirect_url": s.redirect_url,
                "enrichment_source": s.enrichment_source,
                "enriched_at": s.enriched_at.isoformat() if s.enriched_at else None,
                "first_seen": s.first_seen.isoformat() if s.first_seen else None,
                "last_seen": s.last_seen.isoformat() if s.last_seen else None,
            }
            for s in asset.services
        ]

        # ------------------------------------------------------------------ #
        # Certificates serialization (queried directly)
        # ------------------------------------------------------------------ #
        response_data["certificates"] = [
            {
                "id": c.id,
                "subject_cn": c.subject_cn,
                "issuer": c.issuer,
                "serial_number": c.serial_number,
                "not_before": c.not_before.isoformat() if c.not_before else None,
                "not_after": c.not_after.isoformat() if c.not_after else None,
                "is_expired": c.is_expired,
                "days_until_expiry": c.days_until_expiry,
                "san_domains": c.san_domains,
                "signature_algorithm": c.signature_algorithm,
                "public_key_algorithm": c.public_key_algorithm,
                "public_key_bits": c.public_key_bits,
                "is_self_signed": c.is_self_signed,
                "is_wildcard": c.is_wildcard,
                "has_weak_signature": c.has_weak_signature,
                "first_seen": c.first_seen.isoformat() if c.first_seen else None,
                "last_seen": c.last_seen.isoformat() if c.last_seen else None,
            }
            for c in certificates
        ]

        # ------------------------------------------------------------------ #
        # Endpoints serialization (queried directly, max 100)
        # ------------------------------------------------------------------ #
        response_data["endpoints"] = [
            {
                "id": e.id,
                "url": e.url,
                "path": e.path,
                "method": e.method,
                "status_code": e.status_code,
                "content_type": e.content_type,
                "endpoint_type": e.endpoint_type,
                "is_api": e.is_api,
                "is_external": e.is_external,
                "depth": e.depth,
            }
            for e in endpoints
        ]

        # ------------------------------------------------------------------ #
        # Findings serialization (with fingerprint + occurrence_count)
        # ------------------------------------------------------------------ #
        response_data["findings"] = [
            {
                "id": f.id,
                "asset_id": f.asset_id,
                "source": f.source,
                "template_id": f.template_id,
                "name": f.name,
                "severity": f.severity.value if hasattr(f.severity, "value") else str(f.severity),
                "cvss_score": f.cvss_score,
                "cve_id": f.cve_id,
                "status": f.status.value if hasattr(f.status, "value") else str(f.status),
                "matched_at": f.matched_at,
                "host": f.host,
                "matcher_name": f.matcher_name,
                "fingerprint": f.fingerprint,
                "occurrence_count": f.occurrence_count,
                "first_seen": f.first_seen.isoformat() if f.first_seen else None,
                "last_seen": f.last_seen.isoformat() if f.last_seen else None,
            }
            for f in asset.findings
        ]

        # ------------------------------------------------------------------ #
        # Events serialization (last 50 by created_at desc)
        # ------------------------------------------------------------------ #
        response_data["events"] = [
            {
                "id": e.id,
                "asset_id": e.asset_id,
                "kind": e.kind.value if hasattr(e.kind, "value") else str(e.kind),
                "payload": e.payload,
                "created_at": e.created_at.isoformat() if e.created_at else None,
            }
            for e in sorted(asset.events, key=lambda e: e.created_at, reverse=True)[:50]
        ]

        # ------------------------------------------------------------------ #
        # Technology stack aggregation
        # ------------------------------------------------------------------ #
        tech_stack: set[str] = set()
        for s in asset.services:
            # technologies is a Text column that may hold a JSON-encoded list
            if s.technologies:
                try:
                    techs = json.loads(s.technologies) if isinstance(s.technologies, str) else s.technologies
                    if isinstance(techs, list):
                        tech_stack.update(str(t) for t in techs)
                except (ValueError, TypeError):
                    pass
            # http_technologies is a native JSON column (list)
            if s.http_technologies and isinstance(s.http_technologies, list):
                tech_stack.update(str(t) for t in s.http_technologies)
            if s.web_server:
                tech_stack.add(s.web_server)

        response_data["tech_stack"] = sorted(tech_stack)

        # ------------------------------------------------------------------ #
        # HTTP response info (only services with HTTP data)
        # ------------------------------------------------------------------ #
        http_info_list = []
        for s in asset.services:
            if s.http_status or s.http_title:
                # Parse per-service technologies
                svc_techs: list[str] = []
                if s.technologies:
                    try:
                        parsed = json.loads(s.technologies) if isinstance(s.technologies, str) else s.technologies
                        if isinstance(parsed, list):
                            svc_techs = [str(t) for t in parsed]
                    except (ValueError, TypeError):
                        pass
                if s.http_technologies and isinstance(s.http_technologies, list):
                    svc_techs.extend(str(t) for t in s.http_technologies)

                http_info_list.append(
                    {
                        "port": s.port,
                        "title": s.http_title,
                        "status_code": s.http_status,
                        "web_server": s.web_server,
                        "technologies": svc_techs,
                        "response_time_ms": s.response_time_ms,
                        "redirect_url": s.redirect_url,
                        "has_tls": s.has_tls,
                        "tls_version": s.tls_version,
                    }
                )
        response_data["http_info"] = http_info_list

        # ------------------------------------------------------------------ #
        # DNS / Network intelligence
        # ------------------------------------------------------------------ #
        dns_info = self._build_dns_info(asset)
        response_data["dns_info"] = dns_info

        # ------------------------------------------------------------------ #
        # Summary statistics
        # ------------------------------------------------------------------ #
        severity_counts: dict[str, int] = {}
        for f in asset.findings:
            sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        open_findings = sum(
            1 for f in asset.findings if (f.status.value if hasattr(f.status, "value") else str(f.status)) == "open"
        )

        open_ports = sorted(set(s.port for s in asset.services if s.port is not None))

        response_data["summary"] = {
            "total_services": len(asset.services),
            "total_findings": len(asset.findings),
            "total_certificates": len(certificates),
            "total_endpoints": len(endpoints),
            "open_ports": open_ports,
            "has_tls": any(s.has_tls for s in asset.services),
            "has_http": any(s.port in (80, 443, 8080, 8443) for s in asset.services if s.port is not None),
            "severity_breakdown": severity_counts,
            "open_findings": open_findings,
        }

        # ------------------------------------------------------------------ #
        # SERVICE-type asset: resolve parent and inherit data
        # ------------------------------------------------------------------ #
        if asset.type and asset.type.value == "service" and not response_data["services"]:
            self._enrich_service_asset(asset, response_data)

        return response_data

    def _enrich_service_asset(self, asset: Asset, response_data: dict) -> None:
        """
        For SERVICE-type assets (e.g. smtp.l.autistici.org:5269), find the parent
        subdomain/domain and pull the relevant service record + findings.

        Modifies response_data in place.
        """
        identifier = asset.identifier or ""

        # Parse hostname and port from identifier (e.g. "host.example.com:5269")
        if ":" in identifier:
            hostname = identifier.rsplit(":", 1)[0]
            try:
                target_port = int(identifier.rsplit(":", 1)[1])
            except ValueError:
                target_port = None
        else:
            hostname = identifier
            target_port = None

        # Find parent asset (subdomain, domain, or IP matching hostname)
        parent = (
            self.db.query(Asset)
            .filter(
                Asset.tenant_id == asset.tenant_id,
                Asset.identifier == hostname,
                Asset.type.in_([AssetType.SUBDOMAIN, AssetType.DOMAIN, AssetType.IP]),
            )
            .first()
        )

        if not parent:
            return

        # Add parent_asset reference
        response_data["parent_asset"] = {
            "id": parent.id,
            "identifier": parent.identifier,
            "type": parent.type.value if hasattr(parent.type, "value") else str(parent.type),
            "risk_score": parent.risk_score,
            "is_active": parent.is_active,
        }

        # Pull the matching service from the parent
        matching_service = None
        for s in parent.services:
            if target_port is not None and s.port == target_port:
                matching_service = s
                break

        if matching_service:
            response_data["services"] = [
                {
                    "id": matching_service.id,
                    "asset_id": matching_service.asset_id,
                    "port": matching_service.port,
                    "protocol": matching_service.protocol,
                    "product": matching_service.product,
                    "version": matching_service.version,
                    "tls_fingerprint": matching_service.tls_fingerprint,
                    "http_title": matching_service.http_title,
                    "http_status": matching_service.http_status,
                    "technologies": matching_service.technologies,
                    "web_server": matching_service.web_server,
                    "has_tls": matching_service.has_tls,
                    "tls_version": matching_service.tls_version,
                    "http_technologies": matching_service.http_technologies,
                    "response_time_ms": matching_service.response_time_ms,
                    "content_length": matching_service.content_length,
                    "redirect_url": matching_service.redirect_url,
                    "enrichment_source": matching_service.enrichment_source,
                    "enriched_at": matching_service.enriched_at.isoformat() if matching_service.enriched_at else None,
                    "first_seen": matching_service.first_seen.isoformat() if matching_service.first_seen else None,
                    "last_seen": matching_service.last_seen.isoformat() if matching_service.last_seen else None,
                }
            ]

        # Pull parent's certificates
        parent_certs = self.db.query(Certificate).filter(Certificate.asset_id == parent.id).all()
        if parent_certs:
            response_data["certificates"] = [
                {
                    "id": c.id,
                    "subject_cn": c.subject_cn,
                    "issuer": c.issuer,
                    "serial_number": c.serial_number,
                    "not_before": c.not_before.isoformat() if c.not_before else None,
                    "not_after": c.not_after.isoformat() if c.not_after else None,
                    "is_expired": c.is_expired,
                    "days_until_expiry": c.days_until_expiry,
                    "san_domains": c.san_domains,
                    "is_self_signed": c.is_self_signed,
                    "is_wildcard": c.is_wildcard,
                    "has_weak_signature": c.has_weak_signature,
                }
                for c in parent_certs
            ]

        # Pull parent's findings
        parent_findings = list(parent.findings)
        if parent_findings:
            response_data["findings"] = [
                {
                    "id": f.id,
                    "asset_id": f.asset_id,
                    "source": f.source,
                    "template_id": f.template_id,
                    "name": f.name,
                    "severity": f.severity.value if hasattr(f.severity, "value") else str(f.severity),
                    "cvss_score": f.cvss_score,
                    "cve_id": f.cve_id,
                    "status": f.status.value if hasattr(f.status, "value") else str(f.status),
                    "matched_at": f.matched_at,
                    "host": f.host,
                    "matcher_name": f.matcher_name,
                    "fingerprint": f.fingerprint,
                    "occurrence_count": f.occurrence_count,
                    "first_seen": f.first_seen.isoformat() if f.first_seen else None,
                    "last_seen": f.last_seen.isoformat() if f.last_seen else None,
                }
                for f in parent_findings
            ]

        # Pull DNS info from parent
        response_data["dns_info"] = self._build_dns_info(parent)

        # Pull tech stack from parent services
        parent_tech: set[str] = set()
        for s in parent.services:
            if s.technologies:
                try:
                    techs = json.loads(s.technologies) if isinstance(s.technologies, str) else s.technologies
                    if isinstance(techs, list):
                        parent_tech.update(str(t) for t in techs)
                except (ValueError, TypeError):
                    pass
            if s.http_technologies and isinstance(s.http_technologies, list):
                parent_tech.update(str(t) for t in s.http_technologies)
            if s.web_server:
                parent_tech.add(s.web_server)
        response_data["tech_stack"] = sorted(parent_tech)

        # Recalculate summary with parent data
        svc_list = response_data.get("services", [])
        find_list = response_data.get("findings", [])
        cert_list = response_data.get("certificates", [])

        parent_open_ports = sorted(set(s.port for s in parent.services if s.port is not None))

        parent_severity_counts: dict[str, int] = {}
        parent_open_findings = 0
        for f in parent_findings:
            sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
            parent_severity_counts[sev] = parent_severity_counts.get(sev, 0) + 1
            st = f.status.value if hasattr(f.status, "value") else str(f.status)
            if st == "open":
                parent_open_findings += 1

        response_data["summary"] = {
            "total_services": len(parent.services),
            "total_findings": len(parent_findings),
            "total_certificates": len(cert_list),
            "total_endpoints": 0,
            "open_ports": parent_open_ports,
            "has_tls": any(s.has_tls for s in parent.services),
            "has_http": any(s.port in (80, 443, 8080, 8443) for s in parent.services if s.port is not None),
            "severity_breakdown": parent_severity_counts,
            "open_findings": parent_open_findings,
        }

    def _build_dns_info(self, asset: Asset) -> dict:
        """
        Build DNS / network intelligence section from asset data.

        This function never makes external network calls. All data is derived
        from the asset's raw_metadata JSON field, its services, and simple
        heuristics like cloud provider detection by IP range patterns.
        """
        dns_info: dict = {
            "resolved_ips": [],
            "reverse_dns": None,
            "whois_summary": None,
            "asn_info": None,
            "geo_info": None,
            "cloud_provider": None,
        }

        # Parse raw_metadata safely
        raw_meta: dict = {}
        if asset.raw_metadata:
            try:
                raw_meta = json.loads(asset.raw_metadata) if isinstance(asset.raw_metadata, str) else {}
            except (ValueError, TypeError):
                raw_meta = {}

        # Resolved IPs: from raw_metadata or from asset identifier if type is IP
        resolved_ips = raw_meta.get("resolved_ips") or raw_meta.get("a_records") or []
        if not resolved_ips and asset.type and asset.type.value == "ip":
            resolved_ips = [asset.identifier]
        # Also gather IPs from services with numeric identifiers or metadata
        if not resolved_ips:
            for s in asset.services:
                if s.product and s.product.startswith(("ip:", "IP:")):
                    resolved_ips.append(s.product.split(":", 1)[1].strip())
        dns_info["resolved_ips"] = list(set(resolved_ips))

        # Network enrichment data (GeoIP, rDNS, ASN -- from Phase 1c)
        network = raw_meta.get("network") or {}

        # Reverse DNS from network enrichment or legacy keys
        dns_info["reverse_dns"] = (
            network.get("reverse_dns") or raw_meta.get("rdns") or raw_meta.get("reverse_dns") or raw_meta.get("ptr")
        )

        # Resolved IPs: also use network.ip if available
        if not dns_info["resolved_ips"] and network.get("ip"):
            dns_info["resolved_ips"] = [network["ip"]]

        # WHOIS summary
        whois = raw_meta.get("whois") or raw_meta.get("whois_summary")
        if whois:
            dns_info["whois_summary"] = whois

        # ASN info (from network enrichment or legacy keys)
        asn = raw_meta.get("asn") or raw_meta.get("asn_info")
        if not asn and network.get("asn"):
            asn = {
                "asn": network.get("asn"),
                "org": network.get("asn_org"),
                "country": network.get("country"),
            }
        if asn:
            dns_info["asn_info"] = asn

        # GeoIP info (country, city, lat/lon, ISP -- from MaxMind GeoLite2)
        if network.get("country") or network.get("lat"):
            dns_info["geo_info"] = {
                "country": network.get("country"),
                "country_code": network.get("country_code"),
                "region": network.get("region"),
                "city": network.get("city"),
                "lat": network.get("lat"),
                "lon": network.get("lon"),
                "isp": network.get("isp"),
            }

        # Cloud provider detection from raw_metadata or heuristic on IPs
        cloud = raw_meta.get("cloud_provider") or raw_meta.get("cdn")
        if not cloud:
            cloud = self._detect_cloud_provider(dns_info["resolved_ips"], asset)
        dns_info["cloud_provider"] = cloud

        return dns_info

    def _detect_cloud_provider(self, ips: list[str], asset: Asset) -> Optional[str]:
        """
        Heuristic cloud provider detection based on IP prefix matching and
        service HTTP headers (Server, Via, X-Served-By).

        Returns the provider name or None.
        """
        # Check service headers first (most reliable signal)
        for s in asset.services:
            headers = s.http_headers if hasattr(s, "http_headers") and s.http_headers else {}
            if isinstance(headers, dict):
                header_str = " ".join(str(v) for v in headers.values()).lower()
                if "cloudflare" in header_str:
                    return "Cloudflare"
                if "akamai" in header_str or "akamaighost" in header_str:
                    return "Akamai"
                if "amazons3" in header_str or "cloudfront" in header_str or "awselb" in header_str:
                    return "AWS"
                if "gws" in header_str or "google" in header_str:
                    return "GCP"
                if "microsoft" in header_str or "azure" in header_str:
                    return "Azure"

            # Also check web_server field
            if s.web_server:
                ws = s.web_server.lower()
                if "cloudflare" in ws:
                    return "Cloudflare"
                if "akamai" in ws:
                    return "Akamai"

        # Fallback: match on IP prefixes (Cloudflare first because its prefixes
        # are more specific and overlap with generic cloud ranges)
        for ip in ips:
            if not ip:
                continue
            # Check Cloudflare first (more specific prefixes)
            for prefix in _CLOUD_HINTS.get("Cloudflare", []):
                if ip.startswith(prefix):
                    return "Cloudflare"
            for prefix in _CLOUD_HINTS.get("Akamai", []):
                if ip.startswith(prefix):
                    # Akamai prefixes are broad; only match if not already matched
                    pass
            for provider in ("AWS", "GCP", "Azure"):
                for prefix in _CLOUD_HINTS.get(provider, []):
                    if ip.startswith(prefix):
                        return provider

        return None
