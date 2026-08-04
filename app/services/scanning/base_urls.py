"""Base-URL construction for a set of assets (Sprint 3, step 3b-2b).

The per-asset base URLs the HTTP-stock pass scans — derived from the asset's web services (scheme
from the TLS flag + port, not the transport ``protocol``), with a hostname fallback for domains /
subdomains without services. Extracted so the http_endpoint pass can drop those exact base URLs from
its endpoint candidate set (matching odd ports like :8080/:8443, not just :80/:443).

NOTE: ``run_nuclei_scan`` still builds the same URLs inline today; adopting this helper there too
(follow-up) would remove the last duplication. Keeping it out of that merged path here avoids any
behaviour risk to the http_stock pass while the endpoint feature is still flag-gated OFF.
"""

from __future__ import annotations

from typing import Sequence

from app.models.database import AssetType
from app.repositories.service_repository import ServiceRepository


def build_base_urls_by_asset(db, assets: Sequence) -> dict[int, list[str]]:
    """``{asset_id: [base_url, ...]}`` — the same construction ``run_nuclei_scan`` uses."""
    service_repo = ServiceRepository(db)
    urls_by_asset: dict[int, list[str]] = {}
    for asset in assets:
        web_services = service_repo.get_web_services(asset.id, only_live=True) or service_repo.get_web_services(
            asset.id, only_live=False
        )
        for service in web_services:
            port = service.port
            if service.has_tls or port in (443, 8443):
                scheme = "https"
            elif port in (80, 8080):
                scheme = "http"
            elif service.protocol in ("http", "https"):
                scheme = service.protocol
            else:
                scheme = "https" if port == 443 else "http"
            url = f"{scheme}://{asset.identifier}" if port in (80, 443) else f"{scheme}://{asset.identifier}:{port}"
            urls_by_asset.setdefault(asset.id, []).append(url)
        if asset.id not in urls_by_asset and asset.type in (AssetType.DOMAIN, AssetType.SUBDOMAIN):
            urls_by_asset[asset.id] = [f"https://{asset.identifier}", f"http://{asset.identifier}"]
    return urls_by_asset


def build_base_urls(db, assets: Sequence) -> list[str]:
    """Flat list of the base URLs across ``assets`` (order-stable per asset)."""
    out: list[str] = []
    for urls in build_base_urls_by_asset(db, assets).values():
        out.extend(urls)
    return out
