"""Origin-server discovery for WAF/CDN-fronted hosts.

When a web host sits behind a WAF/CDN (Cloudflare, Sucuri, Akamai, ...), the
protection is only effective if the real origin IP is not directly reachable.
If the origin answers HTTP for the fronted hostname on a public IP, an attacker
can bypass the WAF entirely by talking to the origin directly.

WAF/CDN detection already runs (Phase 5b / cdncheck populates ``Asset.waf_name``).
This module adds the missing half: for each WAF-fronted asset it gathers origin
*candidate* IPs from data already in the DB (sibling non-fronted hosts on the
same registrable domain, resolved A records) and verifies each by issuing a
direct request to the IP carrying the fronted ``Host`` header.

Findings are tagged ``presumptive`` — a direct HTTP answer strongly suggests an
exposed origin but is not proof the content is identical to the protected site,
so it is flagged for validation rather than asserted (see the confidence model
shipped with the finding-confidence feature).
"""

from __future__ import annotations

import ipaddress
import json
import logging
import re
from datetime import datetime, timezone
from typing import Any, Optional

from app.config import settings
from app.database import SessionLocal
from app.models.database import Asset, Finding, FindingSeverity, FindingStatus
from app.services.dedup import compute_finding_fingerprint
from app.utils.validators import DomainValidator

logger = logging.getLogger(__name__)

# HTTP status codes that indicate a real web server answered for the Host —
# i.e. the IP is plausibly the origin (not a refused/unrelated endpoint).
_ORIGIN_STATUSES = {200, 301, 302, 401, 403}
_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


def _is_public_ip(value: str) -> bool:
    """True only for a routable, non-reserved IP literal."""
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return not any(ip in net for net in DomainValidator.RESERVED_NETWORKS)


def _registrable_domain(host: str) -> str:
    """Best-effort registrable domain (last two labels).

    No public-suffix list is bundled, so multi-part TLDs (e.g. co.uk) collapse
    to the last two labels. That only ever *widens* the sibling set slightly;
    the direct-probe verification is the real filter.
    """
    parts = (host or "").strip().strip(".").lower().split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def _asset_ips(asset: Asset) -> list[str]:
    """Resolved A-record IPs for an asset (from dnsx metadata), plus its own
    identifier if the asset itself is an IP."""
    ips: list[str] = []
    if asset.identifier and _is_public_ip(asset.identifier):
        ips.append(asset.identifier)
    raw = asset.raw_metadata
    if raw:
        try:
            record = json.loads(raw) if isinstance(raw, str) else raw
        except (json.JSONDecodeError, TypeError):
            record = {}
        if isinstance(record, dict):
            for ip in record.get("a", []) or []:
                if isinstance(ip, str):
                    ips.append(ip)
    return ips


_SPF_IP4_RE = re.compile(r"ip4:(\d+\.\d+\.\d+\.\d+)(?:/(\d+))?")


def _txt_records(asset: Asset) -> list[str]:
    raw = asset.raw_metadata
    if not raw:
        return []
    try:
        record = json.loads(raw) if isinstance(raw, str) else raw
    except (json.JSONDecodeError, TypeError):
        return []
    return record.get("txt", []) or [] if isinstance(record, dict) else []


def _spf_candidate_ips(asset: Asset) -> list[str]:
    """Extract host IPs published in the domain's SPF record.

    ``ip4:`` mechanisms (bare or /32) frequently list the real mail/hosting IP,
    which is often the same box as the web origin. Ranges (prefix < 32) are
    skipped — enumerating a whole block is not worth the probe budget.
    """
    ips: list[str] = []
    for txt in _txt_records(asset):
        s = str(txt)
        if "v=spf1" not in s.lower():
            continue
        for match in _SPF_IP4_RE.finditer(s):
            ip, mask = match.group(1), match.group(2)
            if mask is None or mask == "32":
                ips.append(ip)
    return ips


def _crtsh_hostnames(domain: str, timeout: int) -> set[str]:
    """Enumerate hostnames for a domain from crt.sh certificate transparency."""
    import httpx

    hosts: set[str] = set()
    try:
        with httpx.Client(timeout=timeout) as client:
            resp = client.get("https://crt.sh/", params={"q": f"%.{domain}", "output": "json"})
            data = resp.json()
    except Exception:
        return hosts
    for entry in data if isinstance(data, list) else []:
        for name in str(entry.get("name_value", "")).splitlines():
            name = name.strip().lstrip("*.").lower()
            if name and name.endswith(domain) and "@" not in name:
                hosts.add(name)
    return hosts


def _resolve_ipv4(hostname: str) -> list[str]:
    import socket

    try:
        infos = socket.getaddrinfo(hostname, None, socket.AF_INET)
    except OSError:
        return []
    return list(dict.fromkeys(info[4][0] for info in infos))


def _crtsh_candidate_ips(domain: str, timeout: int, max_hosts: int) -> list[str]:
    """crt.sh hostnames → resolve to A records → candidate IPs."""
    ips: list[str] = []
    for host in list(_crtsh_hostnames(domain, timeout))[:max_hosts]:
        ips.extend(_resolve_ipv4(host))
    return ips


def gather_origin_candidates(
    db: Any,
    asset: Asset,
    max_candidates: int = 8,
    use_external: Optional[bool] = None,
) -> list[str]:
    """Collect candidate origin IPs for a WAF-fronted asset.

    Sources, in order of cost:
      1. public A-record IPs of *sibling* assets on the same registrable domain
         that are NOT behind a WAF/CDN (direct-resolving siblings) — from the DB;
      2. ``ip4:`` hosts in the domain's SPF record — from the DB;
      3. (optional) hostnames from crt.sh certificate transparency, resolved to
         A records — external calls, gated by ``use_external``.

    The asset's own (WAF-edge) IPs, reserved/internal IPs, and duplicates are
    excluded. Capped at ``max_candidates``.
    """
    if use_external is None:
        use_external = settings.origin_use_external_sources
    base = _registrable_domain(asset.identifier)
    fronted_ips = set(_asset_ips(asset))  # exclude the asset's own (WAF) IPs

    candidates: list[str] = []
    seen: set[str] = set()

    def _add(ip: str) -> bool:
        """Add ip if usable; return True once the cap is reached."""
        if ip not in seen and ip not in fronted_ips and _is_public_ip(ip):
            seen.add(ip)
            candidates.append(ip)
        return len(candidates) >= max_candidates

    # 1. Direct-resolving sibling assets on the same registrable domain.
    siblings = (
        db.query(Asset)
        .filter(
            Asset.tenant_id == asset.tenant_id,
            Asset.is_active.is_(True),
            Asset.id != asset.id,
            Asset.waf_name.is_(None),
            Asset.cdn_name.is_(None),
        )
        .all()
    )
    for sib in siblings:
        if _registrable_domain(sib.identifier) != base:
            continue
        for ip in _asset_ips(sib):
            if _add(ip):
                return candidates

    # 2. SPF ip4 hosts published by the domain itself.
    for ip in _spf_candidate_ips(asset):
        if _add(ip):
            return candidates

    # 3. crt.sh certificate-transparency hostnames, resolved (external).
    if use_external:
        for ip in _crtsh_candidate_ips(base, settings.origin_crtsh_timeout, settings.origin_crtsh_max_hosts):
            if _add(ip):
                return candidates

    return candidates


def _extract_title(html: str) -> str:
    match = _TITLE_RE.search(html or "")
    return (match.group(1).strip() if match else "")[:120]


def verify_origin(hostname: str, candidate_ip: str, timeout: int = 6) -> dict:
    """Probe a candidate origin IP directly, carrying the fronted Host header.

    Returns a dict with ``reachable`` and, when reachable, the status/server/title
    of the direct response. Network errors are swallowed (candidate simply not an
    origin). TLS verification is disabled because we connect by IP.
    """
    if not _is_public_ip(candidate_ip):
        return {"reachable": False, "candidate_ip": candidate_ip}

    import httpx

    headers = {"Host": hostname, "User-Agent": "easm-origin-check"}
    for scheme in ("https", "http"):
        try:
            with httpx.Client(verify=False, timeout=timeout, follow_redirects=False) as client:
                resp = client.get(f"{scheme}://{candidate_ip}/", headers=headers)
            return {
                "reachable": True,
                "scheme": scheme,
                "status": resp.status_code,
                "server": resp.headers.get("server", ""),
                "title": _extract_title(resp.text),
                "candidate_ip": candidate_ip,
            }
        except Exception:
            continue
    return {"reachable": False, "candidate_ip": candidate_ip}


def _looks_like_origin(result: dict) -> bool:
    return bool(result.get("reachable")) and result.get("status") in _ORIGIN_STATUSES


def _upsert_finding(db: Any, tenant_id: int, asset: Asset, result: dict, scan_run_id: Optional[int]) -> bool:
    """Upsert an exposed-origin finding. Returns True if newly created."""
    ip = result["candidate_ip"]
    finding_key = f"ORIGIN-001:{asset.identifier}:{ip}"
    fingerprint = compute_finding_fingerprint(
        tenant_id=tenant_id,
        asset_identifier=asset.identifier,
        template_id=finding_key,
        source="origin_discovery",
    )
    evidence = {
        "hostname": asset.identifier,
        "waf_name": asset.waf_name,
        "candidate_origin_ip": ip,
        "direct_status": result.get("status"),
        "direct_server": result.get("server"),
        "direct_title": result.get("title"),
        "scheme": result.get("scheme"),
        # Presumptive: a direct answer strongly implies exposure but is not
        # proof the content matches the protected site — validate manually.
        "confidence": "presumptive",
        "scan_run_id": scan_run_id,
    }
    name = f"Potential origin server exposed behind {asset.waf_name or 'WAF/CDN'} ({asset.identifier} -> {ip})"

    existing = db.query(Finding).filter(Finding.fingerprint == fingerprint).first()
    now = datetime.now(timezone.utc)
    if existing:
        existing.last_seen = now
        existing.evidence = evidence
        existing.occurrence_count = (existing.occurrence_count or 1) + 1
        if existing.status == FindingStatus.FIXED:
            existing.status = FindingStatus.OPEN
        return False

    db.add(
        Finding(
            asset_id=asset.id,
            source="origin_discovery",
            template_id=finding_key,
            name=name,
            severity=FindingSeverity.MEDIUM,
            evidence=evidence,
            first_seen=now,
            last_seen=now,
            status=FindingStatus.OPEN,
            host=asset.identifier,
            fingerprint=fingerprint,
            occurrence_count=1,
        )
    )
    return True


def run_origin_discovery(tenant_id: int, scan_run_id: Optional[int] = None) -> dict:
    """For every WAF-fronted asset, try to find and verify an exposed origin IP."""
    stats = {
        "status": "completed",
        "assets_checked": 0,
        "candidates_probed": 0,
        "findings_created": 0,
        "findings_updated": 0,
    }
    if not settings.waf_origin_discovery_enabled:
        stats["status"] = "disabled"
        return stats

    db = SessionLocal()
    try:
        fronted = (
            db.query(Asset)
            .filter(
                Asset.tenant_id == tenant_id,
                Asset.is_active.is_(True),
                Asset.waf_name.isnot(None),
            )
            .all()
        )
        for asset in fronted:
            stats["assets_checked"] += 1
            candidates = gather_origin_candidates(db, asset, settings.origin_max_candidates)
            for ip in candidates:
                stats["candidates_probed"] += 1
                result = verify_origin(asset.identifier, ip, settings.origin_probe_timeout)
                if _looks_like_origin(result):
                    if _upsert_finding(db, tenant_id, asset, result, scan_run_id):
                        stats["findings_created"] += 1
                    else:
                        stats["findings_updated"] += 1
        db.commit()
    except Exception as exc:  # pragma: no cover - defensive
        db.rollback()
        logger.error("origin discovery failed (tenant %d): %s", tenant_id, exc)
        stats["status"] = "error"
    finally:
        db.close()
    return stats
