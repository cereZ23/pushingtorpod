"""
Soft-404 detection utility.

Detects hosts that return HTTP 200 for non-existent paths (custom error
pages). These hosts produce false positives in vulnerability scanners
because every path appears "found".

Usage:
    from app.utils.soft404 import detect_soft404_hosts
    soft404_set = detect_soft404_hosts(urls, timeout=5)
"""

from __future__ import annotations

import hashlib
import logging
import re
import secrets
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Set

import httpx

logger = logging.getLogger(__name__)

# Body patterns that indicate a custom 404 page
_SOFT_404_PATTERNS = [
    re.compile(r"page\s+not\s+found", re.IGNORECASE),
    re.compile(r"404\s+not\s+found", re.IGNORECASE),
    re.compile(r"not\s+found.*the.*page", re.IGNORECASE),
    re.compile(r"error\s+404", re.IGNORECASE),
    re.compile(r"<title>404", re.IGNORECASE),
    re.compile(r"does\s+not\s+exist", re.IGNORECASE),
    re.compile(r"page\s+you.*looking\s+for", re.IGNORECASE),
    re.compile(r"nothing.*found\s+here", re.IGNORECASE),
]


def is_soft_404(body: str) -> bool:
    """Return True if the response body looks like a custom 404 page."""
    if not body:
        return True
    snippet = body[:4000]
    for pat in _SOFT_404_PATTERNS:
        if pat.search(snippet):
            return True
    return False


def _probe_host(base_url: str, timeout: float = 5.0) -> bool:
    """Probe a single host with a random path. Returns True if soft-404 detected."""
    random_path = f"/{secrets.token_hex(8)}-{secrets.token_hex(4)}.html"
    probe_url = base_url.rstrip("/") + random_path

    try:
        with httpx.Client(
            timeout=timeout,
            follow_redirects=True,
            verify=False,
            headers={"User-Agent": "Mozilla/5.0 (EASM Scanner)"},
        ) as client:
            resp = client.get(probe_url)

            # Real 404 → host is fine (returns proper 404)
            if resp.status_code in (404, 403, 410):
                return False

            # 200 on a random path → check body for soft-404 patterns
            if resp.status_code == 200:
                return is_soft_404(resp.text)

            # 301/302 to a generic error page → soft-404
            if resp.status_code in (301, 302):
                return True

            return False

    except (httpx.TimeoutException, httpx.ConnectError, httpx.HTTPError):
        # Can't reach host — not a soft-404, just unreachable
        return False
    except Exception:
        return False


def detect_soft404_hosts(
    base_urls: list[str],
    timeout: float = 5.0,
    max_workers: int = 20,
) -> Set[str]:
    """Probe multiple hosts in parallel for soft-404 behavior.

    Args:
        base_urls: List of base URLs like ["https://example.com", "http://test.org"]
        timeout: Per-request timeout in seconds
        max_workers: Thread pool size

    Returns:
        Set of base URLs that exhibit soft-404 behavior.
    """
    if not base_urls:
        return set()

    soft404_hosts: set[str] = set()

    with ThreadPoolExecutor(max_workers=min(max_workers, len(base_urls))) as pool:
        future_to_url = {pool.submit(_probe_host, url, timeout): url for url in base_urls}

        for future in as_completed(future_to_url):
            url = future_to_url[future]
            try:
                if future.result():
                    soft404_hosts.add(url)
            except Exception:
                pass

    if soft404_hosts:
        logger.info("Soft-404 detected on %d/%d hosts", len(soft404_hosts), len(base_urls))

    return soft404_hosts
