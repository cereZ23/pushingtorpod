"""Domain helpers built on the public suffix list (tldextract).

Kept separate from ``validators`` so pipeline/task code can reuse a single,
network-free registrable-domain function.
"""

from __future__ import annotations

import tldextract

# Use only the bundled public-suffix snapshot: ``suffix_list_urls=()`` disables
# the network fetch tldextract would otherwise attempt on first use, which must
# never happen inside a Celery worker.
_extract = tldextract.TLDExtract(suffix_list_urls=())


def registrable_domain(host: str | None) -> str | None:
    """Return the registrable domain (eTLD+1) for a hostname.

    ``api.staging.example.co.uk`` -> ``example.co.uk``. Returns ``None`` for
    empty input, bare IPs, or names with no public suffix (e.g. ``localhost``).
    """
    if not host:
        return None
    cleaned = host.strip().lower().rstrip(".")
    if not cleaned:
        return None
    ext = _extract(cleaned)
    if ext.domain and ext.suffix:
        return f"{ext.domain}.{ext.suffix}"
    return None
