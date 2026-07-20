"""Small DNS lookup helpers (dnspython) for targeted record queries.

dnsx (the ProjectDiscovery binary) only resolves records for the asset name
itself. Email-auth and origin checks need records at *derived* names
(``_dmarc.<domain>``, ``<selector>._domainkey.<domain>``, MX targets), so this
module does those targeted lookups directly. All failures return empty — a DNS
error must never crash a scan phase.
"""

from __future__ import annotations

import logging
from typing import List

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 5


def _resolver(timeout: int):
    import dns.resolver

    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout
    return resolver


def resolve_txt(name: str, timeout: int = DEFAULT_TIMEOUT) -> List[str]:
    """Return TXT records for ``name`` as joined strings (empty on any failure)."""
    try:
        import dns.resolver  # noqa: F401

        answers = _resolver(timeout).resolve(name, "TXT")
    except Exception:
        return []
    records: List[str] = []
    for rdata in answers:
        parts = getattr(rdata, "strings", None)
        if parts:
            records.append("".join(p.decode() if isinstance(p, bytes) else str(p) for p in parts))
        else:
            records.append(str(rdata).strip('"'))
    return records


def resolve_mx(domain: str, timeout: int = DEFAULT_TIMEOUT) -> List[str]:
    """Return MX target hostnames for ``domain`` (empty on any failure)."""
    try:
        import dns.resolver  # noqa: F401

        answers = _resolver(timeout).resolve(domain, "MX")
    except Exception:
        return []
    return [str(r.exchange).rstrip(".") for r in answers]


def has_mx(domain: str, timeout: int = DEFAULT_TIMEOUT) -> bool:
    """True if the domain publishes at least one MX record (i.e. receives mail)."""
    return bool(resolve_mx(domain, timeout))
