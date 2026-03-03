"""
Finding deduplication utilities for EASM.

Computes SHA-256 fingerprints for findings based on their identity attributes
to enable consistent deduplication across all scan sources (Nuclei, cloud_scan,
dnstwist, sensitive_paths, misconfig).

Fingerprint formula:
    SHA256(tenant_id + asset_identifier + template_id + matcher_name + source)

Where:
- tenant_id: ensures cross-tenant isolation
- asset_identifier: the asset this finding belongs to (domain, IP, URL)
- template_id: the detection rule that triggered (e.g. "CVE-2021-44228")
- matcher_name: Nuclei matcher or scanner-specific sub-key (optional)
- source: scanner name (nuclei, cloud_scan, misconfig, etc.)
"""

import hashlib
from typing import Optional


def compute_finding_fingerprint(
    tenant_id: int,
    asset_identifier: str,
    template_id: Optional[str],
    matcher_name: Optional[str] = None,
    source: str = "nuclei",
) -> str:
    """
    Compute a SHA-256 fingerprint for a finding.

    Returns:
        64-character lowercase hex digest.
    """
    parts = [
        str(tenant_id),
        asset_identifier.strip().lower(),
        (template_id or "").strip().lower(),
        (matcher_name or "").strip().lower(),
        source.strip().lower(),
    ]
    payload = "|".join(parts)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()
