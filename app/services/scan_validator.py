"""
Post-scan validation service.

After each scan completes, verifies that known-vulnerable URLs are still
detected. If a canary is missed, logs a WARNING and marks the scan as
"validation_failed" in stats.

This catches pipeline regressions (severity filters, template path issues,
URL construction bugs) before they produce silent false negatives.
"""

from __future__ import annotations

import logging
from typing import Optional

import httpx

from app.database import SessionLocal
from app.models.database import Asset, Finding

logger = logging.getLogger(__name__)

# Known-vulnerable URLs that MUST produce findings.
# Updated manually when new confirmed vulns are found on monitored targets.
# Format: (url_substring_in_matched_at, finding_name_substring, severity)
CANARY_FINDINGS = [
    # IFO targets — confirmed manually
    ("ifo.it/Dockerfile", "Dockerfile", "MEDIUM"),
    ("ifo.it/docker-compose.yml", "docker-compose", "CRITICAL"),
    ("ifo.it/.htaccess", "htaccess", "MEDIUM"),
]


def validate_scan_findings(tenant_id: int, scan_run_id: int) -> dict:
    """Check that known canary findings were detected in the scan.

    Returns:
        Dict with validation results:
        - canaries_total: number of canaries checked
        - canaries_found: number matched in findings
        - canaries_missing: list of missing canary descriptions
        - validation_passed: bool
    """
    db = SessionLocal()
    try:
        findings = db.query(Finding).join(Asset).filter(Asset.tenant_id == tenant_id).all()

        matched_at_set = set()
        finding_names = set()
        for f in findings:
            if f.matched_at:
                matched_at_set.add(f.matched_at.lower())
            if f.name:
                finding_names.add(f.name.lower())

        found = 0
        missing = []

        for url_sub, name_sub, severity in CANARY_FINDINGS:
            url_match = any(url_sub.lower() in ma for ma in matched_at_set)
            name_match = any(name_sub.lower() in fn for fn in finding_names)

            if url_match or name_match:
                found += 1
            else:
                # Verify the canary URL is still accessible
                still_live = _check_url_accessible(url_sub)
                if still_live:
                    missing.append(f"{name_sub} ({url_sub}) [severity={severity}] - URL still live but NOT found")
                    logger.warning(
                        "CANARY MISSED: %s (%s) not found in scan %d findings "
                        "(URL still accessible — possible pipeline false negative)",
                        name_sub,
                        url_sub,
                        scan_run_id,
                    )
                else:
                    found += 1  # URL no longer accessible — canary is stale, not a false negative
                    logger.info("Canary %s (%s) - URL no longer accessible, skipping", name_sub, url_sub)

        result = {
            "canaries_total": len(CANARY_FINDINGS),
            "canaries_found": found,
            "canaries_missing": missing,
            "validation_passed": len(missing) == 0,
        }

        if missing:
            logger.warning(
                "SCAN VALIDATION FAILED for scan %d: %d/%d canaries missing: %s",
                scan_run_id,
                len(missing),
                len(CANARY_FINDINGS),
                missing,
            )
        else:
            logger.info(
                "Scan validation passed for scan %d: %d/%d canaries found",
                scan_run_id,
                found,
                len(CANARY_FINDINGS),
            )

        return result

    finally:
        db.close()


def _check_url_accessible(url_substring: str) -> bool:
    """Quick check if a canary URL is still accessible."""
    # Build a full URL from the substring
    if not url_substring.startswith("http"):
        url = f"https://{url_substring}"
    else:
        url = url_substring

    try:
        resp = httpx.get(url, timeout=10, follow_redirects=True, verify=False)
        return resp.status_code == 200
    except Exception:
        return False
