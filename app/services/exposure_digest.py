"""Weekly exposure digest — the proactive retention hook.

The exposure/trend/changes endpoints already exist, but they are passive (the
customer must log in and call them). This composes the same signals into a
concise "what changed and why it matters this week" summary that a scheduled
email (or a hero dashboard card) uses to pull the customer back in:

  - exposure/risk score + the change since last week (the burndown narrative)
  - new findings that appeared, by severity (the "new & dangerous")
  - findings resolved in the window (progress)
  - newly discovered assets (new attack surface)

Pure read/compose over existing data; no new tables.
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List

from sqlalchemy import func

from app.models.database import Asset, Finding, FindingSeverity, FindingStatus
from app.models.risk import RiskScore

_SEVERITY_WEIGHT = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}


def _sev(finding: Finding) -> str:
    return finding.severity.value if finding.severity else "info"


def build_digest(db: Any, tenant_id: int, days: int = 7) -> Dict[str, Any]:
    """Compose the exposure digest for a tenant over the last ``days``."""
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)

    latest = (
        db.query(RiskScore)
        .filter(RiskScore.tenant_id == tenant_id, RiskScore.scope_type == "organization")
        .order_by(RiskScore.scored_at.desc())
        .first()
    )
    prior = (
        db.query(RiskScore)
        .filter(
            RiskScore.tenant_id == tenant_id,
            RiskScore.scope_type == "organization",
            RiskScore.scored_at <= cutoff,
        )
        .order_by(RiskScore.scored_at.desc())
        .first()
    )
    score = round(latest.score, 1) if latest else None
    score_delta = round(latest.score - prior.score, 1) if (latest and prior) else None

    new_findings: List[Finding] = (
        db.query(Finding)
        .join(Asset)
        .filter(
            Asset.tenant_id == tenant_id,
            Finding.first_seen >= cutoff,
            Finding.status == FindingStatus.OPEN,
        )
        .all()
    )
    by_severity = Counter(_sev(f) for f in new_findings)
    top_new = [
        {"name": f.name, "severity": _sev(f), "cve_id": f.cve_id}
        for f in sorted(new_findings, key=lambda f: _SEVERITY_WEIGHT.get(_sev(f), 0), reverse=True)[:5]
    ]

    resolved_count = (
        db.query(func.count(Finding.id))
        .join(Asset)
        .filter(
            Asset.tenant_id == tenant_id,
            Finding.status == FindingStatus.FIXED,
            Finding.last_seen >= cutoff,
        )
        .scalar()
        or 0
    )
    new_assets = (
        db.query(func.count(Asset.id)).filter(Asset.tenant_id == tenant_id, Asset.first_seen >= cutoff).scalar() or 0
    )

    new_dangerous = by_severity.get(FindingSeverity.CRITICAL.value, 0) + by_severity.get(FindingSeverity.HIGH.value, 0)

    return {
        "tenant_id": tenant_id,
        "days": days,
        "score": score,
        "score_delta": score_delta,  # negative = exposure went DOWN (good)
        "grade": latest.grade if latest else None,
        "new_findings_total": len(new_findings),
        "new_by_severity": dict(by_severity),
        "new_dangerous": new_dangerous,
        "top_new": top_new,
        "resolved_count": int(resolved_count),
        "new_assets": int(new_assets),
        # Worth sending only if there's something actionable/notable.
        "has_noteworthy": bool(new_dangerous or resolved_count or new_assets or (score_delta not in (None, 0))),
    }


def render_digest_html(digest: Dict[str, Any], tenant_name: str = "") -> str:
    """Minimal HTML body for the digest email."""
    delta = digest.get("score_delta")
    if delta is None:
        trend = "no prior score to compare"
    elif delta < 0:
        trend = f"down {abs(delta)} — exposure decreased 🎉"
    elif delta > 0:
        trend = f"up {delta} — exposure increased"
    else:
        trend = "unchanged"

    rows = "".join(
        f"<li><b>{f['severity'].upper()}</b> — {f['name']}{(' (' + f['cve_id'] + ')') if f.get('cve_id') else ''}</li>"
        for f in digest.get("top_new", [])
    )
    return (
        f"<h2>Exposure digest{(' — ' + tenant_name) if tenant_name else ''}</h2>"
        f"<p>Risk score: <b>{digest.get('score')}</b> ({digest.get('grade')}) — {trend} over {digest['days']} days.</p>"
        f"<p><b>{digest['new_findings_total']}</b> new findings "
        f"(<b>{digest['new_dangerous']}</b> critical/high), "
        f"<b>{digest['resolved_count']}</b> resolved, "
        f"<b>{digest['new_assets']}</b> new assets.</p>"
        f"{('<h3>Top new exposures</h3><ul>' + rows + '</ul>') if rows else ''}"
    )
