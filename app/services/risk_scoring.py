"""
Comprehensive Risk Scoring Engine for EASM Platform

Two-tier scoring model:

Finding-level score (0-100):
    - Base: CVSS score (0-10) * 10 = 0-100
    - EPSS multiplier: >0.5 -> +15, >0.1 -> +10, >0.01 -> +5
    - KEV (Known Exploited Vulnerability): if in CISA KEV -> +20
    - Severity fallback (when no CVSS): critical=90, high=70, medium=45, low=20, info=5
    - Capped at 100

Asset-level score (0-100):
    - Highest finding score among open findings
    - Internet-exposed bonus: ports 80/443/8080/8443 -> +5
    - Expired TLS certificate -> +10
    - New asset (first_seen < 7 days) -> +10
    - Capped at 100

The engine also produces detailed component breakdowns and actionable
recommendations for each scored asset.

Integration points:
    - Pipeline Phase 11 calls recalculate_asset_risk per asset
    - recalculate_tenant_risk batch-updates all active assets for a tenant
    - ThreatIntelService provides EPSS/KEV data (cached in Redis)
    - RiskScore snapshots are stored for historical trending
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Dict, List, Optional

from sqlalchemy import text
from sqlalchemy.orm import Session

from app.models.database import Asset, Finding, FindingSeverity, FindingStatus, Service

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Finding-level scoring constants
# ---------------------------------------------------------------------------

# Severity fallback when CVSS is unavailable (e.g. misconfigs, missing headers).
# Real CVE findings use cvss_score * 10 instead, so these only affect findings
# without a CVSS score — keep them conservative to avoid inflated risk grades.
SEVERITY_FALLBACK_SCORE: Dict[str, float] = {
    'critical': 75.0,
    'high': 50.0,
    'medium': 25.0,
    'low': 10.0,
    'info': 2.0,
}

# EPSS probability thresholds and their bonus points
EPSS_THRESHOLDS = [
    (0.5, 15.0),   # > 50% exploitation probability
    (0.1, 10.0),   # > 10%
    (0.01, 5.0),   # > 1%
]

# CISA KEV bonus
KEV_BONUS = 20.0

# ---------------------------------------------------------------------------
# Asset-level scoring constants
# ---------------------------------------------------------------------------

# Ports that indicate internet exposure
INTERNET_EXPOSED_PORTS = {80, 443, 8080, 8443}
INTERNET_EXPOSED_BONUS = 5.0

EXPIRED_CERT_BONUS = 10.0
NEW_ASSET_DAYS = 7
NEW_ASSET_BONUS = 5.0

# High-risk ports with individual penalties (kept for detailed breakdown)
HIGH_RISK_PORTS = {
    22: ('SSH', 8.0),
    23: ('Telnet', 10.0),
    445: ('SMB', 8.0),
    1433: ('MSSQL', 7.0),
    3306: ('MySQL', 7.0),
    3389: ('RDP', 9.0),
    5432: ('PostgreSQL', 7.0),
    5984: ('CouchDB', 6.0),
    6379: ('Redis', 7.0),
    7001: ('WebLogic', 6.0),
    8089: ('Splunk', 5.0),
    9200: ('Elasticsearch', 7.0),
    27017: ('MongoDB', 7.0),
}

# Login page indicators
LOGIN_INDICATORS = [
    'login', 'signin', 'sign-in', 'auth', 'sso',
    'admin', 'console', 'dashboard', 'portal',
]


# ---------------------------------------------------------------------------
# Finding-level scoring
# ---------------------------------------------------------------------------

def compute_finding_score(
    finding: Finding,
    epss_score: float = 0.0,
    is_kev: bool = False,
) -> float:
    """Compute a risk score (0-100) for a single finding.

    Algorithm:
        1. If the finding has a CVSS score, base = cvss * 10 (maps 0-10 to 0-100).
        2. Otherwise fall back to a severity-based static score.
        3. Add EPSS bonus based on exploitation probability thresholds.
        4. Add KEV bonus (+20) if the CVE appears in the CISA KEV catalog.
        5. Cap the result at 100.

    Args:
        finding: Finding ORM object with severity and optional cvss_score.
        epss_score: EPSS probability (0.0-1.0) for this finding's CVE.
        is_kev: Whether this finding's CVE is in the CISA KEV catalog.

    Returns:
        Numeric score between 0.0 and 100.0.
    """
    # 1. Base score from CVSS or severity fallback
    if finding.cvss_score is not None and finding.cvss_score > 0:
        base = finding.cvss_score * 10.0
    else:
        severity = _normalize_severity(finding.severity)
        base = SEVERITY_FALLBACK_SCORE.get(severity, 5.0)

    # 2. EPSS bonus (first matching threshold wins)
    epss_bonus = 0.0
    for threshold, bonus in EPSS_THRESHOLDS:
        if epss_score > threshold:
            epss_bonus = bonus
            break

    # 3. KEV bonus
    kev_bonus = KEV_BONUS if is_kev else 0.0

    score = base + epss_bonus + kev_bonus
    return min(score, 100.0)


# ---------------------------------------------------------------------------
# Threat intel helpers
# ---------------------------------------------------------------------------

def _get_finding_threat_intel(
    finding: Finding,
    threat_intel_svc: Optional[object] = None,
) -> tuple[float, bool]:
    """Extract or fetch EPSS score and KEV status for a finding.

    Checks the cached ``evidence.threat_intel`` field first (populated by
    the threat_intel_sync Celery task). If not present, falls back to a
    live lookup via the provided ThreatIntelService instance.

    Args:
        finding: Finding ORM object.
        threat_intel_svc: Optional ThreatIntelService instance for live lookups.

    Returns:
        Tuple of (epss_score: float, is_kev: bool).
    """
    if not finding.cve_id:
        return 0.0, False

    # Prefer cached data from evidence field
    evidence = finding.evidence or {}
    if isinstance(evidence, str):
        try:
            import json
            evidence = json.loads(evidence)
        except (json.JSONDecodeError, TypeError):
            evidence = {}
    cached = evidence.get("threat_intel", {})
    if cached:
        return float(cached.get("epss_score", 0.0)), bool(cached.get("is_kev", False))

    # Live lookup fallback
    if threat_intel_svc is not None:
        try:
            epss = threat_intel_svc.get_epss_score(finding.cve_id)
            kev = threat_intel_svc.is_in_kev(finding.cve_id)
            return epss, kev
        except Exception as exc:
            logger.debug("Threat intel lookup failed for %s: %s", finding.cve_id, exc)

    return 0.0, False


def _build_threat_intel_service() -> Optional[object]:
    """Lazy-construct a ThreatIntelService, returning None on failure."""
    try:
        from app.services.threat_intel import ThreatIntelService
        return ThreatIntelService()
    except Exception as exc:
        logger.warning("Could not initialize ThreatIntelService: %s", exc)
        return None


# ---------------------------------------------------------------------------
# Asset-level scoring
# ---------------------------------------------------------------------------

def _normalize_severity(severity) -> str:
    """Normalise a FindingSeverity enum or string to a lowercase string."""
    if severity is None:
        return 'info'
    if isinstance(severity, FindingSeverity):
        return severity.value.lower()
    return str(severity).lower()


def _is_asset_new(asset: Asset) -> bool:
    """Check whether the asset was first seen within NEW_ASSET_DAYS."""
    if not asset.first_seen:
        return False
    first_seen = asset.first_seen
    if first_seen.tzinfo is None:
        first_seen = first_seen.replace(tzinfo=timezone.utc)
    days = (datetime.now(timezone.utc) - first_seen).days
    return days <= NEW_ASSET_DAYS


def _has_expired_cert(asset_id: int, db: Session) -> bool:
    """Check if the asset has at least one expired TLS certificate."""
    try:
        row = db.execute(
            text("SELECT 1 FROM certificates WHERE asset_id = :aid AND is_expired = true LIMIT 1"),
            {"aid": asset_id},
        ).fetchone()
        return row is not None
    except Exception:
        # Table may not exist yet; degrade gracefully
        return False


def _has_internet_exposed_services(asset_id: int, db: Session) -> bool:
    """Check if the asset has services on common internet-facing ports."""
    services = db.query(Service.port).filter_by(asset_id=asset_id).all()
    return any(svc.port in INTERNET_EXPOSED_PORTS for svc in services)


# ---------------------------------------------------------------------------
# Main public API
# ---------------------------------------------------------------------------

class RiskScoringEngine:
    """Comprehensive risk scoring engine for EASM assets.

    Score Range: 0.0 to 100.0
        - 0-20:  Low Risk (Green)
        - 21-40: Medium Risk (Yellow)
        - 41-70: High Risk (Orange)
        - 71-100: Critical Risk (Red)

    The engine computes a **finding-level score** for each open finding
    (CVSS + EPSS + KEV), then derives the **asset-level score** as the
    highest finding score plus environmental modifiers (internet exposure,
    expired certs, new-asset bonus).

    For assets with no open findings the score is driven purely by
    environmental modifiers (expired certs, high-risk ports, etc.).
    """

    def __init__(self, db: Session):
        self.db = db
        self._threat_intel_svc: Optional[object] = None
        self._threat_intel_loaded = False

    # -- Lazy threat intel accessor ------------------------------------------

    def _get_threat_intel(self) -> Optional[object]:
        """Return (and cache) a ThreatIntelService, or None on failure."""
        if not self._threat_intel_loaded:
            self._threat_intel_svc = _build_threat_intel_service()
            self._threat_intel_loaded = True
        return self._threat_intel_svc

    # -- Finding scoring -----------------------------------------------------

    def _score_all_findings(self, asset: Asset) -> Dict:
        """Score all open findings for an asset.

        Returns a dict with:
            - max_finding_score: highest individual finding score (0-100)
            - finding_scores: list of per-finding score dicts
            - severity_counts: dict of severity -> count
            - kev_count / high_epss_count: threat intel summary
            - recommendations: list of actionable items
        """
        findings = (
            self.db.query(Finding)
            .filter_by(asset_id=asset.id)
            .filter(Finding.status == FindingStatus.OPEN)
            .all()
        )

        if not findings:
            return {
                'max_finding_score': 0.0,
                'finding_scores': [],
                'severity_counts': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0},
                'kev_count': 0,
                'high_epss_count': 0,
                'recommendations': [],
            }

        threat_svc = self._get_threat_intel() if any(f.cve_id for f in findings) else None

        max_score = 0.0
        per_finding: List[Dict] = []
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        kev_findings: List[Finding] = []
        high_epss_findings: List[tuple] = []
        recommendations: List[Dict] = []

        for finding in findings:
            epss, is_kev = _get_finding_threat_intel(finding, threat_svc)
            score = compute_finding_score(finding, epss_score=epss, is_kev=is_kev)

            severity = _normalize_severity(finding.severity)
            if severity in severity_counts:
                severity_counts[severity] += 1

            per_finding.append({
                'finding_id': finding.id,
                'name': finding.name,
                'severity': severity,
                'cvss': finding.cvss_score,
                'cve_id': finding.cve_id,
                'epss_score': epss,
                'is_kev': is_kev,
                'score': round(score, 2),
            })

            if score > max_score:
                max_score = score

            if is_kev:
                kev_findings.append(finding)
            if epss > 0.5:
                high_epss_findings.append((finding, epss))

        # Build recommendations
        if severity_counts['critical'] > 0:
            recommendations.append({
                'priority': 'critical',
                'message': (
                    f"{severity_counts['critical']} critical vulnerabilities "
                    "require immediate remediation"
                ),
            })

        if severity_counts['high'] > 0:
            recommendations.append({
                'priority': 'high',
                'message': (
                    f"{severity_counts['high']} high-severity vulnerabilities "
                    "need urgent attention"
                ),
            })

        if kev_findings:
            cve_list = ", ".join(f.cve_id for f in kev_findings[:5] if f.cve_id)
            recommendations.append({
                'priority': 'critical',
                'message': (
                    f"{len(kev_findings)} finding(s) with actively exploited "
                    f"CVEs (CISA KEV): {cve_list}. Immediate patching required."
                ),
            })

        if high_epss_findings:
            top = sorted(high_epss_findings, key=lambda x: x[1], reverse=True)[:3]
            epss_list = ", ".join(f"{f.cve_id} ({s:.0%})" for f, s in top if f.cve_id)
            recommendations.append({
                'priority': 'high',
                'message': (
                    f"{len(high_epss_findings)} finding(s) with high exploitation "
                    f"probability (EPSS > 50%): {epss_list}"
                ),
            })

        return {
            'max_finding_score': round(max_score, 2),
            'finding_scores': sorted(per_finding, key=lambda d: d['score'], reverse=True),
            'severity_counts': severity_counts,
            'kev_count': len(kev_findings),
            'high_epss_count': len(high_epss_findings),
            'recommendations': recommendations,
        }

    # -- Certificate scoring -------------------------------------------------

    def _score_certificates(self, asset: Asset) -> Dict:
        """Score based on TLS certificate security."""
        try:
            result = self.db.execute(
                text("""
                    SELECT id, subject_cn, is_expired, days_until_expiry
                    FROM certificates
                    WHERE asset_id = :asset_id
                """),
                {'asset_id': asset.id},
            )
            certificates = result.fetchall()
        except Exception:
            # certificates table may not exist yet
            return {'has_expired': False, 'score': 0.0, 'issues': [], 'recommendations': []}

        has_expired = False
        score = 0.0
        issues: List[str] = []
        recommendations: List[Dict] = []

        for cert in certificates:
            cert_id, subject_cn, is_expired, days_until_expiry = cert

            if is_expired:
                has_expired = True
                issues.append('expired_certificate')
                recommendations.append({
                    'priority': 'critical',
                    'message': f"Certificate expired for {asset.identifier}",
                })
            elif days_until_expiry is not None and days_until_expiry < 30:
                issues.append('expiring_certificate')
                recommendations.append({
                    'priority': 'medium',
                    'message': (
                        f"Certificate expires in {days_until_expiry} days "
                        f"for {asset.identifier}"
                    ),
                })

            if subject_cn and asset.identifier:
                cn_clean = subject_cn.replace('*.', '')
                if cn_clean not in asset.identifier and asset.identifier not in cn_clean:
                    issues.append('certificate_mismatch')
                    recommendations.append({
                        'priority': 'high',
                        'message': (
                            f"Certificate CN '{subject_cn}' doesn't match "
                            f"'{asset.identifier}'"
                        ),
                    })

        return {
            'has_expired': has_expired,
            'score': score,
            'issues': issues,
            'recommendations': recommendations,
        }

    # -- Port exposure scoring -----------------------------------------------

    def _score_port_exposure(self, asset: Asset) -> Dict:
        """Score based on exposed high-risk ports."""
        services = self.db.query(Service).filter_by(asset_id=asset.id).all()

        is_internet_exposed = False
        exposed_high_risk: List[Dict] = []
        recommendations: List[Dict] = []

        for service in services:
            if service.port in INTERNET_EXPOSED_PORTS:
                is_internet_exposed = True

            if service.port in HIGH_RISK_PORTS:
                port_name, _penalty = HIGH_RISK_PORTS[service.port]
                exposed_high_risk.append({
                    'port': service.port,
                    'name': port_name,
                })
                recommendations.append({
                    'priority': 'high' if service.port in (23, 3389) else 'medium',
                    'message': (
                        f"High-risk {port_name} service exposed on "
                        f"{asset.identifier}:{service.port}"
                    ),
                })

        return {
            'is_internet_exposed': is_internet_exposed,
            'exposed_high_risk_ports': exposed_high_risk,
            'recommendations': recommendations,
        }

    # -- Service security scoring --------------------------------------------

    def _score_service_security(self, asset: Asset) -> Dict:
        """Score based on service security (login pages, HTTP without TLS)."""
        services = self.db.query(Service).filter_by(asset_id=asset.id).all()

        issues: List[str] = []
        recommendations: List[Dict] = []

        for service in services:
            title = (service.http_title or '').lower()
            is_login = any(indicator in title for indicator in LOGIN_INDICATORS)

            if is_login:
                if service.protocol == 'http' and not service.has_tls:
                    issues.append('http_login_exposed')
                    recommendations.append({
                        'priority': 'critical',
                        'message': (
                            f"Login page '{service.http_title}' exposed over "
                            f"HTTP (no encryption) on {asset.identifier}"
                        ),
                    })
                else:
                    issues.append('https_login_exposed')
                    recommendations.append({
                        'priority': 'medium',
                        'message': (
                            f"Login page '{service.http_title}' exposed to "
                            f"internet on {asset.identifier}"
                        ),
                    })

        return {
            'issues': issues,
            'recommendations': recommendations,
        }

    # -- Asset age scoring ---------------------------------------------------

    def _score_asset_age(self, asset: Asset) -> Dict:
        """Score based on asset age (new assets are higher risk)."""
        is_new = _is_asset_new(asset)
        recommendations: List[Dict] = []

        if is_new and asset.first_seen:
            first_seen = asset.first_seen
            if first_seen.tzinfo is None:
                first_seen = first_seen.replace(tzinfo=timezone.utc)
            days = (datetime.now(timezone.utc) - first_seen).days
            recommendations.append({
                'priority': 'high',
                'message': (
                    f"New asset discovered {days} days ago - requires "
                    "additional monitoring"
                ),
            })

        return {
            'is_new': is_new,
            'recommendations': recommendations,
        }

    # -- Main entry point ----------------------------------------------------

    def calculate_asset_risk(self, asset_id: int) -> Dict:
        """Calculate comprehensive risk score for an asset.

        Algorithm:
            1. Compute finding-level scores for every open finding.
            2. Take the highest finding score as the base.
            3. Add environmental modifiers:
               - Internet-exposed (ports 80/443/8080/8443): +5
               - Expired TLS certificate: +10
               - New asset (< 7 days): +10
            4. Cap at 100.

        Args:
            asset_id: Asset ID to score.

        Returns:
            Dict with risk_score, risk_level, components, and recommendations.
        """
        asset = self.db.query(Asset).filter_by(id=asset_id).first()
        if not asset:
            logger.warning("Asset %d not found for risk scoring", asset_id)
            return {
                'asset_id': asset_id,
                'risk_score': 0.0,
                'error': 'asset_not_found',
            }

        # 1. Findings analysis
        findings_data = self._score_all_findings(asset)
        max_finding_score = findings_data['max_finding_score']

        # 2. Certificate analysis
        cert_data = self._score_certificates(asset)

        # 3. Port exposure analysis
        port_data = self._score_port_exposure(asset)

        # 4. Service security analysis
        service_data = self._score_service_security(asset)

        # 5. Asset age analysis
        age_data = self._score_asset_age(asset)

        # Compute asset-level score
        asset_score = max_finding_score

        internet_exposed_bonus = 0.0
        if port_data['is_internet_exposed']:
            internet_exposed_bonus = INTERNET_EXPOSED_BONUS
            asset_score += internet_exposed_bonus

        expired_cert_bonus = 0.0
        if cert_data['has_expired']:
            expired_cert_bonus = EXPIRED_CERT_BONUS
            asset_score += expired_cert_bonus

        new_asset_bonus = 0.0
        if age_data['is_new']:
            new_asset_bonus = NEW_ASSET_BONUS
            asset_score += new_asset_bonus

        asset_score = min(asset_score, 100.0)
        asset_score = round(asset_score, 2)

        risk_level = _get_risk_level(asset_score)

        # Collect all recommendations
        recommendations: List[Dict] = []
        recommendations.extend(findings_data.get('recommendations', []))
        recommendations.extend(cert_data.get('recommendations', []))
        recommendations.extend(port_data.get('recommendations', []))
        recommendations.extend(service_data.get('recommendations', []))
        recommendations.extend(age_data.get('recommendations', []))

        # Build components breakdown
        components = {
            'max_finding_score': max_finding_score,
            'internet_exposed_bonus': internet_exposed_bonus,
            'expired_cert_bonus': expired_cert_bonus,
            'new_asset_bonus': new_asset_bonus,
            'finding_count': len(findings_data['finding_scores']),
            'severity_counts': findings_data['severity_counts'],
            'threat_intel': {
                'kev_count': findings_data['kev_count'],
                'high_epss_count': findings_data['high_epss_count'],
            },
            'top_findings': findings_data['finding_scores'][:5],
            'exposed_high_risk_ports': port_data['exposed_high_risk_ports'],
            'cert_issues': cert_data.get('issues', []),
            'service_issues': service_data.get('issues', []),
        }

        return {
            'asset_id': asset_id,
            'asset_identifier': asset.identifier,
            'risk_score': asset_score,
            'risk_level': risk_level,
            'components': components,
            'recommendations': recommendations,
            'last_calculated': datetime.now(timezone.utc).isoformat(),
        }

    # -- Tenant scorecard ----------------------------------------------------

    def calculate_tenant_risk_scorecard(self, tenant_id: int) -> Dict:
        """Calculate aggregated risk scorecard for a tenant.

        Reads the already-persisted ``asset.risk_score`` values (set by
        ``recalculate_asset_risk`` or the pipeline). Does NOT recompute
        individual asset scores.

        Args:
            tenant_id: Tenant ID.

        Returns:
            Summary dict with distribution, average, and top-risk assets.
        """
        assets = self.db.query(Asset).filter_by(
            tenant_id=tenant_id,
            is_active=True,
        ).all()

        if not assets:
            return {
                'tenant_id': tenant_id,
                'total_assets': 0,
                'average_risk_score': 0.0,
                'risk_distribution': {},
            }

        risk_levels = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        total_score = 0.0
        high_risk_assets: List[Dict] = []

        for asset in assets:
            score = asset.risk_score if asset.risk_score is not None else 0.0
            total_score += score
            level = _get_risk_level(score)
            risk_levels[level] += 1

            if score >= 70.0:
                high_risk_assets.append({
                    'identifier': asset.identifier,
                    'risk_score': score,
                })

        average_score = total_score / len(assets)

        return {
            'tenant_id': tenant_id,
            'total_assets': len(assets),
            'average_risk_score': round(average_score, 2),
            'risk_distribution': risk_levels,
            'high_risk_assets': sorted(
                high_risk_assets,
                key=lambda x: x['risk_score'],
                reverse=True,
            )[:10],
            'last_calculated': datetime.now(timezone.utc).isoformat(),
        }


# ---------------------------------------------------------------------------
# Shared utility
# ---------------------------------------------------------------------------

def _get_risk_level(score: float) -> str:
    """Map a numeric score to a human-readable risk level."""
    if score >= 71.0:
        return 'critical'
    if score >= 41.0:
        return 'high'
    if score >= 21.0:
        return 'medium'
    return 'low'


# ---------------------------------------------------------------------------
# Top-level convenience functions (importable from tasks/pipeline)
# ---------------------------------------------------------------------------

def recalculate_asset_risk(asset_id: int, db: Session) -> Dict:
    """Recalculate and persist the risk score for a single asset.

    This is the primary entry point for the pipeline and ad-hoc rescoring.
    It computes the full finding-level + asset-level score, persists the
    result on the Asset row, and returns the full breakdown.

    Args:
        asset_id: ID of the asset to score.
        db: Active SQLAlchemy session (caller manages commit).

    Returns:
        Full score breakdown dict (same shape as
        ``RiskScoringEngine.calculate_asset_risk``).  If the asset is not
        found, returns ``{'asset_id': ..., 'risk_score': 0.0, 'error': ...}``.
    """
    engine = RiskScoringEngine(db)
    result = engine.calculate_asset_risk(asset_id)

    if 'error' not in result:
        asset = db.query(Asset).filter_by(id=asset_id).first()
        if asset is not None:
            asset.risk_score = result['risk_score']
            db.flush()
            logger.debug(
                "Asset %d (%s) risk score updated to %.2f",
                asset_id,
                asset.identifier,
                result['risk_score'],
            )

    return result


def recalculate_tenant_risk(
    tenant_id: int,
    db: Session,
    batch_size: int = 100,
) -> Dict:
    """Recalculate risk scores for every active asset in a tenant.

    Processes assets in batches and commits after each batch so that
    long-running rescoring does not hold a single oversized transaction.

    Args:
        tenant_id: Tenant ID.
        db: Active SQLAlchemy session.
        batch_size: Number of assets to process per commit cycle.

    Returns:
        Summary dict::

            {
                "tenant_id": 1,
                "total_assets": 150,
                "processed": 148,
                "updated": 148,
                "failed": 2,
                "score_distribution": {"critical": 5, "high": 23, ...},
                "average_risk_score": 42.7,
                "max_risk_score": 98.0
            }
    """
    logger.info("Starting tenant risk recalculation for tenant %d", tenant_id)

    assets = (
        db.query(Asset)
        .filter_by(tenant_id=tenant_id, is_active=True)
        .all()
    )

    total = len(assets)
    processed = 0
    updated = 0
    failed = 0
    distribution = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
    all_scores: List[float] = []

    engine = RiskScoringEngine(db)

    for batch_start in range(0, total, batch_size):
        batch = assets[batch_start:batch_start + batch_size]

        for asset in batch:
            try:
                result = engine.calculate_asset_risk(asset.id)
                score = result.get('risk_score', 0.0)

                if 'error' not in result:
                    asset.risk_score = score
                    updated += 1
                    level = _get_risk_level(score)
                    distribution[level] += 1
                    all_scores.append(score)
                else:
                    failed += 1

                processed += 1

            except Exception as exc:
                logger.error(
                    "Risk scoring failed for asset %d: %s",
                    asset.id,
                    exc,
                    exc_info=True,
                )
                failed += 1
                processed += 1

        db.commit()
        logger.debug(
            "Tenant %d risk scoring batch %d/%d complete",
            tenant_id,
            batch_start // batch_size + 1,
            (total + batch_size - 1) // batch_size,
        )

    avg_score = sum(all_scores) / len(all_scores) if all_scores else 0.0
    max_score = max(all_scores) if all_scores else 0.0

    logger.info(
        "Tenant %d risk scoring complete: %d/%d updated, %d failed, avg=%.1f max=%.1f",
        tenant_id,
        updated,
        total,
        failed,
        avg_score,
        max_score,
    )

    return {
        'tenant_id': tenant_id,
        'total_assets': total,
        'processed': processed,
        'updated': updated,
        'failed': failed,
        'score_distribution': distribution,
        'average_risk_score': round(avg_score, 2),
        'max_risk_score': round(max_score, 2),
    }


# ---------------------------------------------------------------------------
# Backward-compatible alias
# ---------------------------------------------------------------------------

def batch_calculate_risk_scores(
    db: Session,
    tenant_id: int,
    batch_size: int = 100,
) -> Dict:
    """Backward-compatible wrapper around recalculate_tenant_risk.

    Existing callers (e.g., older Celery tasks) can continue to import and
    call this function without changes.
    """
    result = recalculate_tenant_risk(tenant_id, db, batch_size=batch_size)
    # Map to the legacy return shape expected by older callers
    return {
        'tenant_id': result['tenant_id'],
        'total_assets': result['total_assets'],
        'processed': result['processed'],
        'updated': result['updated'],
    }
