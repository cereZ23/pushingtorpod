"""
Comprehensive Risk Scoring Engine for EASM Platform

Calculates risk scores for assets based on multiple security factors:
- Vulnerability findings (Nuclei)
- EPSS exploit probability scores (FIRST.org)
- CISA KEV known exploited vulnerabilities
- TLS/certificate issues
- Exposed high-risk ports
- Login page exposure
- Asset age (new assets are higher risk)
- Service security posture
"""

import logging
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional
from sqlalchemy.orm import Session
from sqlalchemy import text

from app.models.database import Asset, Service, Finding

logger = logging.getLogger(__name__)


class RiskScoringEngine:
    """
    Comprehensive risk scoring engine for EASM assets

    Score Range: 0.0 to 100.0
    - 0-20: Low Risk (Green)
    - 21-40: Medium Risk (Yellow)
    - 41-70: High Risk (Orange)
    - 71-100: Critical Risk (Red)
    """

    # Finding severity weights
    FINDING_WEIGHTS = {
        'critical': 15.0,
        'high': 10.0,
        'medium': 5.0,
        'low': 2.0,
        'info': 0.5
    }

    # Risk modifiers
    NEW_ASSET_BONUS = 10.0  # Asset discovered in last 7 days
    EXPIRED_CERT_PENALTY = 15.0
    EXPIRING_CERT_PENALTY = 8.0  # < 30 days
    CERT_MISMATCH_PENALTY = 12.0
    LOGIN_PAGE_EXPOSED = 10.0
    HTTP_LOGIN_EXPOSED = 15.0  # Login over HTTP (no TLS)

    # Threat intelligence risk modifiers
    KEV_BOOST = 15.0          # CISA KEV: confirmed active exploitation
    EPSS_HIGH_BOOST = 10.0    # EPSS >= 0.7: very likely to be exploited
    EPSS_MEDIUM_BOOST = 5.0   # EPSS >= 0.4: likely to be exploited
    EPSS_LOW_BOOST = 2.0      # EPSS >= 0.1: some exploitation probability

    # High-risk ports (database, admin, remote access)
    HIGH_RISK_PORTS = {
        22: 8.0,    # SSH
        23: 10.0,   # Telnet (very high risk)
        445: 8.0,   # SMB
        1433: 7.0,  # MSSQL
        3306: 7.0,  # MySQL
        3389: 9.0,  # RDP
        5432: 7.0,  # PostgreSQL
        5984: 6.0,  # CouchDB
        6379: 7.0,  # Redis
        7001: 6.0,  # WebLogic
        8089: 5.0,  # Splunk
        9200: 7.0,  # Elasticsearch
        27017: 7.0, # MongoDB
    }

    # Login page indicators
    LOGIN_INDICATORS = [
        'login', 'signin', 'sign-in', 'auth', 'sso',
        'admin', 'console', 'dashboard', 'portal'
    ]

    def __init__(self, db: Session):
        """
        Initialize risk scoring engine

        Args:
            db: Database session
        """
        self.db = db

    def calculate_asset_risk(self, asset_id: int) -> Dict:
        """
        Calculate comprehensive risk score for an asset

        Args:
            asset_id: Asset ID to score

        Returns:
            Dict with score breakdown and recommendations
        """
        asset = self.db.query(Asset).filter_by(id=asset_id).first()

        if not asset:
            logger.warning(f"Asset {asset_id} not found for risk scoring")
            return {
                'asset_id': asset_id,
                'risk_score': 0.0,
                'error': 'asset_not_found'
            }

        # Initialize score components
        components = {
            'findings_score': 0.0,
            'certificate_score': 0.0,
            'port_exposure_score': 0.0,
            'service_security_score': 0.0,
            'asset_age_score': 0.0,
            'threat_intel': {
                'kev_count': 0,
                'high_epss_count': 0,
            }
        }

        recommendations = []

        # 1. Findings Score (Nuclei vulnerabilities + EPSS/KEV boosts)
        findings_data = self._score_findings(asset)
        components['findings_score'] = findings_data['score']
        components['threat_intel']['kev_count'] = findings_data.get('kev_count', 0)
        components['threat_intel']['high_epss_count'] = findings_data.get('high_epss_count', 0)
        recommendations.extend(findings_data.get('recommendations', []))

        # 2. Certificate/TLS Score
        cert_data = self._score_certificates(asset)
        components['certificate_score'] = cert_data['score']
        recommendations.extend(cert_data.get('recommendations', []))

        # 3. Port Exposure Score
        port_data = self._score_port_exposure(asset)
        components['port_exposure_score'] = port_data['score']
        recommendations.extend(port_data.get('recommendations', []))

        # 4. Service Security Score (login pages, HTTP vs HTTPS, etc.)
        service_data = self._score_service_security(asset)
        components['service_security_score'] = service_data['score']
        recommendations.extend(service_data.get('recommendations', []))

        # 5. Asset Age Score (new assets get bonus)
        age_data = self._score_asset_age(asset)
        components['asset_age_score'] = age_data['score']
        recommendations.extend(age_data.get('recommendations', []))

        # Calculate total score (capped at 100.0)
        # Only sum numeric component values (skip nested dicts like threat_intel)
        total_score = sum(
            v for v in components.values() if isinstance(v, (int, float))
        )
        total_score = min(total_score, 100.0)

        # Determine risk level
        risk_level = self._get_risk_level(total_score)

        return {
            'asset_id': asset_id,
            'asset_identifier': asset.identifier,
            'risk_score': round(total_score, 2),
            'risk_level': risk_level,
            'components': components,
            'recommendations': recommendations,
            'last_calculated': datetime.now(timezone.utc).isoformat()
        }

    def _score_findings(self, asset: Asset) -> Dict:
        """Score based on vulnerability findings, boosted by EPSS/KEV threat intel.

        For each open finding:
        - Base score from severity weight (critical=15, high=10, medium=5, low=2, info=0.5)
        - EPSS boost: adds extra points based on exploit probability score
        - KEV boost: adds 15 points if CVE is in CISA Known Exploited Vulnerabilities

        Threat intel data is read from the finding's evidence.threat_intel field
        (populated by the threat_intel_sync task) or fetched live from the
        ThreatIntelService if not cached in the finding.
        """
        from app.models.database import FindingStatus

        findings = self.db.query(Finding).filter_by(
            asset_id=asset.id,
        ).filter(
            Finding.status == FindingStatus.OPEN
        ).all()

        score = 0.0
        recommendations = []
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        kev_findings = []
        high_epss_findings = []

        # Lazy-load threat intel service only if we have findings with CVEs
        threat_intel_service = None
        cve_findings = [f for f in findings if f.cve_id]
        if cve_findings:
            try:
                from app.services.threat_intel import ThreatIntelService
                threat_intel_service = ThreatIntelService()
            except Exception as exc:
                logger.warning(
                    "Could not initialize ThreatIntelService for risk scoring: %s", exc
                )

        for finding in findings:
            severity = finding.severity.value.lower() if finding.severity else 'info'
            weight = self.FINDING_WEIGHTS.get(severity, 0.0)

            # Get threat intel data from evidence cache or live lookup
            epss_score = 0.0
            is_kev = False

            if finding.cve_id:
                # Try cached threat intel in evidence field first
                evidence = finding.evidence or {}
                threat_intel_data = evidence.get("threat_intel", {})

                if threat_intel_data:
                    epss_score = float(threat_intel_data.get("epss_score", 0.0))
                    is_kev = bool(threat_intel_data.get("is_kev", False))
                elif threat_intel_service:
                    # Live lookup as fallback
                    try:
                        epss_score = threat_intel_service.get_epss_score(finding.cve_id)
                        is_kev = threat_intel_service.is_in_kev(finding.cve_id)
                    except Exception as exc:
                        logger.debug(
                            "Threat intel lookup failed for %s: %s",
                            finding.cve_id, exc
                        )

            # Apply EPSS boost
            epss_boost = 0.0
            if epss_score >= 0.7:
                epss_boost = self.EPSS_HIGH_BOOST
            elif epss_score >= 0.4:
                epss_boost = self.EPSS_MEDIUM_BOOST
            elif epss_score >= 0.1:
                epss_boost = self.EPSS_LOW_BOOST

            # Apply KEV boost
            kev_boost = self.KEV_BOOST if is_kev else 0.0

            finding_score = weight + epss_boost + kev_boost
            score += finding_score

            if severity in severity_counts:
                severity_counts[severity] += 1

            if is_kev:
                kev_findings.append(finding)

            if epss_score >= 0.5:
                high_epss_findings.append((finding, epss_score))

        # Add recommendations based on findings
        if severity_counts['critical'] > 0:
            recommendations.append({
                'priority': 'critical',
                'message': f"{severity_counts['critical']} critical vulnerabilities require immediate remediation"
            })

        if severity_counts['high'] > 0:
            recommendations.append({
                'priority': 'high',
                'message': f"{severity_counts['high']} high-severity vulnerabilities need urgent attention"
            })

        # Add threat intel recommendations
        if kev_findings:
            cve_list = ", ".join(
                f.cve_id for f in kev_findings[:5] if f.cve_id
            )
            recommendations.append({
                'priority': 'critical',
                'message': (
                    f"{len(kev_findings)} finding(s) with actively exploited CVEs "
                    f"(CISA KEV): {cve_list}. Immediate patching required."
                )
            })

        if high_epss_findings:
            top_epss = sorted(high_epss_findings, key=lambda x: x[1], reverse=True)[:3]
            epss_list = ", ".join(
                f"{f.cve_id} ({s:.0%})" for f, s in top_epss if f.cve_id
            )
            recommendations.append({
                'priority': 'high',
                'message': (
                    f"{len(high_epss_findings)} finding(s) with high exploitation "
                    f"probability (EPSS >= 50%): {epss_list}"
                )
            })

        return {
            'score': min(score, 50.0),  # Cap findings score at 50
            'severity_counts': severity_counts,
            'kev_count': len(kev_findings),
            'high_epss_count': len(high_epss_findings),
            'recommendations': recommendations
        }

    def _score_certificates(self, asset: Asset) -> Dict:
        """Score based on TLS certificate security"""
        # Query certificates using raw SQL since there's no ORM model
        query = text("""
            SELECT id, subject_cn, is_expired, days_until_expiry
            FROM certificates
            WHERE asset_id = :asset_id
        """)

        result = self.db.execute(query, {'asset_id': asset.id})
        certificates = result.fetchall()

        score = 0.0
        recommendations = []
        issues = []

        for cert in certificates:
            cert_id, subject_cn, is_expired, days_until_expiry = cert

            # Check for expired certificates
            if is_expired:
                score += self.EXPIRED_CERT_PENALTY
                issues.append('expired_certificate')
                recommendations.append({
                    'priority': 'critical',
                    'message': f"Certificate expired for {asset.identifier}"
                })

            # Check for expiring certificates (< 30 days)
            elif days_until_expiry is not None and days_until_expiry < 30:
                score += self.EXPIRING_CERT_PENALTY
                issues.append('expiring_certificate')
                recommendations.append({
                    'priority': 'medium',
                    'message': f"Certificate expires in {days_until_expiry} days for {asset.identifier}"
                })

            # Check for certificate CN mismatch
            if subject_cn and asset.identifier:
                # Simple mismatch check
                cn_clean = subject_cn.replace('*.', '')
                if cn_clean not in asset.identifier and asset.identifier not in cn_clean:
                    score += self.CERT_MISMATCH_PENALTY
                    issues.append('certificate_mismatch')
                    recommendations.append({
                        'priority': 'high',
                        'message': f"Certificate CN '{subject_cn}' doesn't match '{asset.identifier}'"
                    })

        return {
            'score': min(score, 30.0),  # Cap certificate score at 30
            'issues': issues,
            'recommendations': recommendations
        }

    def _score_port_exposure(self, asset: Asset) -> Dict:
        """Score based on exposed high-risk ports"""
        services = self.db.query(Service).filter_by(asset_id=asset.id).all()

        score = 0.0
        recommendations = []
        exposed_ports = []

        for service in services:
            if service.port in self.HIGH_RISK_PORTS:
                port_penalty = self.HIGH_RISK_PORTS[service.port]
                score += port_penalty
                exposed_ports.append(service.port)

                port_names = {
                    22: 'SSH', 23: 'Telnet', 445: 'SMB',
                    1433: 'MSSQL', 3306: 'MySQL', 3389: 'RDP',
                    5432: 'PostgreSQL', 5984: 'CouchDB',
                    6379: 'Redis', 7001: 'WebLogic',
                    8089: 'Splunk', 9200: 'Elasticsearch',
                    27017: 'MongoDB'
                }

                port_name = port_names.get(service.port, f'Port {service.port}')

                recommendations.append({
                    'priority': 'high' if service.port in [23, 3389] else 'medium',
                    'message': f"High-risk {port_name} service exposed on {asset.identifier}"
                })

        return {
            'score': min(score, 40.0),  # Cap port exposure score at 40
            'exposed_high_risk_ports': exposed_ports,
            'recommendations': recommendations
        }

    def _score_service_security(self, asset: Asset) -> Dict:
        """Score based on service security (login pages, HTTP, etc.)"""
        services = self.db.query(Service).filter_by(asset_id=asset.id).all()

        score = 0.0
        recommendations = []
        issues = []

        for service in services:
            # Check for login pages
            is_login_page = False
            title = (service.http_title or '').lower()

            for indicator in self.LOGIN_INDICATORS:
                if indicator in title:
                    is_login_page = True
                    break

            if is_login_page:
                # Check if it's over HTTP (no TLS)
                if service.protocol == 'http' and not service.has_tls:
                    score += self.HTTP_LOGIN_EXPOSED
                    issues.append('http_login_exposed')
                    recommendations.append({
                        'priority': 'critical',
                        'message': f"Login page '{service.http_title}' exposed over HTTP (no encryption) on {asset.identifier}"
                    })
                else:
                    # HTTPS login page
                    score += self.LOGIN_PAGE_EXPOSED
                    recommendations.append({
                        'priority': 'medium',
                        'message': f"Login page '{service.http_title}' exposed to internet on {asset.identifier}"
                    })

        return {
            'score': min(score, 25.0),  # Cap service security score at 25
            'issues': issues,
            'recommendations': recommendations
        }

    def _score_asset_age(self, asset: Asset) -> Dict:
        """Score based on asset age (new assets get bonus for monitoring)"""
        score = 0.0
        recommendations = []

        if asset.first_seen:
            days_since_discovery = (datetime.now(timezone.utc) - asset.first_seen).days

            if days_since_discovery <= 7:
                score += self.NEW_ASSET_BONUS
                recommendations.append({
                    'priority': 'high',
                    'message': f"New asset discovered {days_since_discovery} days ago - requires additional monitoring"
                })

        return {
            'score': score,
            'recommendations': recommendations
        }

    def _get_risk_level(self, score: float) -> str:
        """Determine risk level from score"""
        if score >= 71.0:
            return 'critical'
        elif score >= 41.0:
            return 'high'
        elif score >= 21.0:
            return 'medium'
        else:
            return 'low'

    def calculate_tenant_risk_scorecard(self, tenant_id: int) -> Dict:
        """
        Calculate risk scorecard for entire tenant

        Args:
            tenant_id: Tenant ID

        Returns:
            Aggregated risk metrics for tenant
        """
        assets = self.db.query(Asset).filter_by(
            tenant_id=tenant_id,
            is_active=True
        ).all()

        if not assets:
            return {
                'tenant_id': tenant_id,
                'total_assets': 0,
                'average_risk_score': 0.0,
                'risk_distribution': {}
            }

        risk_levels = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        total_score = 0.0
        high_risk_assets = []

        for asset in assets:
            if asset.risk_score is not None:
                total_score += asset.risk_score
                level = self._get_risk_level(asset.risk_score)
                risk_levels[level] += 1

                if asset.risk_score >= 70.0:
                    high_risk_assets.append({
                        'identifier': asset.identifier,
                        'risk_score': asset.risk_score
                    })

        average_score = total_score / len(assets) if assets else 0.0

        return {
            'tenant_id': tenant_id,
            'total_assets': len(assets),
            'average_risk_score': round(average_score, 2),
            'risk_distribution': risk_levels,
            'high_risk_assets': sorted(high_risk_assets, key=lambda x: x['risk_score'], reverse=True)[:10],
            'last_calculated': datetime.now(timezone.utc).isoformat()
        }


def batch_calculate_risk_scores(db: Session, tenant_id: int, batch_size: int = 100) -> Dict:
    """
    Calculate risk scores for all assets in a tenant (batch operation)

    Args:
        db: Database session
        tenant_id: Tenant ID
        batch_size: Number of assets to process per batch

    Returns:
        Summary of risk score calculations
    """
    from app.repositories.asset_repository import AssetRepository

    logger.info(f"Starting batch risk score calculation for tenant {tenant_id}")

    engine = RiskScoringEngine(db)
    asset_repo = AssetRepository(db)

    # Get all active assets for tenant
    assets = db.query(Asset).filter_by(
        tenant_id=tenant_id,
        is_active=True
    ).all()

    total_assets = len(assets)
    processed = 0
    updated = 0

    logger.info(f"Processing {total_assets} assets for risk scoring")

    # Process in batches
    for i in range(0, total_assets, batch_size):
        batch = assets[i:i + batch_size]

        for asset in batch:
            try:
                # Calculate risk score
                result = engine.calculate_asset_risk(asset.id)

                # Update asset risk score
                if 'risk_score' in result:
                    asset_repo.update_risk_score(asset.id, result['risk_score'])
                    updated += 1

                processed += 1

            except Exception as e:
                logger.error(f"Error calculating risk for asset {asset.id}: {e}", exc_info=True)

        # Commit batch
        db.commit()
        logger.debug(f"Processed batch {i//batch_size + 1}: {len(batch)} assets")

    logger.info(f"Risk scoring complete: {updated}/{total_assets} assets updated")

    return {
        'tenant_id': tenant_id,
        'total_assets': total_assets,
        'processed': processed,
        'updated': updated
    }
