"""Pipeline phase implementations, split by functional area.

Modules:
- discovery:       Phases 0, 1, 1b, 1c, 1d, 1e
- enumeration:     Phases 2, 3, 4, 4b, 5, 5b, 5c
- reconnaissance:  Phases 6, 6b, 6c, 7
- detection:       Phases 8, 9, 10, 11, 12
"""

from app.tasks.pipeline_phases.discovery import (
    _phase_0_seed_ingestion,
    _phase_1_passive_discovery,
    _phase_1b_github_dorking,
    _phase_1c_whois_discovery,
    _phase_1d_cloud_buckets,
    _phase_1e_cloud_enum,
)
from app.tasks.pipeline_phases.enumeration import (
    _phase_2_dns_bruteforce,
    _phase_3_dns_resolution,
    _phase_4_http_probing,
    _phase_4b_tls_collection,
    _phase_5_port_scanning,
    _phase_5b_cdn_detection,
    _phase_5c_service_fingerprint,
)
from app.tasks.pipeline_phases.reconnaissance import (
    _phase_6_fingerprinting,
    _phase_6b_web_crawling,
    _phase_6c_sensitive_paths,
    _phase_7_visual_recon,
)
from app.tasks.pipeline_phases.detection import (
    _phase_8_misconfig_detection,
    _phase_9_vuln_scanning,
    _phase_10_correlation,
    _phase_11_risk_scoring,
    _phase_12_diff_alerting,
)

__all__ = [
    '_phase_0_seed_ingestion',
    '_phase_1_passive_discovery',
    '_phase_1b_github_dorking',
    '_phase_1c_whois_discovery',
    '_phase_1d_cloud_buckets',
    '_phase_1e_cloud_enum',
    '_phase_2_dns_bruteforce',
    '_phase_3_dns_resolution',
    '_phase_4_http_probing',
    '_phase_4b_tls_collection',
    '_phase_5_port_scanning',
    '_phase_5b_cdn_detection',
    '_phase_5c_service_fingerprint',
    '_phase_6_fingerprinting',
    '_phase_6b_web_crawling',
    '_phase_6c_sensitive_paths',
    '_phase_7_visual_recon',
    '_phase_8_misconfig_detection',
    '_phase_9_vuln_scanning',
    '_phase_10_correlation',
    '_phase_11_risk_scoring',
    '_phase_12_diff_alerting',
]
