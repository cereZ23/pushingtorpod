"""Version -> CVE inference: product->CPE mapping + NVD parsing (pure core)."""

from app.services.scanning.cve_inference import (
    product_to_cpe,
    parse_nvd_cves,
    cvss_to_severity,
    infer_cves,
)


def test_product_to_cpe_known():
    assert product_to_cpe("Apache", "2.4.49") == "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"
    assert product_to_cpe("nginx", "1.18.0").startswith("cpe:2.3:a:nginx:nginx:1.18.0")
    iis = product_to_cpe("Microsoft-IIS", "10.0").split(":")
    assert iis[3] == "microsoft"  # vendor
    assert iis[4] == "internet_information_services"  # product
    assert iis[5] == "10.0"  # version


def test_product_to_cpe_version_embedded():
    assert "2.4.49" in (product_to_cpe("Apache/2.4.49", None) or "")


def test_product_to_cpe_none():
    assert product_to_cpe("SomeUnknownServer", "1.0") is None  # no curated mapping
    assert product_to_cpe("Apache", None) is None  # no version
    assert product_to_cpe(None, "1.0") is None


def test_parse_nvd_sorts_by_cvss():
    j = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2020-2",
                    "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 5.0}}]},
                    "descriptions": [],
                }
            },
            {
                "cve": {
                    "id": "CVE-2021-1",
                    "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8}}]},
                    "descriptions": [{"lang": "en", "value": "bad"}],
                }
            },
        ]
    }
    out = parse_nvd_cves(j)
    assert [c["cve_id"] for c in out] == ["CVE-2021-1", "CVE-2020-2"]
    assert out[0]["cvss"] == 9.8
    assert out[0]["description"] == "bad"


def test_cvss_severity():
    assert cvss_to_severity(9.8) == "critical"
    assert cvss_to_severity(7.5) == "high"
    assert cvss_to_severity(5.0) == "medium"
    assert cvss_to_severity(2.0) == "low"
    assert cvss_to_severity(0) == "info"


def test_infer_cves_injected_http():
    def fake_get(_cpe):
        return {"vulnerabilities": [{"cve": {"id": "CVE-X", "metrics": {}, "descriptions": []}}]}

    out = infer_cves("Apache", "2.4.49", http_get=fake_get)
    assert out and out[0]["cve_id"] == "CVE-X"
    # unmappable product -> no lookup, empty
    assert infer_cves("TotallyUnknown", "1.0", http_get=fake_get) == []
