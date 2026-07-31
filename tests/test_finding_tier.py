"""finding_tier: exposure vs hygiene classification (biases toward exposure)."""

from app.services.scanning.finding_tier import finding_tier


def test_hygiene_best_practice_findings():
    assert finding_tier("Missing HSTS header (Security Headers check)") == "hygiene"
    assert finding_tier("Weak Cipher Suites Detection") == "hygiene"
    assert finding_tier("SPF record not found") == "hygiene"
    assert finding_tier("DMARC policy missing") == "hygiene"
    assert finding_tier("Self-signed certificate") == "hygiene"
    assert finding_tier("Content-Security-Policy header missing") == "hygiene"


def test_actionable_exposures():
    assert finding_tier("RDP exposed to the internet on port 3389") == "exposure"
    assert finding_tier("FTP on port 21 transmits credentials in cleartext") == "exposure"
    assert finding_tier("CVE-2021-44228 Apache Log4j RCE", "cves/2021/CVE-2021-44228") == "exposure"
    assert finding_tier("Exposed admin login panel") == "exposure"
    assert finding_tier("2 non-standard service ports exposed to the internet") == "exposure"


def test_defaults_to_exposure_when_unknown():
    assert finding_tier("Some brand new finding") == "exposure"
    assert finding_tier(None, None, None) == "exposure"
