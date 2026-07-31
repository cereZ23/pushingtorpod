"""Device identification from TLS cert subject (Fortinet serial → model)."""

from types import SimpleNamespace

from app.services.scanning.device_fingerprint import identify_device
from app.tasks.misconfig import check_dev_001


def test_identify_fortigate_from_serial_cn():
    d = identify_device("FG100D3G15815658")
    assert d is not None
    assert d["vendor"] == "Fortinet"
    assert d["device"] == "FortiGate"
    assert d["model"] == "FortiGate-100D"
    assert d["serial"] == "FG100D3G15815658"
    assert d["unit_id"] == "3G15815658"


def test_normal_web_cert_is_not_a_device():
    assert identify_device("myrights.itsright.it") is None
    assert identify_device("*.example.com") is None
    assert identify_device("") is None
    assert identify_device(None) is None


def test_check_dev_001_emits_finding_and_ignores_web_cert():
    asset = SimpleNamespace(identifier="vpn.example.com")
    certs = [
        SimpleNamespace(subject_cn="FG100D3G15815658"),
        SimpleNamespace(subject_cn="www.example.com"),
    ]
    findings = check_dev_001(asset, [], certs, None)
    assert len(findings) == 1
    f = findings[0]
    assert f["control_id"] == "DEV-001"
    assert "FortiGate-100D" in f["name"]
    assert f["evidence"]["serial"] == "FG100D3G15815658"
    assert f["finding_key"] == "DEV-001:vpn.example.com:FG100D3G15815658"


def test_check_dev_001_dedups_same_serial():
    asset = SimpleNamespace(identifier="vpn.example.com")
    certs = [SimpleNamespace(subject_cn="FG100D3G15815658")] * 2
    assert len(check_dev_001(asset, [], certs, None)) == 1
