"""EXP-012: cluster of non-standard, unidentified non-web ports exposed.

Mirrors the real myrights.itsright.it case: naabu found a batch of odd ports
(541, 1042, 1043, 2100-2111) that fingerprintx couldn't identify, so no per-port
finding existed. EXP-012 surfaces the cluster for manual review without claiming a
specific product.
"""

from types import SimpleNamespace

from app.tasks.misconfig import check_exp_012


def _svc(port):
    return SimpleNamespace(port=port)


def _asset(identifier="myrights.itsright.it"):
    return SimpleNamespace(identifier=identifier)


def test_flags_cluster_of_unusual_ports():
    ports = (80, 443, 21, 541, 1042, 1043, 2100, 2103, 2105, 2107, 2111)
    findings = check_exp_012(_asset(), [_svc(p) for p in ports], [], None)

    assert len(findings) == 1
    f = findings[0]
    assert f["control_id"] == "EXP-012"
    assert f["severity"] == "medium"
    assert f["finding_key"] == "EXP-012:myrights.itsright.it"
    # Web (80/443) and expected FTP control (21) are excluded; the odd ports remain.
    assert set(f["evidence"]["ports"]) == {541, 1042, 1043, 2100, 2103, 2105, 2107, 2111}


def test_no_finding_below_threshold():
    # Only 9999 is "unusual" — below the cluster threshold, so no finding.
    services = [_svc(p) for p in (80, 443, 25, 587, 9999)]
    assert check_exp_012(_asset(), services, [], None) == []


def test_excludes_web_mail_and_sensitive_ports():
    # web + mail + a sensitive port (3389, owned by EXP-011) — none count as unusual.
    services = [_svc(p) for p in (25, 110, 143, 443, 993, 995, 3389, 8443)]
    assert check_exp_012(_asset(), services, [], None) == []
