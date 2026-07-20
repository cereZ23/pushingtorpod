"""Tests for the non-web service exposure control (EXP-011)."""

from unittest.mock import MagicMock, patch

from app.models.database import Asset, AssetType
from app.tasks.misconfig import _probe_tcp, check_exp_011


def _asset(identifier="host.example.com"):
    return Asset(identifier=identifier, type=AssetType.SUBDOMAIN)


class TestProbeTcp:
    def test_open_port_returns_banner(self):
        sock = MagicMock()
        sock.recv.return_value = b"SSH-2.0-OpenSSH_8.4\r\n"
        conn = MagicMock()
        conn.__enter__.return_value = sock
        conn.__exit__.return_value = False
        with patch("socket.create_connection", return_value=conn):
            is_open, banner = _probe_tcp("host.example.com", 22, 3)
        assert is_open is True
        assert "OpenSSH" in banner

    def test_closed_port(self):
        with patch("socket.create_connection", side_effect=OSError("refused")):
            is_open, banner = _probe_tcp("host.example.com", 3306, 3)
        assert is_open is False
        assert banner == ""


class TestExp011:
    def test_exposed_db_and_ssh_flagged(self):
        probe_result = {
            3306: (True, "mysql_native_password"),
            22: (True, "SSH-2.0-OpenSSH_8.4"),
            5432: (False, ""),
        }
        with patch("app.tasks.misconfig._probe_sensitive_ports", return_value=probe_result):
            findings = check_exp_011(_asset(), [], [], db=MagicMock())

        by_port = {f["evidence"]["port"]: f for f in findings}
        assert 3306 in by_port and by_port[3306]["severity"] == "high"
        assert 22 in by_port and by_port[22]["severity"] == "low"  # SSH is surface, not alarm
        assert 5432 not in by_port  # closed → no finding
        assert all(f["control_id"] == "EXP-011" for f in findings)

    def test_no_open_ports_no_findings(self):
        empty = {port: (False, "") for port in (22, 3306, 3389)}
        with patch("app.tasks.misconfig._probe_sensitive_ports", return_value=empty):
            findings = check_exp_011(_asset(), [], [], db=MagicMock())
        assert findings == []

    def test_internal_target_skipped(self):
        with patch("app.tasks.misconfig._probe_sensitive_ports") as probe:
            findings = check_exp_011(_asset("10.0.0.5"), [], [], db=MagicMock())
        assert findings == []
        probe.assert_not_called()
