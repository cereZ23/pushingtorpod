"""Tests for the mail-security controls in app/tasks/misconfig.py.

Covers the SSRF probe guard, the revived SPF check, and the new POP3/IMAP
(EML-008) and FTP (EML-009) cleartext controls. Network is mocked — no real
sockets are opened.
"""

import ftplib
import json
from unittest.mock import MagicMock, patch

from app.models.database import Asset, AssetType, Service
from app.tasks.misconfig import (
    _is_safe_probe_target,
    check_eml_001,
    check_eml_008,
    check_eml_009,
)


def _asset(identifier="mail.example.com", raw_metadata=None):
    return Asset(
        identifier=identifier,
        type=AssetType.SUBDOMAIN,
        raw_metadata=raw_metadata,
    )


def _service(port, protocol=None):
    return Service(port=port, protocol=protocol)


class TestSafeProbeTarget:
    def test_public_hostname_allowed(self):
        assert _is_safe_probe_target("mail.example.com") is True

    def test_public_ip_allowed(self):
        assert _is_safe_probe_target("8.8.8.8") is True

    def test_private_ip_blocked(self):
        assert _is_safe_probe_target("10.0.0.5") is False
        assert _is_safe_probe_target("192.168.1.10") is False
        assert _is_safe_probe_target("127.0.0.1") is False

    def test_metadata_endpoint_blocked(self):
        assert _is_safe_probe_target("169.254.169.254") is False

    def test_internal_tld_blocked(self):
        assert _is_safe_probe_target("host.internal") is False
        assert _is_safe_probe_target("db.local") is False

    def test_empty_blocked(self):
        assert _is_safe_probe_target("") is False


class TestSpfRevived:
    """EML-001 must read the 'txt' key that dnsx actually populates."""

    def test_missing_spf_flagged(self):
        asset = _asset("example.com", json.dumps({"txt": ["google-site-verification=abc"]}))
        findings = check_eml_001(asset, [], [], db=MagicMock())
        assert len(findings) == 1
        assert findings[0]["control_id"] == "EML-001"

    def test_present_spf_not_flagged(self):
        asset = _asset("example.com", json.dumps({"txt": ["v=spf1 include:_spf.google.com -all"]}))
        findings = check_eml_001(asset, [], [], db=MagicMock())
        assert findings == []

    def test_no_txt_records_not_flagged(self):
        # Nothing resolved → cannot assert missing SPF (avoid false positives).
        asset = _asset("example.com", json.dumps({"a": ["1.2.3.4"]}))
        findings = check_eml_001(asset, [], [], db=MagicMock())
        assert findings == []


def _mock_sock(recv_chunks):
    """Build a socket whose context-manager yields a socket returning chunks."""
    sock = MagicMock()
    sock.recv.side_effect = recv_chunks
    conn = MagicMock()
    conn.__enter__.return_value = sock
    conn.__exit__.return_value = False
    return conn


class TestPop3ImapCleartext:
    def test_pop3_without_starttls_is_high(self):
        asset = _asset("mail.example.com")
        svc = _service(110, "pop3")
        conn = _mock_sock([b"+OK POP3 ready\r\n", b"+OK\r\nUSER\r\nUIDL\r\n."])
        with patch("socket.create_connection", return_value=conn):
            findings = check_eml_008(asset, [svc], [], db=MagicMock())
        assert len(findings) == 1
        assert findings[0]["control_id"] == "EML-008"
        assert findings[0]["severity"] == "high"  # no STLS advertised
        assert findings[0]["evidence"]["starttls_offered"] is False

    def test_imap_with_starttls_is_medium(self):
        asset = _asset("mail.example.com")
        svc = _service(143, "imap")
        conn = _mock_sock([b"* OK IMAP ready\r\n", b"* CAPABILITY IMAP4rev1 STARTTLS\r\na1 OK\r\n"])
        with patch("socket.create_connection", return_value=conn):
            findings = check_eml_008(asset, [svc], [], db=MagicMock())
        assert len(findings) == 1
        assert findings[0]["severity"] == "medium"  # STARTTLS offered
        assert findings[0]["evidence"]["starttls_offered"] is True

    def test_tls_ports_ignored(self):
        asset = _asset("mail.example.com")
        # 993/995 are implicit TLS — not probed/flagged
        with patch("socket.create_connection") as conn:
            findings = check_eml_008(asset, [_service(993), _service(995)], [], db=MagicMock())
        assert findings == []
        conn.assert_not_called()

    def test_internal_target_skipped(self):
        asset = _asset("10.0.0.9")
        with patch("socket.create_connection") as conn:
            findings = check_eml_008(asset, [_service(110)], [], db=MagicMock())
        assert findings == []
        conn.assert_not_called()


class TestFtpCleartext:
    def _mock_ftp(self, login_ok=True, welcome="220 vsftpd ready"):
        ftp = MagicMock()
        ftp.getwelcome.return_value = welcome
        if login_ok:
            ftp.login.return_value = "230 Login successful"
        else:
            ftp.login.side_effect = ftplib.error_perm("530 Login incorrect")
        return ftp

    def test_anonymous_login_is_high(self):
        asset = _asset("ftp.example.com")
        with patch("ftplib.FTP", return_value=self._mock_ftp(login_ok=True)):
            findings = check_eml_009(asset, [_service(21, "ftp")], [], db=MagicMock())
        assert len(findings) == 1
        assert findings[0]["control_id"] == "EML-009"
        assert findings[0]["severity"] == "high"
        assert findings[0]["evidence"]["anonymous_login"] is True

    def test_cleartext_without_anonymous_is_medium(self):
        asset = _asset("ftp.example.com")
        with patch("ftplib.FTP", return_value=self._mock_ftp(login_ok=False)):
            findings = check_eml_009(asset, [_service(21, "ftp")], [], db=MagicMock())
        assert len(findings) == 1
        assert findings[0]["severity"] == "medium"
        assert findings[0]["evidence"]["anonymous_login"] is False

    def test_unreachable_ftp_no_finding(self):
        asset = _asset("ftp.example.com")
        ftp = MagicMock()
        ftp.connect.side_effect = OSError("connection refused")
        with patch("ftplib.FTP", return_value=ftp):
            findings = check_eml_009(asset, [_service(21, "ftp")], [], db=MagicMock())
        assert findings == []
