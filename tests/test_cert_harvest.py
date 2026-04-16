"""
Unit tests for app/tasks/cert_harvest.py

Focuses on pure helpers:
- fetch_certificate: exception paths (timeout, gaierror, SSL error) -> None
- _parse_cert: invalid DER returns None
- fetch_certificate: no peer cert returns None
"""

from __future__ import annotations

import socket
import ssl
from unittest.mock import MagicMock, patch

import pytest

from app.tasks.cert_harvest import _parse_cert, fetch_certificate


class TestParseCert:
    def test_invalid_der_returns_none(self):
        assert _parse_cert(b"invalid der bytes", None, None, "x", 443) is None

    def test_empty_bytes_returns_none(self):
        assert _parse_cert(b"", None, None, "x", 443) is None


class TestFetchCertificate:
    def test_timeout_returns_none(self):
        with patch("socket.create_connection", side_effect=socket.timeout("timed out")):
            assert fetch_certificate("x.com") is None

    def test_gaierror_returns_none(self):
        with patch("socket.create_connection", side_effect=socket.gaierror("dns failure")):
            assert fetch_certificate("x.com") is None

    def test_connection_refused_returns_none(self):
        with patch("socket.create_connection", side_effect=ConnectionRefusedError()):
            assert fetch_certificate("x.com") is None

    def test_connection_reset_returns_none(self):
        with patch("socket.create_connection", side_effect=ConnectionResetError()):
            assert fetch_certificate("x.com") is None

    def test_os_error_returns_none(self):
        with patch("socket.create_connection", side_effect=OSError("boom")):
            assert fetch_certificate("x.com") is None

    def test_ssl_error_returns_none(self):
        with patch("socket.create_connection", side_effect=ssl.SSLError("tls fail")):
            assert fetch_certificate("x.com") is None

    def test_no_peer_cert_returns_none(self):
        mock_sock = MagicMock()
        mock_sock.__enter__.return_value = mock_sock
        mock_sock.__exit__.return_value = False

        mock_ssock = MagicMock()
        mock_ssock.__enter__.return_value = mock_ssock
        mock_ssock.__exit__.return_value = False
        mock_ssock.getpeercert.return_value = None

        with patch("socket.create_connection", return_value=mock_sock):
            with patch("ssl.create_default_context") as mock_ctx:
                mock_ctx.return_value.wrap_socket.return_value = mock_ssock
                assert fetch_certificate("x.com") is None

    def test_empty_binary_cert_returns_none(self):
        mock_sock = MagicMock()
        mock_sock.__enter__.return_value = mock_sock
        mock_sock.__exit__.return_value = False

        mock_ssock = MagicMock()
        mock_ssock.__enter__.return_value = mock_ssock
        mock_ssock.__exit__.return_value = False
        mock_ssock.getpeercert.return_value = b""

        with patch("socket.create_connection", return_value=mock_sock):
            with patch("ssl.create_default_context") as mock_ctx:
                mock_ctx.return_value.wrap_socket.return_value = mock_ssock
                assert fetch_certificate("x.com") is None

    def test_default_port_443(self):
        with patch("socket.create_connection", side_effect=OSError) as mock_conn:
            fetch_certificate("x.com")
        args, kwargs = mock_conn.call_args
        assert args[0] == ("x.com", 443)

    def test_custom_port(self):
        with patch("socket.create_connection", side_effect=OSError) as mock_conn:
            fetch_certificate("x.com", port=8443)
        args, _ = mock_conn.call_args
        assert args[0] == ("x.com", 8443)

    def test_custom_timeout(self):
        with patch("socket.create_connection", side_effect=OSError) as mock_conn:
            fetch_certificate("x.com", timeout=5.0)
        args, kwargs = mock_conn.call_args
        assert kwargs["timeout"] == 5.0
