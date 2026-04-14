"""Tests for soft-404 detection utility."""

from __future__ import annotations

from unittest.mock import patch, MagicMock

import pytest

from app.utils.soft404 import is_soft_404, detect_soft404_hosts


class TestIsSoft404:
    """Test body pattern matching."""

    def test_empty_body_is_soft_404(self):
        assert is_soft_404("") is True

    def test_none_body_is_soft_404(self):
        assert is_soft_404(None) is True

    def test_page_not_found(self):
        assert is_soft_404("<html><body>Page Not Found</body></html>") is True

    def test_error_404_title(self):
        assert is_soft_404("<html><title>404 - Error</title></html>") is True

    def test_does_not_exist(self):
        assert is_soft_404("The resource does not exist.") is True

    def test_normal_page_not_soft_404(self):
        assert is_soft_404("<html><body>Welcome to our website</body></html>") is False

    def test_login_page_not_soft_404(self):
        assert is_soft_404("<html><form><input name='password'></form></html>") is False

    def test_json_api_not_soft_404(self):
        assert is_soft_404('{"status": "ok", "data": []}') is False


class TestDetectSoft404Hosts:
    """Test parallel host probing."""

    @patch("app.utils.soft404._probe_host")
    def test_detects_soft404_hosts(self, mock_probe):
        mock_probe.side_effect = lambda url, timeout=5.0: url == "https://soft404.example.com"

        urls = ["https://soft404.example.com", "https://good.example.com"]
        result = detect_soft404_hosts(urls)

        assert "https://soft404.example.com" in result
        assert "https://good.example.com" not in result

    @patch("app.utils.soft404._probe_host")
    def test_empty_input_returns_empty(self, mock_probe):
        result = detect_soft404_hosts([])
        assert result == set()
        mock_probe.assert_not_called()

    @patch("app.utils.soft404._probe_host")
    def test_all_good_hosts(self, mock_probe):
        mock_probe.return_value = False
        result = detect_soft404_hosts(["https://a.com", "https://b.com"])
        assert result == set()
