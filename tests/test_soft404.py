"""Tests for soft-404 detection utility."""

from __future__ import annotations

from unittest.mock import patch, MagicMock

import pytest

from app.utils.soft404 import is_soft_404, detect_soft404_hosts, detect_dead_hosts, _probe_host_alive


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


class TestDeadHostPruning:
    """A host is dead only when every probe fails/5xx; a single alive probe keeps it."""

    def _client(self, statuses):
        """A fake httpx.Client whose .get() yields the given statuses in order,
        or raises when the item is an Exception."""
        seq = iter(statuses)

        class _Resp:
            def __init__(self, code):
                self.status_code = code

        class _Client:
            def __enter__(self_):
                return self_

            def __exit__(self_, *a):
                return False

            def get(self_, url):
                item = next(seq)
                if isinstance(item, Exception):
                    raise item
                return _Resp(item)

        return _Client()

    @patch("app.utils.soft404.httpx.Client")
    def test_alive_when_any_probe_under_min_status(self, mock_client):
        import httpx

        # root times out, but /robots.txt returns 404 (<500) → ALIVE
        mock_client.return_value = self._client([httpx.TimeoutException("t"), 404])
        assert _probe_host_alive("https://x.example.com") is True

    @patch("app.utils.soft404.httpx.Client")
    def test_dead_when_all_probes_5xx_or_timeout(self, mock_client):
        import httpx

        mock_client.return_value = self._client([500, httpx.ConnectError("c")])
        assert _probe_host_alive("https://dead.example.com") is False

    @patch("app.utils.soft404._probe_host_alive")
    def test_detect_dead_hosts_returns_only_dead(self, mock_alive):
        mock_alive.side_effect = lambda url, timeout=6.0, min_status=500: url != "https://dead.example.com"
        result = detect_dead_hosts(["https://dead.example.com", "https://live.example.com"])
        assert result == {"https://dead.example.com"}

    @patch("app.utils.soft404._probe_host_alive")
    def test_detect_dead_hosts_empty_input(self, mock_alive):
        assert detect_dead_hosts([]) == set()
        mock_alive.assert_not_called()
