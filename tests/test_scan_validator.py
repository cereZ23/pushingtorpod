"""Tests for scan validation canary system."""

from __future__ import annotations

from unittest.mock import patch, MagicMock

from app.services.scan_validator import CANARY_FINDINGS


class TestCanaryFindings:
    """Verify canary list is sane."""

    def test_canaries_defined(self):
        assert len(CANARY_FINDINGS) > 0

    def test_canary_format(self):
        for url_sub, name_sub, severity in CANARY_FINDINGS:
            assert isinstance(url_sub, str) and len(url_sub) > 0
            assert isinstance(name_sub, str) and len(name_sub) > 0
            assert severity in ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL")

    def test_canary_urls_are_specific(self):
        """Canary URLs should be specific enough to avoid false matches."""
        for url_sub, _, _ in CANARY_FINDINGS:
            assert "/" in url_sub, f"Canary URL too generic: {url_sub}"
