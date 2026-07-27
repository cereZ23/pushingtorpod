"""Tests for the registrable-domain helper (app.utils.domains)."""

from __future__ import annotations

import pytest

from app.utils.domains import registrable_domain


@pytest.mark.parametrize(
    "host,expected",
    [
        ("example.com", "example.com"),
        ("www.example.com", "example.com"),
        ("api.staging.example.com", "example.com"),
        ("deep.a.b.example.co.uk", "example.co.uk"),  # multi-part suffix (PSL)
        ("EXAMPLE.COM", "example.com"),  # case-insensitive
        ("example.com.", "example.com"),  # trailing dot
        ("", None),
        (None, None),
        ("localhost", None),  # no public suffix
        ("10.0.0.1", None),  # bare IP
    ],
)
def test_registrable_domain(host, expected):
    assert registrable_domain(host) == expected
