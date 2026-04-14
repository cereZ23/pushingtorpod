"""
Tests for Finding.evidence SQLAlchemy validator.

Ensures evidence is always normalized to a dict (or None) at write time,
preventing the string-not-dict bug that caused phase 11 failures.
"""

from __future__ import annotations

import json

import pytest

from app.models.database import Finding, FindingSeverity


class TestEvidenceValidator:
    """Test the @validates('evidence') on the Finding model."""

    def _make_finding(self, evidence):
        """Create a Finding with the given evidence value."""
        return Finding(
            asset_id=1,
            name="test",
            severity=FindingSeverity.INFO,
            evidence=evidence,
        )

    def test_dict_passes_through(self):
        f = self._make_finding({"key": "val"})
        assert f.evidence == {"key": "val"}

    def test_none_passes_through(self):
        f = self._make_finding(None)
        assert f.evidence is None

    def test_empty_string_becomes_none(self):
        f = self._make_finding("")
        assert f.evidence is None

    def test_whitespace_string_becomes_none(self):
        f = self._make_finding("   ")
        assert f.evidence is None

    def test_valid_json_dict_string_parsed(self):
        f = self._make_finding('{"key": "val"}')
        assert f.evidence == {"key": "val"}

    def test_double_encoded_json_unwrapped(self):
        inner = json.dumps({"key": "val"})
        double = json.dumps(inner)  # '"{\\"key\\": \\"val\\"}"'
        f = self._make_finding(double)
        assert f.evidence == {"key": "val"}

    def test_plain_string_wrapped_in_raw(self):
        f = self._make_finding("some plain text")
        assert f.evidence == {"raw": "some plain text"}

    def test_json_string_scalar_wrapped(self):
        # json.dumps("hello") -> '"hello"'
        f = self._make_finding('"hello"')
        assert f.evidence == {"raw": "hello"}

    def test_list_wrapped_in_raw(self):
        f = self._make_finding([1, 2, 3])
        assert f.evidence == {"raw": [1, 2, 3]}

    def test_json_list_string_wrapped(self):
        f = self._make_finding("[1, 2, 3]")
        assert f.evidence == {"raw": [1, 2, 3]}

    def test_integer_wrapped(self):
        f = self._make_finding(42)
        assert f.evidence == {"raw": 42}

    def test_nested_dict_preserved(self):
        data = {"headers": {"X-Frame": "DENY"}, "status": 200}
        f = self._make_finding(data)
        assert f.evidence == data
