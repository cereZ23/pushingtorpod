"""
Tests for finding deduplication service (app/services/dedup.py).

Covers:
- Fingerprint computation determinism
- Tenant isolation (different tenant_id → different fingerprint)
- Case normalization
- Whitespace handling
- Optional field handling (None matcher_name, None template_id)
- Different sources produce different fingerprints
"""

import hashlib

import pytest

from app.services.dedup import compute_finding_fingerprint


class TestComputeFindingFingerprint:
    """Tests for compute_finding_fingerprint()."""

    def test_deterministic_output(self):
        """Same inputs always produce the same fingerprint."""
        fp1 = compute_finding_fingerprint(1, "example.com", "CVE-2021-44228", "version", "nuclei")
        fp2 = compute_finding_fingerprint(1, "example.com", "CVE-2021-44228", "version", "nuclei")
        assert fp1 == fp2

    def test_returns_64_char_hex(self):
        """Output is a 64-character lowercase hex string (SHA-256)."""
        fp = compute_finding_fingerprint(1, "test.com", "template-1")
        assert len(fp) == 64
        assert fp == fp.lower()
        # Verify it's valid hex
        int(fp, 16)

    def test_tenant_isolation(self):
        """Different tenant_id produces different fingerprint."""
        fp1 = compute_finding_fingerprint(1, "example.com", "CVE-2021-44228")
        fp2 = compute_finding_fingerprint(2, "example.com", "CVE-2021-44228")
        assert fp1 != fp2

    def test_different_assets_different_fingerprint(self):
        """Different asset identifiers produce different fingerprints."""
        fp1 = compute_finding_fingerprint(1, "a.example.com", "CVE-2021-44228")
        fp2 = compute_finding_fingerprint(1, "b.example.com", "CVE-2021-44228")
        assert fp1 != fp2

    def test_different_templates_different_fingerprint(self):
        """Different template_id produces different fingerprints."""
        fp1 = compute_finding_fingerprint(1, "example.com", "CVE-2021-44228")
        fp2 = compute_finding_fingerprint(1, "example.com", "CVE-2022-12345")
        assert fp1 != fp2

    def test_different_sources_different_fingerprint(self):
        """Different source scanner produces different fingerprints."""
        fp1 = compute_finding_fingerprint(1, "example.com", "weak-header", source="misconfig")
        fp2 = compute_finding_fingerprint(1, "example.com", "weak-header", source="nuclei")
        assert fp1 != fp2

    def test_case_normalization(self):
        """Asset identifier and template_id are lowercased."""
        fp1 = compute_finding_fingerprint(1, "EXAMPLE.COM", "CVE-2021-44228")
        fp2 = compute_finding_fingerprint(1, "example.com", "cve-2021-44228")
        assert fp1 == fp2

    def test_whitespace_stripped(self):
        """Leading/trailing whitespace is stripped from inputs."""
        fp1 = compute_finding_fingerprint(1, "  example.com  ", " CVE-2021-44228 ")
        fp2 = compute_finding_fingerprint(1, "example.com", "CVE-2021-44228")
        assert fp1 == fp2

    def test_none_matcher_name(self):
        """None matcher_name is handled gracefully (treated as empty string)."""
        fp = compute_finding_fingerprint(1, "example.com", "template-1", matcher_name=None)
        assert len(fp) == 64

    def test_none_template_id(self):
        """None template_id is handled gracefully (treated as empty string)."""
        fp = compute_finding_fingerprint(1, "example.com", None, source="misconfig")
        assert len(fp) == 64

    def test_matcher_name_affects_fingerprint(self):
        """Different matcher_name produces different fingerprint."""
        fp1 = compute_finding_fingerprint(1, "example.com", "CVE-2021-44228", "version-check")
        fp2 = compute_finding_fingerprint(1, "example.com", "CVE-2021-44228", "header-check")
        assert fp1 != fp2

    def test_matches_manual_sha256(self):
        """Verify the fingerprint matches a manually computed SHA-256."""
        # The formula: SHA256("1|example.com|cve-2021-44228||nuclei")
        expected_payload = "1|example.com|cve-2021-44228||nuclei"
        expected = hashlib.sha256(expected_payload.encode("utf-8")).hexdigest()
        actual = compute_finding_fingerprint(1, "example.com", "CVE-2021-44228", None, "nuclei")
        assert actual == expected

    def test_default_source_is_nuclei(self):
        """Default source parameter is 'nuclei'."""
        fp_default = compute_finding_fingerprint(1, "example.com", "template-1")
        fp_explicit = compute_finding_fingerprint(1, "example.com", "template-1", source="nuclei")
        assert fp_default == fp_explicit
