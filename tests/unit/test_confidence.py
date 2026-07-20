"""Tests for finding confidence classification (presumptive vs confirmed)."""

import json

from app.services.scanning.confidence import (
    CONFIRMED,
    PRESUMPTIVE,
    confidence_from_evidence,
    derive_confidence,
)
from app.services.scanning.nuclei_service import NucleiService


class TestDeriveConfidence:
    def test_version_matcher_is_presumptive(self):
        assert derive_confidence(matcher_name="version_check") == PRESUMPTIVE
        assert derive_confidence(matcher_name="version-check") == PRESUMPTIVE
        assert derive_confidence(matcher_name="Version") == PRESUMPTIVE

    def test_behavioural_matcher_is_confirmed(self):
        assert derive_confidence(matcher_name="rce") == CONFIRMED
        assert derive_confidence(matcher_name="body-match") == CONFIRMED

    def test_no_matcher_defaults_to_confirmed(self):
        assert derive_confidence(matcher_name=None) == CONFIRMED
        assert derive_confidence() == CONFIRMED

    def test_version_tag_is_presumptive(self):
        assert derive_confidence(matcher_name="foo", tags=["tech", "version"]) == PRESUMPTIVE

    def test_non_version_tags_are_confirmed(self):
        assert derive_confidence(matcher_name="foo", tags=["cve", "rce"]) == CONFIRMED


class TestConfidenceFromEvidence:
    def test_reads_from_dict(self):
        assert confidence_from_evidence({"confidence": PRESUMPTIVE}) == PRESUMPTIVE
        assert confidence_from_evidence({"confidence": CONFIRMED}) == CONFIRMED

    def test_reads_from_json_string(self):
        assert confidence_from_evidence(json.dumps({"confidence": PRESUMPTIVE})) == PRESUMPTIVE

    def test_missing_key_defaults_confirmed(self):
        assert confidence_from_evidence({"matched_at": "x"}) == CONFIRMED

    def test_bad_value_defaults_confirmed(self):
        assert confidence_from_evidence({"confidence": "banana"}) == CONFIRMED

    def test_none_and_garbage_default_confirmed(self):
        assert confidence_from_evidence(None) == CONFIRMED
        assert confidence_from_evidence("not-json") == CONFIRMED
        assert confidence_from_evidence(42) == CONFIRMED


class TestNucleiParseSetsConfidence:
    """The nuclei parser must stamp confidence into evidence at parse time."""

    def _parse(self, result):
        finding = NucleiService(tenant_id=1).parse_nuclei_result(result)
        assert finding is not None
        return json.loads(finding["evidence"])

    def test_version_check_match_is_presumptive(self):
        result = {
            "template-id": "roundcube-detect",
            "info": {"name": "Roundcube", "severity": "info"},
            "host": "https://webmail.example.com",
            "matched-at": "https://webmail.example.com",
            "matcher-name": "version",
        }
        evidence = self._parse(result)
        assert evidence["confidence"] == PRESUMPTIVE

    def test_behavioural_match_is_confirmed(self):
        result = {
            "template-id": "CVE-2021-12345",
            "info": {"name": "RCE", "severity": "critical"},
            "host": "https://example.com",
            "matched-at": "https://example.com/x",
            "matcher-name": "body",
        }
        evidence = self._parse(result)
        assert evidence["confidence"] == CONFIRMED
