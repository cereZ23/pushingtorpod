"""Detection-efficacy golden set: known positives/negatives for our controls.

Runs the actual control functions against curated inputs and asserts perfect
recall/precision. A change that stops a detection from firing (or makes it fire
spuriously) breaks this test — the regression is caught here, not by a client.
"""

import json

from app.models.database import Asset, AssetType, Service
from app.services.detection_efficacy import GoldenCase, evaluate, summarize

MISCONFIG = "app.tasks.misconfig"


def _domain(txt=None):
    md = json.dumps({"txt": txt}) if txt is not None else None
    return Asset(identifier="example.com", type=AssetType.DOMAIN, raw_metadata=md)


def _host():
    return Asset(identifier="host.example.com", type=AssetType.SUBDOMAIN)


GOLDEN_CASES = [
    # EML-001 — missing SPF (data-driven from dnsx txt)
    GoldenCase("EML-001", "spf missing", lambda: (_domain(["google-site-verification=x"]), [], []), True),
    GoldenCase("EML-001", "spf present", lambda: (_domain(["v=spf1 -all"]), [], []), False),
    # EML-003 — DMARC via live lookup (mocked)
    GoldenCase("EML-003", "dmarc missing", lambda: (_domain(), [], []), True, mocks={f"{MISCONFIG}.resolve_txt": []}),
    GoldenCase(
        "EML-003",
        "dmarc enforcing",
        lambda: (_domain(), [], []),
        False,
        mocks={f"{MISCONFIG}.resolve_txt": ["v=DMARC1; p=reject"]},
    ),
    # EML-004 — DKIM absence on a mail domain (mocked MX + selector lookups)
    GoldenCase(
        "EML-004",
        "dkim absent on mail domain",
        lambda: (_domain(), [], []),
        True,
        mocks={f"{MISCONFIG}.has_mx": True, f"{MISCONFIG}.resolve_txt": []},
    ),
    GoldenCase(
        "EML-004",
        "non-mail domain skipped",
        lambda: (_domain(), [], []),
        False,
        mocks={f"{MISCONFIG}.has_mx": False},
    ),
    # EXP-011 — sensitive non-web port exposure (mocked probe)
    GoldenCase(
        "EXP-011",
        "exposed mysql",
        lambda: (_host(), [Service(port=3306, protocol="mysql")], []),
        True,
        mocks={f"{MISCONFIG}._probe_sensitive_ports": {3306: (True, "mysql")}},
    ),
    GoldenCase(
        "EXP-011",
        "all ports closed",
        lambda: (_host(), [], []),
        False,
        mocks={f"{MISCONFIG}._probe_sensitive_ports": {22: (False, "")}},
    ),
]


class TestDetectionEfficacy:
    def test_golden_set_perfect_recall_and_precision(self):
        report = summarize(evaluate(GOLDEN_CASES))
        assert report["overall"]["recall"] == 1.0, report
        assert report["overall"]["precision"] == 1.0, report
        assert report["missed"] == [], report
        assert report["false_positives"] == [], report

    def test_harness_flags_a_regression(self):
        # A control that should fire but is fed a negative-shaped input must be
        # recorded as a miss (proves the harness actually measures recall).
        broken = [GoldenCase("EML-001", "spf present but expected", lambda: (_domain(["v=spf1 -all"]), [], []), True)]
        report = summarize(evaluate(broken))
        assert report["overall"]["recall"] == 0.0
        assert "EML-001" in report["missed"]
