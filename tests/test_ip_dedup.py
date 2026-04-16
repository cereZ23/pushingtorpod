"""
Unit tests for app/services/ip_dedup.py

Covers:
- Empty input
- All-IP input (no dedup needed)
- No hostnames
- Hostnames without resolved IPs preserved
- Multiple hostnames resolving to same IP -> dedup
- Preference: DOMAIN over SUBDOMAIN, shorter identifier
- Standalone IPs preserved alongside deduped
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from app.models.database import AssetType
from app.services.ip_dedup import dedup_by_resolved_ip


def _asset(id_, type_, identifier):
    a = SimpleNamespace()
    a.id = id_
    a.type = type_
    a.identifier = identifier
    return a


def _rel(source_id, target_id):
    r = SimpleNamespace()
    r.source_asset_id = source_id
    r.target_asset_id = target_id
    r.rel_type = "resolves_to"
    return r


class _RelQuery:
    def __init__(self, rels):
        self.rels = rels

    def filter(self, *a, **kw):
        return self

    def all(self):
        return self.rels


class _IPQuery:
    def __init__(self, rows):
        self.rows = rows

    def filter(self, *a, **kw):
        return self

    def all(self):
        return self.rows


class TestDedup:
    def test_empty_input(self):
        db = MagicMock()
        result, skipped = dedup_by_resolved_ip([], tenant_id=1, db=db)
        assert result == []
        assert skipped == 0

    def test_only_ips_no_dedup(self):
        ips = [_asset(1, AssetType.IP, "1.1.1.1"), _asset(2, AssetType.IP, "2.2.2.2")]
        db = MagicMock()
        result, skipped = dedup_by_resolved_ip(ips, tenant_id=1, db=db)
        assert len(result) == 2
        assert skipped == 0

    def test_hostnames_without_relationships_preserved(self):
        hosts = [
            _asset(10, AssetType.SUBDOMAIN, "a.x.com"),
            _asset(11, AssetType.SUBDOMAIN, "b.x.com"),
        ]
        db = MagicMock()
        db.query.return_value = _RelQuery(rels=[])
        result, skipped = dedup_by_resolved_ip(hosts, tenant_id=1, db=db)
        # With no resolved IPs, all hosts preserved
        assert len(result) == 2
        assert skipped == 0

    def test_duplicate_hosts_same_ip(self):
        h1 = _asset(10, AssetType.SUBDOMAIN, "a.x.com")
        h2 = _asset(11, AssetType.SUBDOMAIN, "b.x.com")
        rels = [_rel(10, 500), _rel(11, 500)]
        db = MagicMock()
        # First query returns relationships, second returns IP rows
        db.query.side_effect = [
            _RelQuery(rels),
            _IPQuery([SimpleNamespace(id=500, identifier="1.2.3.4")]),
        ]
        result, skipped = dedup_by_resolved_ip([h1, h2], tenant_id=1, db=db)
        assert skipped == 1
        assert len(result) == 1
        # Shorter identifier wins (both same type): "a.x.com" < "b.x.com"
        assert result[0].identifier == "a.x.com"

    def test_domain_preferred_over_subdomain(self):
        domain = _asset(10, AssetType.DOMAIN, "x.com")
        sub = _asset(11, AssetType.SUBDOMAIN, "a.x.com")
        rels = [_rel(10, 500), _rel(11, 500)]
        db = MagicMock()
        db.query.side_effect = [
            _RelQuery(rels),
            _IPQuery([SimpleNamespace(id=500, identifier="1.2.3.4")]),
        ]
        result, skipped = dedup_by_resolved_ip([domain, sub], tenant_id=1, db=db)
        assert skipped == 1
        assert result[0].identifier == "x.com"

    def test_mixed_standalone_ip_and_hostnames(self):
        h1 = _asset(10, AssetType.SUBDOMAIN, "a.x.com")
        h2 = _asset(11, AssetType.SUBDOMAIN, "b.x.com")
        ip_a = _asset(20, AssetType.IP, "9.9.9.9")
        rels = [_rel(10, 500), _rel(11, 500)]
        db = MagicMock()
        db.query.side_effect = [
            _RelQuery(rels),
            _IPQuery([SimpleNamespace(id=500, identifier="1.2.3.4")]),
        ]
        result, skipped = dedup_by_resolved_ip([h1, h2, ip_a], tenant_id=1, db=db)
        assert skipped == 1
        # 1 deduped host + 1 standalone IP
        assert len(result) == 2
        ids = {a.id for a in result}
        assert 20 in ids  # standalone IP preserved

    def test_many_groups(self):
        # 3 hostnames on IP_A, 2 on IP_B, 1 without IP
        hosts = [
            _asset(1, AssetType.SUBDOMAIN, "a.x.com"),
            _asset(2, AssetType.SUBDOMAIN, "b.x.com"),
            _asset(3, AssetType.SUBDOMAIN, "c.x.com"),
            _asset(4, AssetType.SUBDOMAIN, "d.x.com"),
            _asset(5, AssetType.SUBDOMAIN, "e.x.com"),
            _asset(6, AssetType.SUBDOMAIN, "f.x.com"),
        ]
        rels = [
            _rel(1, 100),
            _rel(2, 100),
            _rel(3, 100),
            _rel(4, 200),
            _rel(5, 200),
            # 6 has no relationship
        ]
        db = MagicMock()
        db.query.side_effect = [
            _RelQuery(rels),
            _IPQuery(
                [
                    SimpleNamespace(id=100, identifier="1.1.1.1"),
                    SimpleNamespace(id=200, identifier="2.2.2.2"),
                ]
            ),
        ]
        result, skipped = dedup_by_resolved_ip(hosts, tenant_id=1, db=db)
        # 1 rep per IP group (2 groups) + 1 no-resolve = 3 total
        assert len(result) == 3
        assert skipped == 3  # (3-1) + (2-1) = 3

    def test_target_ip_rows_missing_id_skipped(self):
        # If target_ip_rows don't include an IP, that relationship is dropped
        h1 = _asset(1, AssetType.SUBDOMAIN, "a.x.com")
        h2 = _asset(2, AssetType.SUBDOMAIN, "b.x.com")
        rels = [_rel(1, 999), _rel(2, 999)]
        db = MagicMock()
        db.query.side_effect = [
            _RelQuery(rels),
            _IPQuery([]),  # No IP row -> no identifier lookup
        ]
        result, skipped = dedup_by_resolved_ip([h1, h2], tenant_id=1, db=db)
        # All go to no_ip_assets
        assert len(result) == 2
        assert skipped == 0
