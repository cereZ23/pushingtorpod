"""Tests for tech catalog service (app/services/tech_catalog.py).

Pure-unit tests covering:
- normalize_tech_name aliasing
- get_tech_info category lookup (exact + case-insensitive)
- Fallback to 'other' category
- Category labels and icons mapping
"""

from __future__ import annotations

from app.services.tech_catalog import (
    CATEGORY_ICONS,
    CATEGORY_LABELS,
    TECH_ALIASES,
    TECH_CATALOG,
    TECH_ICONS,
    get_tech_info,
    normalize_tech_name,
)


class TestNormalizeTechName:
    def test_exact_alias(self):
        assert normalize_tech_name("Microsoft-IIS") == "IIS"
        assert normalize_tech_name("Amazon CloudFront") == "CloudFront"
        assert normalize_tech_name("Envoy") == "Envoy Proxy"

    def test_no_alias_returns_same(self):
        assert normalize_tech_name("Nginx") == "Nginx"
        assert normalize_tech_name("RandomName") == "RandomName"

    def test_empty_string(self):
        assert normalize_tech_name("") == ""

    def test_all_aliases_resolve_to_catalog_entries_or_valid_names(self):
        # Ensure alias targets are strings
        for alias, target in TECH_ALIASES.items():
            assert isinstance(target, str)
            assert target


class TestGetTechInfo:
    def test_known_tech_returns_category(self):
        info = get_tech_info("Nginx")
        assert info["category"] in CATEGORY_LABELS
        assert info["category_label"]
        assert info["description"]

    def test_case_insensitive_lookup(self):
        info = get_tech_info("nginx")
        assert info["category"] == get_tech_info("Nginx")["category"]

    def test_case_insensitive_lookup_mixed(self):
        info = get_tech_info("NGINX")
        assert info["category"] == get_tech_info("Nginx")["category"]

    def test_unknown_tech_returns_other(self):
        info = get_tech_info("ThisDefinitelyDoesNotExist9999")
        assert info["category"] == "other"
        assert info["category_label"] == "Other"
        assert info["description"] == ""
        assert info["icon"] == ""

    def test_alias_resolves_to_catalog(self):
        # Microsoft-IIS → IIS (in TECH_CATALOG)
        info = get_tech_info("Microsoft-IIS")
        # Should not be "other"
        assert info["category"] != "other"

    def test_returns_dict_with_expected_keys(self):
        info = get_tech_info("WordPress")
        assert set(info.keys()) == {"category", "category_label", "description", "icon"}

    def test_category_label_from_mapping_or_fallback(self):
        # All known categories have labels
        info = get_tech_info("WordPress")
        cat = info["category"]
        if cat in CATEGORY_LABELS:
            assert info["category_label"] == CATEGORY_LABELS[cat]

    def test_tech_specific_icon_overrides_category_icon(self):
        # Nginx has TECH_ICONS override
        info = get_tech_info("Nginx")
        assert info["icon"] == TECH_ICONS.get("Nginx")

    def test_icon_falls_back_to_category_icon(self):
        # Pick a tech that's not in TECH_ICONS but in a known category
        # Moment.js is js-library with no explicit TECH_ICONS
        info = get_tech_info("Moment.js")
        # Icon should be the category icon or empty
        assert info["icon"] == CATEGORY_ICONS.get("js-library", "")


class TestCatalogStructure:
    def test_all_entries_have_category(self):
        for name, entry in TECH_CATALOG.items():
            assert "category" in entry, f"{name} missing category"
            assert isinstance(entry["category"], str)

    def test_all_entries_have_description(self):
        for name, entry in TECH_CATALOG.items():
            assert "description" in entry

    def test_category_labels_are_strings(self):
        for key, label in CATEGORY_LABELS.items():
            assert isinstance(key, str)
            assert isinstance(label, str)
            assert label

    def test_tech_icons_map_to_strings(self):
        for key, slug in TECH_ICONS.items():
            assert isinstance(slug, str) and slug
