"""Tests for CSV formula-injection neutralization in exports."""

from app.api.routers.reports import _csv_safe


class TestCsvSafe:
    def test_formula_cells_are_prefixed(self):
        assert _csv_safe('=HYPERLINK("http://evil")') == '\'=HYPERLINK("http://evil")'
        assert _csv_safe("+1+1") == "'+1+1"
        assert _csv_safe("-2+3") == "'-2+3"
        assert _csv_safe("@SUM(A1)") == "'@SUM(A1)"
        assert _csv_safe("\tcmd") == "'\tcmd"

    def test_normal_values_untouched(self):
        assert _csv_safe("www.example.com") == "www.example.com"
        assert _csv_safe("CVE-2021-1234") == "CVE-2021-1234"
        assert _csv_safe(200) == "200"

    def test_none_becomes_empty(self):
        assert _csv_safe(None) == ""
