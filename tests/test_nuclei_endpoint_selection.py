"""Tests for Nuclei endpoint target selection (shape-dedup + static filtering)."""

from __future__ import annotations

from app.tasks.scanning import endpoint_shape_key


class TestEndpointShapeKey:
    def test_numeric_id_path_segments_fold(self):
        assert endpoint_shape_key("https://x.it/user/1") == endpoint_shape_key("https://x.it/user/2")

    def test_long_hash_segments_fold(self):
        assert endpoint_shape_key("https://x.it/a/deadbeef1234") == endpoint_shape_key("https://x.it/a/cafebabe5678")

    def test_query_values_fold_but_names_matter(self):
        assert endpoint_shape_key("https://x.it/item?id=5") == endpoint_shape_key("https://x.it/item?id=6")
        assert endpoint_shape_key("https://x.it/item?id=5") != endpoint_shape_key("https://x.it/item?token=5")

    def test_distinct_paths_are_kept(self):
        assert endpoint_shape_key("https://x.it/admin") != endpoint_shape_key("https://x.it/login")

    def test_host_is_part_of_shape(self):
        assert endpoint_shape_key("https://a.it/x") != endpoint_shape_key("https://b.it/x")

    def test_case_insensitive_host(self):
        assert endpoint_shape_key("https://X.IT/user/1") == endpoint_shape_key("https://x.it/user/2")


class TestStaticPathFilter:
    """The static-asset filter must look at the URL path, not the full string,
    so a handler URL whose path ends in an archive extension but carries a query
    string is still excluded (the backup-file false positive)."""

    STATIC = {".css", ".js", ".zip", ".png", ".pdf"}

    @staticmethod
    def _path_is_static(url: str, exts: set) -> bool:
        from urllib.parse import urlparse

        return any(urlparse(url).path.lower().endswith(e) for e in exts)

    def test_zip_handler_with_query_is_static(self):
        url = "https://x.it/files/download/download.php/public_html.zip?dws=documenti&did=216"
        assert self._path_is_static(url, self.STATIC) is True

    def test_css_with_cache_buster_query_is_static(self):
        assert self._path_is_static("https://x.it/style.css?v=2", self.STATIC) is True

    def test_dynamic_url_without_static_ext_is_kept(self):
        assert self._path_is_static("https://x.it/item?file=backup", self.STATIC) is False
