"""The shared canonical endpoint-shape string — the single identity for endpoint coverage.

id/hash path segments collapse to {id}, query VALUES drop (param NAMES kept), so two URLs with the
same attack surface map to the same shape, and NO secret/token value is ever persisted.
"""

from __future__ import annotations

from app.tasks.scanning import endpoint_shape_string


def test_id_path_segments_collapse():
    assert endpoint_shape_string("https://h.example/user/1/edit") == endpoint_shape_string(
        "https://h.example/user/2/edit"
    )
    assert endpoint_shape_string("https://h.example/user/1") == "h.example|/user/{id}|"


def test_hash_id_segments_collapse():
    a = endpoint_shape_string("https://h.example/o/deadbeefcafe1234/x")
    b = endpoint_shape_string("https://h.example/o/0011223344556677/x")
    assert a == b and "{id}" in a


def test_query_values_dropped_names_kept():
    a = endpoint_shape_string("https://h.example/search?q=secrettoken&page=2")
    b = endpoint_shape_string("https://h.example/search?q=other&page=9")
    assert a == b
    assert "secrettoken" not in a and "other" not in b  # no VALUES persisted
    assert a == "h.example|/search|page,q"  # param names, sorted


def test_different_param_set_is_a_different_shape():
    assert endpoint_shape_string("https://h.example/x?a=1") != endpoint_shape_string("https://h.example/x?b=1")


def test_host_lowercased_and_deterministic():
    s1 = endpoint_shape_string("https://H.Example.COM/Path")
    s2 = endpoint_shape_string("https://h.example.com/Path")
    assert s1 == s2
    assert {endpoint_shape_string("https://h.example/a/1") for _ in range(5)} == {"h.example|/a/{id}|"}


def test_base_url_shape_has_no_path_or_params():
    assert endpoint_shape_string("https://h.example") == "h.example||"
    assert endpoint_shape_string("https://h.example/") == "h.example|/|"
