"""
Unit tests for app/services/scanning/template_manager.py

Covers:
- list_templates: args construction with categories/severities, success parse,
  executor error, non-zero returncode
- update_templates: success, non-zero returncode, tool error
- get_template_info: returns parsed JSON, invalid JSON, tool error
- validate_template: valid, invalid
- get_categories: returns copy
- get_recommended_templates: known and unknown asset types
- CATEGORIES/singleton sanity checks
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from app.services.scanning.template_manager import TemplateManager, template_manager
from app.utils.secure_executor import ToolExecutionError


class _FakeExecutor:
    """Mimics the SecureToolExecutor context manager."""

    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr
        self.last_args = None
        self.input_files = []
        self.raise_on_execute = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def execute(self, tool, args, timeout=None):
        self.last_args = (tool, list(args), timeout)
        if self.raise_on_execute is not None:
            raise self.raise_on_execute
        return self.returncode, self.stdout, self.stderr

    def create_input_file(self, name, content):
        self.input_files.append((name, content))
        return f"/tmp/{name}"


def _patch_executor(fake):
    return patch(
        "app.services.scanning.template_manager.SecureToolExecutor",
        return_value=fake,
    )


class TestListTemplates:
    def test_parses_stdout_lines(self):
        fake = _FakeExecutor(returncode=0, stdout="http/cves/cve-1.yaml\nexposures/panel.yaml\n[INF] log\n")
        with _patch_executor(fake):
            mgr = TemplateManager(tenant_id=1)
            results = mgr.list_templates()
        assert any(t["path"] == "http/cves/cve-1.yaml" for t in results)
        # Lines starting with "[" should be skipped
        assert not any("[INF]" in t["path"] for t in results)
        assert fake.last_args[1][0] == "-tl"

    def test_with_categories_adds_paths(self):
        fake = _FakeExecutor(returncode=0, stdout="")
        with _patch_executor(fake):
            mgr = TemplateManager()
            mgr.list_templates(categories=["cves", "exposures"])
        args = fake.last_args[1]
        # -t cves/ and -t exposures/ should be present
        assert "-t" in args
        assert "cves/" in args
        assert "exposures/" in args

    def test_unknown_category_ignored(self):
        fake = _FakeExecutor(returncode=0, stdout="")
        with _patch_executor(fake):
            mgr = TemplateManager()
            mgr.list_templates(categories=["not-real"])
        # No -t additions from unknown cat
        args = fake.last_args[1]
        assert "-t" not in args

    def test_with_severity(self):
        fake = _FakeExecutor(returncode=0, stdout="")
        with _patch_executor(fake):
            mgr = TemplateManager()
            mgr.list_templates(severity=["critical", "high"])
        args = fake.last_args[1]
        assert "-severity" in args
        idx = args.index("-severity")
        assert args[idx + 1] == "critical,high"

    def test_executor_error_returns_empty(self):
        fake = _FakeExecutor()
        fake.raise_on_execute = ToolExecutionError("boom")
        with _patch_executor(fake):
            mgr = TemplateManager()
            results = mgr.list_templates()
        assert results == []

    def test_nonzero_returncode_still_parses_stdout(self):
        fake = _FakeExecutor(returncode=1, stdout="foo.yaml\n")
        with _patch_executor(fake):
            mgr = TemplateManager()
            results = mgr.list_templates()
        assert len(results) == 1
        assert results[0]["path"] == "foo.yaml"


class TestUpdateTemplates:
    def test_success(self):
        fake = _FakeExecutor(returncode=0, stdout="successfully updated\n")
        with _patch_executor(fake):
            mgr = TemplateManager()
            result = mgr.update_templates()
        assert result["success"] is True
        assert "timestamp" in result

    def test_failure_returncode(self):
        fake = _FakeExecutor(returncode=2, stdout="", stderr="no connection")
        with _patch_executor(fake):
            mgr = TemplateManager()
            result = mgr.update_templates()
        assert result["success"] is False
        assert result["error"] == "no connection"

    def test_tool_exec_error(self):
        fake = _FakeExecutor()
        fake.raise_on_execute = ToolExecutionError("boom")
        with _patch_executor(fake):
            mgr = TemplateManager()
            result = mgr.update_templates()
        assert result["success"] is False
        assert "boom" in result["error"]


class TestGetTemplateInfo:
    def test_returns_parsed_json(self):
        payload = {"id": "CVE-2021-1", "info": {"severity": "critical"}}
        fake = _FakeExecutor(returncode=0, stdout=json.dumps(payload))
        with _patch_executor(fake):
            mgr = TemplateManager()
            result = mgr.get_template_info("CVE-2021-1")
        assert result == payload

    def test_invalid_json_returns_none(self):
        fake = _FakeExecutor(returncode=0, stdout="not-json")
        with _patch_executor(fake):
            mgr = TemplateManager()
            assert mgr.get_template_info("x") is None

    def test_nonzero_returns_none(self):
        fake = _FakeExecutor(returncode=1, stdout="")
        with _patch_executor(fake):
            mgr = TemplateManager()
            assert mgr.get_template_info("x") is None

    def test_tool_exec_error_returns_none(self):
        fake = _FakeExecutor()
        fake.raise_on_execute = ToolExecutionError("boom")
        with _patch_executor(fake):
            mgr = TemplateManager()
            assert mgr.get_template_info("x") is None


class TestValidateTemplate:
    def test_valid(self):
        fake = _FakeExecutor(returncode=0, stdout="ok")
        with _patch_executor(fake):
            mgr = TemplateManager()
            ok, err = mgr.validate_template("id: test")
        assert ok is True and err is None

    def test_invalid(self):
        fake = _FakeExecutor(returncode=1, stderr="validation failed: ...")
        with _patch_executor(fake):
            mgr = TemplateManager()
            ok, err = mgr.validate_template("bad yaml")
        assert ok is False
        assert "validation failed" in err

    def test_tool_exec_error(self):
        fake = _FakeExecutor()
        fake.raise_on_execute = ToolExecutionError("no sandbox")
        with _patch_executor(fake):
            mgr = TemplateManager()
            ok, err = mgr.validate_template("x")
        assert ok is False
        assert "no sandbox" in err


class TestCategoriesAndRecommendations:
    def test_get_categories_returns_copy(self):
        mgr = TemplateManager()
        cats = mgr.get_categories()
        cats["new"] = {"path": "x"}
        # Original unchanged
        assert "new" not in mgr.CATEGORIES

    def test_categories_well_formed(self):
        mgr = TemplateManager()
        for name, info in mgr.get_categories().items():
            assert "path" in info
            assert "risk" in info
            assert info["risk"] in ("low", "medium", "high")

    def test_recommended_templates_web(self):
        mgr = TemplateManager()
        recs = mgr.get_recommended_templates("web")
        assert "cves/" in recs

    def test_recommended_templates_api(self):
        recs = TemplateManager().get_recommended_templates("api")
        assert "cves/" in recs

    def test_recommended_templates_subdomain(self):
        recs = TemplateManager().get_recommended_templates("subdomain")
        assert "takeovers/" in recs

    def test_recommended_templates_unknown(self):
        recs = TemplateManager().get_recommended_templates("???")
        # Falls back to default
        assert "vulnerabilities/" in recs


class TestTemplateStats:
    def test_template_stats_sums_from_list_templates(self):
        fake = _FakeExecutor(returncode=0, stdout="a.yaml\n")
        with _patch_executor(fake):
            mgr = TemplateManager()
            stats = mgr.get_template_stats()
        assert stats["total_templates"] == 1
        assert "by_category" in stats
        assert "by_severity" in stats


class TestSingleton:
    def test_module_singleton_is_template_manager(self):
        assert isinstance(template_manager, TemplateManager)
