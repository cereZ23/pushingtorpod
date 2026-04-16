"""Tests for security utility functions (app/utils/security.py).

Pure-unit tests covering:
- Password strength validation
- Filename sanitization
- User input sanitization
- Domain/IP validation
- Redirect URL safety
- CSRF token generation
- Constant-time comparison
- Sensitive data masking
"""

from __future__ import annotations

from app.utils.security import (
    constant_time_compare,
    generate_csrf_token,
    is_safe_redirect_url,
    mask_sensitive_data,
    sanitize_filename,
    sanitize_user_input,
    validate_domain_name,
    validate_ip_address,
    validate_password_strength,
)


class TestValidatePasswordStrength:
    def test_strong_password(self):
        ok, err = validate_password_strength("Str0ng!Pass")
        assert ok is True
        assert err is None

    def test_too_short(self):
        ok, err = validate_password_strength("Ab1!xx")
        assert ok is False
        assert "8 characters" in err

    def test_too_long(self):
        ok, err = validate_password_strength("A" * 129 + "a1!")
        assert ok is False
        assert "128" in err

    def test_missing_uppercase(self):
        ok, err = validate_password_strength("str0ng!pass")
        assert ok is False
        assert "uppercase" in err

    def test_missing_lowercase(self):
        ok, err = validate_password_strength("STR0NG!PASS")
        assert ok is False
        assert "lowercase" in err

    def test_missing_digit(self):
        ok, err = validate_password_strength("Strong!Pass")
        assert ok is False
        assert "digit" in err

    def test_missing_special_char(self):
        ok, err = validate_password_strength("Str0ngPass123")
        assert ok is False
        assert "special" in err

    def test_password_with_special_char_accepted(self):
        # A password that meets all requirements and is not in the common list
        ok, err = validate_password_strength("StrongP@ss1word")
        assert ok is True
        assert err is None


class TestSanitizeFilename:
    def test_removes_path_separators(self):
        assert "/" not in sanitize_filename("foo/bar.txt")
        assert "\\" not in sanitize_filename("foo\\bar.txt")

    def test_removes_null_bytes(self):
        assert "\x00" not in sanitize_filename("foo\x00bar.txt")

    def test_removes_dangerous_chars(self):
        result = sanitize_filename("foo<script>.txt")
        assert "<" not in result
        assert ">" not in result

    def test_strips_leading_trailing_dots_spaces(self):
        result = sanitize_filename("  ..file.txt..  ")
        assert not result.startswith(".")
        assert not result.endswith(".")
        assert not result.startswith(" ")

    def test_empty_returns_fallback(self):
        assert sanitize_filename("") != ""
        assert sanitize_filename("...").startswith("file_")

    def test_truncates_long_filenames(self):
        long_name = "a" * 500 + ".txt"
        result = sanitize_filename(long_name, max_length=50)
        assert len(result) <= 50
        assert result.endswith(".txt")

    def test_preserves_valid_characters(self):
        assert sanitize_filename("report-2024_v1.pdf") == "report-2024_v1.pdf"


class TestSanitizeUserInput:
    def test_empty_input(self):
        assert sanitize_user_input("") == ""
        assert sanitize_user_input(None) == ""

    def test_removes_control_chars(self):
        result = sanitize_user_input("hello\x01\x02world")
        assert "\x01" not in result
        assert "\x02" not in result

    def test_preserves_newline_and_tab(self):
        # Internally newlines are escaped, tabs preserved as \t in sanitizer output
        result = sanitize_user_input("line1\nline2\tcol")
        # newline gets escaped
        assert "\\n" in result
        assert "\t" in result

    def test_truncates_to_max_length(self):
        result = sanitize_user_input("x" * 2000, max_length=500)
        assert len(result) <= 500

    def test_escapes_log_injection(self):
        result = sanitize_user_input("user\ninjected: admin")
        assert "\\n" in result


class TestValidateDomainName:
    def test_valid_domain(self):
        assert validate_domain_name("example.com") is True
        assert validate_domain_name("sub.example.com") is True
        assert validate_domain_name("a.b.c.example.co.uk") is True

    def test_trailing_dot_accepted(self):
        assert validate_domain_name("example.com.") is True

    def test_single_label_rejected(self):
        assert validate_domain_name("localhost") is False

    def test_empty_rejected(self):
        assert validate_domain_name("") is False

    def test_too_long_rejected(self):
        assert validate_domain_name("a" * 254) is False

    def test_label_too_long_rejected(self):
        assert validate_domain_name(("a" * 64) + ".com") is False

    def test_invalid_chars_rejected(self):
        assert validate_domain_name("exa mple.com") is False
        assert validate_domain_name("exa_mple.com") is False

    def test_leading_hyphen_rejected(self):
        assert validate_domain_name("-bad.com") is False
        assert validate_domain_name("bad-.com") is False


class TestValidateIpAddress:
    def test_valid_ipv4(self):
        assert validate_ip_address("192.168.1.1") is True
        assert validate_ip_address("8.8.8.8") is True

    def test_valid_ipv6(self):
        assert validate_ip_address("::1") is True
        assert validate_ip_address("2001:db8::1") is True

    def test_invalid_format(self):
        assert validate_ip_address("not-an-ip") is False
        assert validate_ip_address("999.999.999.999") is False
        assert validate_ip_address("") is False


class TestIsSafeRedirectUrl:
    def test_relative_url_safe(self):
        assert is_safe_redirect_url("/dashboard", ["example.com"]) is True

    def test_protocol_relative_unsafe(self):
        assert is_safe_redirect_url("//evil.com", ["example.com"]) is False

    def test_allowed_host(self):
        assert is_safe_redirect_url("https://example.com/page", ["example.com"]) is True

    def test_disallowed_host(self):
        assert is_safe_redirect_url("https://evil.com/page", ["example.com"]) is False

    def test_userinfo_blocked(self):
        assert is_safe_redirect_url("https://user@example.com/", ["example.com"]) is False

    def test_malformed_url_returns_false(self):
        # "not a url" gets parsed as relative, so it's OK.
        # A truly invalid value triggers the exception path.
        assert is_safe_redirect_url("http://[invalid", ["example.com"]) is False


class TestGenerateCsrfToken:
    def test_returns_non_empty_string(self):
        token = generate_csrf_token()
        assert isinstance(token, str)
        assert len(token) > 0

    def test_tokens_are_unique(self):
        t1 = generate_csrf_token()
        t2 = generate_csrf_token()
        assert t1 != t2


class TestConstantTimeCompare:
    def test_equal_strings(self):
        assert constant_time_compare("secret", "secret") is True

    def test_different_strings(self):
        assert constant_time_compare("secret", "different") is False

    def test_different_lengths(self):
        assert constant_time_compare("abc", "abcdef") is False

    def test_empty_strings(self):
        assert constant_time_compare("", "") is True


class TestMaskSensitiveData:
    def test_masks_long_string(self):
        result = mask_sensitive_data("sk_live_abc123def456", visible_chars=6)
        assert result.endswith("def456")
        assert result.startswith("*")
        assert len(result) == len("sk_live_abc123def456")

    def test_short_string_all_masked(self):
        result = mask_sensitive_data("abc", visible_chars=4)
        assert result == "****"

    def test_empty_string(self):
        assert mask_sensitive_data("") == "****"

    def test_default_visible_chars(self):
        result = mask_sensitive_data("1234567890123456")
        assert result.endswith("3456")
        assert len(result) == len("1234567890123456")
