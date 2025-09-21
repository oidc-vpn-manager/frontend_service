"""
Security tests for input validation vulnerability fixes.

This test suite validates that proper input validation prevents
injection attacks, oversized payloads, and malformed data.
"""

import pytest
from unittest.mock import Mock, patch
from flask import Flask


class TestInputValidationFix:
    """Test cases for input validation vulnerability fixes."""


    def test_validate_port_number(self):
        """Test port number validation."""
        from app.utils.input_validation import validate_port_number, InputValidationError

        # Valid ports
        assert validate_port_number(80) == 80
        assert validate_port_number("443") == 443
        assert validate_port_number("8080") == 8080

        # Invalid ports
        with pytest.raises(InputValidationError):
            validate_port_number("0")  # Too low

        with pytest.raises(InputValidationError):
            validate_port_number("65536")  # Too high

        with pytest.raises(InputValidationError):
            validate_port_number("abc")  # Not a number

        with pytest.raises(InputValidationError):
            validate_port_number("")  # Empty

    def test_validate_email(self):
        """Test email validation."""
        from app.utils.input_validation import validate_email, InputValidationError

        # Valid emails
        assert validate_email("user@example.com") == "user@example.com"
        assert validate_email("test.user+tag@domain.org") == "test.user+tag@domain.org"

        # Invalid emails
        with pytest.raises(InputValidationError):
            validate_email("not-an-email")

        with pytest.raises(InputValidationError):
            validate_email("@domain.com")

        with pytest.raises(InputValidationError):
            validate_email("user@")

        with pytest.raises(InputValidationError):
            validate_email("")

        # Test length limit
        long_email = "a" * 250 + "@example.com"
        with pytest.raises(InputValidationError):
            validate_email(long_email)

    def test_validate_date_string(self):
        """Test date string validation."""
        from app.utils.input_validation import validate_date_string, InputValidationError

        # Valid dates
        assert validate_date_string("2023-12-31") == "2023-12-31"
        assert validate_date_string("2023-01-01T10:30:00") == "2023-01-01T10:30:00"
        assert validate_date_string("2023-01-01 10:30:00") == "2023-01-01 10:30:00"

        # Invalid dates
        with pytest.raises(InputValidationError):
            validate_date_string("invalid-date")

        with pytest.raises(InputValidationError):
            validate_date_string("2023-13-01")  # Invalid month

        with pytest.raises(InputValidationError):
            validate_date_string("2023-02-30")  # Invalid day

        with pytest.raises(InputValidationError):
            validate_date_string("")

    def test_validate_search_filter_prevents_injection(self):
        """Test that search filters prevent SQL injection."""
        from app.utils.input_validation import validate_search_filter, InputValidationError

        # Valid filters
        assert validate_search_filter("subject", "CN=test.example.com") == "CN=test.example.com"
        assert validate_search_filter("issuer", "OpenVPN CA") == "OpenVPN CA"

        # SQL injection attempts
        sql_injection_attempts = [
            "; DROP TABLE certificates; --",
            "' OR '1'='1",
            "UNION SELECT password FROM users",
            "'; DELETE FROM certificates; --",
            "admin'/**/UNION/**/SELECT",
            "<script>alert('xss')</script>",
            "javascript:alert('xss')",
        ]

        for injection in sql_injection_attempts:
            with pytest.raises(InputValidationError):
                validate_search_filter("subject", injection)

    def test_validate_query_param_with_allowlist(self):
        """Test query parameter validation with allowlist."""
        from app.utils.input_validation import validate_query_param, InputValidationError

        # Valid values
        allowed_types = ['server', 'client', 'computer']
        assert validate_query_param('type', 'server', allowed_types) == 'server'
        assert validate_query_param('type', 'client', allowed_types) == 'client'

        # Invalid values
        with pytest.raises(InputValidationError):
            validate_query_param('type', 'malicious', allowed_types)

        with pytest.raises(InputValidationError):
            validate_query_param('type', 'server; DROP TABLE', allowed_types)

        # Length limit
        long_value = "a" * 1000
        with pytest.raises(InputValidationError):
            validate_query_param('test', long_value, max_length=100)

    def test_validate_form_field_comprehensive(self):
        """Test comprehensive form field validation."""
        from app.utils.input_validation import validate_form_field, InputValidationError

        # Valid fields
        assert validate_form_field('reason', 'key_compromise', required=True) == 'key_compromise'
        assert validate_form_field('comment', 'User requested revocation') == 'User requested revocation'
        assert validate_form_field('optional', '', required=False) == ''

        # Required field validation
        with pytest.raises(InputValidationError):
            validate_form_field('reason', '', required=True)

        # XSS prevention
        xss_attempts = [
            '<script>alert("xss")</script>',
            'javascript:alert("xss")',
            'onload=alert("xss")',
            'vbscript:alert("xss")',
        ]

        for xss in xss_attempts:
            with pytest.raises(InputValidationError):
                validate_form_field('test', xss)

        # Length limit
        long_content = "a" * 2000
        with pytest.raises(InputValidationError):
            validate_form_field('test', long_content, max_length=1000)

    def test_validate_certificate_fingerprint(self):
        """Test certificate fingerprint validation."""
        from app.utils.input_validation import validate_certificate_fingerprint, InputValidationError

        # Valid fingerprints
        sha1_fp = "2FD4E1C67A2D28FCED849EE1BB76E7391B93EB12"
        sha256_fp = "96BC82F4F6D3B4B9A8E9F1C2D3E4F5A6B7C8D9E0F1A2B3C4D5E6F7A8B9C0D1E2"

        assert validate_certificate_fingerprint(sha1_fp.lower()) == sha1_fp
        assert validate_certificate_fingerprint(sha256_fp.lower()) == sha256_fp

        # Invalid fingerprints
        with pytest.raises(InputValidationError):
            validate_certificate_fingerprint("invalid")

        with pytest.raises(InputValidationError):
            validate_certificate_fingerprint("12345")  # Too short

        with pytest.raises(InputValidationError):
            validate_certificate_fingerprint("GHIJKLMNOPQRSTUVWXYZ" * 3)  # Invalid hex

        with pytest.raises(InputValidationError):
            validate_certificate_fingerprint("")

    def test_validate_pagination_params(self):
        """Test pagination parameter validation."""
        from app.utils.input_validation import validate_pagination_params, InputValidationError

        # Valid pagination
        result = validate_pagination_params("1", "50")
        assert result['page'] == 1
        assert result['limit'] == 50

        result = validate_pagination_params("5", "100")
        assert result['page'] == 5
        assert result['limit'] == 100

        # Test limits and boundaries
        result = validate_pagination_params("0", "0")  # Should be corrected
        assert result['page'] == 1
        assert result['limit'] == 1

        result = validate_pagination_params("1", "2000")  # Should be capped
        assert result['page'] == 1
        assert result['limit'] == 1000

        # Invalid values
        with pytest.raises(InputValidationError):
            validate_pagination_params("abc", "50")

        with pytest.raises(InputValidationError):
            validate_pagination_params("1", "def")

    def test_validate_url_prevents_open_redirect(self):
        """Test URL validation prevents open redirect attacks."""
        from app.utils.input_validation import validate_url, InputValidationError

        # Valid URLs
        assert validate_url("https://example.com/path") == "https://example.com/path"
        assert validate_url("http://localhost:8080/admin") == "http://localhost:8080/admin"

        # Test scheme restriction
        valid_url = validate_url("https://example.com", allowed_schemes=['https'])
        assert valid_url == "https://example.com"

        with pytest.raises(InputValidationError):
            validate_url("http://example.com", allowed_schemes=['https'])

        # Invalid URLs
        with pytest.raises(InputValidationError):
            validate_url("not-a-url")

        with pytest.raises(InputValidationError):
            validate_url("javascript:alert('xss')")

        with pytest.raises(InputValidationError):
            validate_url("")

        # Length limit
        long_url = "https://example.com/" + "a" * 3000
        with pytest.raises(InputValidationError):
            validate_url(long_url)

    def test_sanitize_for_logging(self):
        """Test log sanitization to prevent log injection."""
        from app.utils.input_validation import sanitize_for_logging

        # Normal content
        assert sanitize_for_logging("normal log entry") == "normal log entry"

        # Remove control characters
        malicious_input = "log entry\n\rINJECTED LOG LINE\x00\x01"
        sanitized = sanitize_for_logging(malicious_input)
        assert "\n" not in sanitized
        assert "\r" not in sanitized
        assert "\x00" not in sanitized

        # Length truncation
        long_input = "a" * 200
        sanitized = sanitize_for_logging(long_input, max_length=50)
        assert len(sanitized) <= 53  # 50 + "..."
        assert sanitized.endswith("...")

    def test_alphanumeric_with_special_validation(self):
        """Test alphanumeric with special characters validation."""
        from app.utils.input_validation import validate_alphanumeric_with_special, InputValidationError

        # Valid inputs
        assert validate_alphanumeric_with_special("test-option_1") == "test-option_1"
        assert validate_alphanumeric_with_special("config.production") == "config.production"

        # Invalid characters
        with pytest.raises(InputValidationError):
            validate_alphanumeric_with_special("test@option")  # @ not allowed

        with pytest.raises(InputValidationError):
            validate_alphanumeric_with_special("test;option")  # ; not allowed

        with pytest.raises(InputValidationError):
            validate_alphanumeric_with_special("test|option")  # | not allowed

        # Length limit
        with pytest.raises(InputValidationError):
            validate_alphanumeric_with_special("a" * 300, max_length=100)