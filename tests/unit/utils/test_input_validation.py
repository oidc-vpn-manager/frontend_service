"""
Tests for input validation utilities in app.utils.input_validation.

These tests ensure comprehensive coverage of all validation functions.
"""

import pytest
import urllib.parse
from unittest.mock import patch
from datetime import datetime
from app.utils.input_validation import (
    InputValidationError,
    validate_email,
    validate_port_number,
    validate_url,
    validate_pagination_params,
    validate_date_string,
    validate_alphanumeric_with_special,
    validate_query_param,
    validate_search_filter,
    sanitize_for_logging
)


class TestInputValidationError:
    """Test the InputValidationError exception class."""

    def test_input_validation_error_message(self):
        """Test InputValidationError with custom message."""
        error = InputValidationError("Test validation error")
        assert str(error) == "Test validation error"

    def test_input_validation_error_inheritance(self):
        """Test InputValidationError inherits from Exception."""
        error = InputValidationError("Test error")
        assert isinstance(error, Exception)


class TestValidateUrl:
    """Test URL validation function."""

    def test_validate_url_valid_http(self):
        """Test valid HTTP URL."""
        url = "http://example.com/path"
        result = validate_url(url)
        assert result == url

    def test_validate_url_none_or_non_string(self):
        """Test URL validation with None or non-string (line 51)."""
        with pytest.raises(InputValidationError) as exc_info:
            validate_url(None)
        assert "URL must be a non-empty string" in str(exc_info.value)

        with pytest.raises(InputValidationError) as exc_info:
            validate_url(123)  # Non-string
        assert "URL must be a non-empty string" in str(exc_info.value)

        with pytest.raises(InputValidationError) as exc_info:
            validate_url("")  # Empty string
        assert "URL must be a non-empty string" in str(exc_info.value)

    def test_validate_url_invalid_format_exception(self):
        """Test URL that causes urlparse exception (lines 58-59)."""
        # Mock urlparse to raise an exception to trigger lines 58-59
        with patch('urllib.parse.urlparse') as mock_urlparse:
            mock_urlparse.side_effect = Exception("Mocked parsing error")

            with pytest.raises(InputValidationError) as exc_info:
                validate_url("http://example.com")

            assert "Invalid URL format" in str(exc_info.value)

    def test_validate_url_missing_scheme(self):
        """Test URL without scheme."""
        with pytest.raises(InputValidationError) as exc_info:
            validate_url("example.com/path")
        assert "URL must include scheme and domain" in str(exc_info.value)

    def test_validate_url_disallowed_scheme(self):
        """Test URL with disallowed scheme."""
        with pytest.raises(InputValidationError) as exc_info:
            validate_url("ftp://example.com", allowed_schemes=['http', 'https'])
        assert "URL scheme must be one of" in str(exc_info.value)

    def test_validate_url_max_length_exceeded(self):
        """Test URL exceeding maximum length."""
        long_url = "https://example.com/" + "x" * 2500  # Exceeds 2048 limit
        with pytest.raises(InputValidationError) as exc_info:
            validate_url(long_url)
        assert "URL too long" in str(exc_info.value)


class TestValidateAlphanumericWithSpecial:
    """Test alphanumeric with special characters validation."""

    def test_validate_alphanumeric_with_special_non_string(self):
        """Test validation with non-string input (line 127)."""
        with pytest.raises(InputValidationError) as exc_info:
            validate_alphanumeric_with_special(123)  # Non-string input
        assert "Text must be a string" in str(exc_info.value)

    def test_validate_alphanumeric_with_special_valid_text(self):
        """Test valid alphanumeric text."""
        text = "ValidText123"
        result = validate_alphanumeric_with_special(text)
        assert result == text

    def test_validate_alphanumeric_with_special_empty_after_strip(self):
        """Test text that's empty after stripping whitespace."""
        # This function actually allows empty strings, so this should pass
        result = validate_alphanumeric_with_special("   ")  # Only whitespace
        assert result == ""  # Should be empty string after strip

    def test_validate_alphanumeric_with_special_too_long(self):
        """Test text exceeding maximum length."""
        long_text = "x" * 300  # Exceeds default 255 limit
        with pytest.raises(InputValidationError) as exc_info:
            validate_alphanumeric_with_special(long_text)
        assert "Text too long" in str(exc_info.value)

    def test_validate_alphanumeric_with_special_invalid_chars(self):
        """Test text with invalid characters."""
        with pytest.raises(InputValidationError) as exc_info:
            validate_alphanumeric_with_special("Text with <script>")
        assert "contains invalid characters" in str(exc_info.value)


# TestValidateCertificateFingerprint removed: validate_certificate_fingerprint
# was deleted from input_validation.py (superseded by _or_404/_or_400 in utils/validation.py).

class TestValidatePortNumber:
    """Test port number validation."""

    def test_validate_port_number_string_conversion_error(self):
        """Test port number with invalid string (covers exception handling)."""
        with pytest.raises(InputValidationError) as exc_info:
            validate_port_number("not_a_number")
        assert "Port must be a valid integer" in str(exc_info.value)

    def test_validate_port_number_out_of_range(self):
        """Test port number out of valid range."""
        with pytest.raises(InputValidationError) as exc_info:
            validate_port_number(70000)  # Above 65535
        assert "Port must be between 1 and 65535" in str(exc_info.value)

    def test_validate_port_number_valid(self):
        """Test valid port number."""
        result = validate_port_number("8080")
        assert result == 8080


class TestValidatePaginationParams:
    """Test pagination parameter validation."""

    def test_validate_pagination_params_invalid_page(self):
        """Test pagination with invalid page parameter."""
        with pytest.raises(InputValidationError) as exc_info:
            validate_pagination_params("not_a_number", 10)
        assert "Page must be a valid positive integer" in str(exc_info.value)

    def test_validate_pagination_params_invalid_limit(self):
        """Test pagination with invalid limit parameter."""
        with pytest.raises(InputValidationError) as exc_info:
            validate_pagination_params(1, "not_a_number")
        assert "Limit must be a valid integer" in str(exc_info.value)

    def test_validate_pagination_params_valid(self):
        """Test valid pagination parameters."""
        result = validate_pagination_params("1", "10")
        assert result == {"page": 1, "limit": 10}

    def test_validate_pagination_params_limit_too_low(self):
        """Cover line 84: limit < 1 is capped to 1."""
        result = validate_pagination_params(1, "-5")
        assert result["limit"] == 1

    def test_validate_pagination_params_limit_too_high(self):
        """Cover line 86: limit > 1000 is capped to 1000."""
        result = validate_pagination_params(1, 9999)
        assert result["limit"] == 1000


class TestValidateQueryParam:
    """Test query parameter validation."""

    def test_validate_query_param_invalid_characters(self):
        """Test query parameter with invalid characters (covers dangerous pattern detection)."""
        with pytest.raises(InputValidationError) as exc_info:
            validate_query_param("search", "value with <script>")
        assert "Parameter search contains potentially dangerous content" in str(exc_info.value)

    def test_validate_query_param_too_long(self):
        """Test query parameter exceeding maximum length."""
        long_value = "x" * 300  # Exceeds default 255 character limit
        with pytest.raises(InputValidationError) as exc_info:
            validate_query_param("search", long_value)
        assert "Parameter search too long (max 255 characters)" in str(exc_info.value)

    def test_validate_query_param_valid(self):
        """Test valid query parameter."""
        result = validate_query_param("search", "valid search term")
        assert result == "valid search term"

    def test_validate_query_param_non_string(self):
        """Test query parameter with non-string value (line 164)."""
        with pytest.raises(InputValidationError) as exc_info:
            validate_query_param("page", 123)  # Integer instead of string
        assert "Parameter page must be a string" in str(exc_info.value)

    def test_validate_query_param_not_in_allowed_values(self):
        """Cover line 158: value not in allowed_values list."""
        with pytest.raises(InputValidationError) as exc_info:
            validate_query_param("type", "invalid", allowed_values=["server", "client"])
        assert "must be one of" in str(exc_info.value)


# TestValidateFormField removed: validate_form_field was deleted from
# input_validation.py (superseded by WTForms validators).

class TestValidateSearchFilter:
    """Test search filter validation."""

    def test_validate_search_filter_invalid_characters(self):
        """Test search filter with invalid characters (covers SQL injection prevention)."""
        with pytest.raises(InputValidationError) as exc_info:
            validate_search_filter("status", "active<script>")
        assert "Filter status contains invalid characters" in str(exc_info.value)

    def test_validate_search_filter_valid(self):
        """Test valid search filter."""
        result = validate_search_filter("status", "active")
        assert result == "active"

    def test_validate_search_filter_non_string(self):
        """Test search filter with non-string value (line 229)."""
        with pytest.raises(InputValidationError) as exc_info:
            validate_search_filter("status", 123)  # Integer instead of string
        assert "Filter status must be a string" in str(exc_info.value)

    def test_validate_search_filter_too_long(self):
        """Test search filter exceeding length limit (line 235)."""
        long_filter = "x" * 501  # Exceeds 500 character limit
        with pytest.raises(InputValidationError) as exc_info:
            validate_search_filter("description", long_filter)
        assert "Filter description too long (max 500 characters)" in str(exc_info.value)


class TestSanitizeForLogging:
    """Test logging sanitization function."""

    def test_sanitize_for_logging_too_long(self):
        """Test sanitizing text that's too long."""
        long_text = "x" * 200  # Exceeds default 100 character limit
        result = sanitize_for_logging(long_text)
        assert len(result) == 103  # 100 chars + "..."
        assert result.endswith("...")

    def test_sanitize_for_logging_non_string(self):
        """Test sanitizing non-string values (line 258)."""
        result = sanitize_for_logging(12345)  # Integer input
        assert result == "12345"

        result = sanitize_for_logging(None)  # None input
        assert result == "None"

    def test_sanitize_for_logging_special_chars(self):
        """Test sanitizing text with special characters."""
        text = "Text with \n newlines \t tabs"
        result = sanitize_for_logging(text)
        assert "\n" not in result
        assert "\t" not in result

    def test_sanitize_for_logging_normal_text(self):
        """Test sanitizing normal text."""
        text = "Normal log message"
        result = sanitize_for_logging(text)
        assert result == text


class TestValidateEmail:
    """Test email validation function."""

    def test_validate_email_valid(self):
        """Test valid email address."""
        email = "test@example.com"
        result = validate_email(email)
        assert result == email

    def test_validate_email_none_or_non_string(self):
        """Test email validation with None or non-string (line 22)."""
        with pytest.raises(InputValidationError) as exc_info:
            validate_email(None)
        assert "Email must be a non-empty string" in str(exc_info.value)

        with pytest.raises(InputValidationError) as exc_info:
            validate_email(123)  # Non-string
        assert "Email must be a non-empty string" in str(exc_info.value)

        with pytest.raises(InputValidationError) as exc_info:
            validate_email("")  # Empty string
        assert "Email must be a non-empty string" in str(exc_info.value)

    def test_validate_email_invalid_format(self):
        """Test invalid email format."""
        with pytest.raises(InputValidationError) as exc_info:
            validate_email("invalid-email")
        assert "Invalid email format" in str(exc_info.value)

    def test_validate_email_too_long(self):
        """Test email that's too long."""
        long_email = "x" * 250 + "@example.com"  # Exceeds 254 character limit
        with pytest.raises(InputValidationError) as exc_info:
            validate_email(long_email)
        assert "Email address too long" in str(exc_info.value)


class TestValidateDateString:
    """Test date string validation function."""

    def test_validate_date_string_valid(self):
        """Test valid ISO date string."""
        date_str = "2023-12-25"
        result = validate_date_string(date_str)
        assert result == date_str

    def test_validate_date_string_invalid_format(self):
        """Test invalid date format."""
        with pytest.raises(InputValidationError) as exc_info:
            validate_date_string("invalid-date")
        assert "Date must be in valid format (YYYY-MM-DD or ISO datetime)" in str(exc_info.value)

    def test_validate_date_string_none_or_non_string(self):
        """Test date validation with None or non-string (line 94)."""
        with pytest.raises(InputValidationError) as exc_info:
            validate_date_string(None)
        assert "Date must be a non-empty string" in str(exc_info.value)

        with pytest.raises(InputValidationError) as exc_info:
            validate_date_string("")  # Empty string

    def test_validate_date_string_iso_datetime_format(self):
        """Cover line 112: datetime with T (ISO datetime format)."""
        result = validate_date_string("2024-06-15T10:30:00Z")
        assert result == "2024-06-15T10:30:00Z"

    def test_validate_date_string_space_datetime_format(self):
        """Cover line 114: datetime with space separator."""
        result = validate_date_string("2024-06-15 10:30:00")
        assert result == "2024-06-15 10:30:00"

    def test_validate_date_string_invalid_date_value(self):
        """Cover lines 117-118: string matches regex but fails date parsing."""
        with pytest.raises(InputValidationError) as exc_info:
            validate_date_string("2024-13-99")  # matches \d{4}-\d{2}-\d{2} but month 13 is invalid
        assert "Invalid date value" in str(exc_info.value)