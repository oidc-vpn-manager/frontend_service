"""
Input validation utilities for OIDC VPN Manager Frontend.

This module provides comprehensive input validation to prevent injection attacks,
oversized payloads, and malformed data from entering the application.
"""

import re
import urllib.parse
from typing import Union, List, Optional, Dict, Any
from datetime import datetime


class InputValidationError(Exception):
    """Exception raised when input validation fails."""
    pass


def validate_email(email: str) -> str:
    """Validate email address format."""
    if not email or not isinstance(email, str):
        raise InputValidationError("Email must be a non-empty string")

    if len(email) > 254:  # RFC 5321 limit
        raise InputValidationError("Email address too long")

    # Basic email validation pattern
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(email_pattern, email):
        raise InputValidationError("Invalid email format")

    return email.lower().strip()


def validate_port_number(port: Union[str, int]) -> int:
    """Validate port number (1-65535)."""
    try:
        port_int = int(port)
    except (ValueError, TypeError):
        raise InputValidationError("Port must be a valid integer")

    if not (1 <= port_int <= 65535):
        raise InputValidationError("Port must be between 1 and 65535")

    return port_int


def validate_url(url: str, allowed_schemes: List[str] = None) -> str:
    """Validate URL format and scheme."""
    if not url or not isinstance(url, str):
        raise InputValidationError("URL must be a non-empty string")

    if len(url) > 2048:  # Reasonable URL length limit
        raise InputValidationError("URL too long")

    try:
        parsed = urllib.parse.urlparse(url)
    except Exception:
        raise InputValidationError("Invalid URL format")

    if not parsed.scheme or not parsed.netloc:
        raise InputValidationError("URL must include scheme and domain")

    if allowed_schemes and parsed.scheme not in allowed_schemes:
        raise InputValidationError(f"URL scheme must be one of: {', '.join(allowed_schemes)}")

    return url.strip()


def validate_pagination_params(page: Union[str, int], limit: Union[str, int]) -> Dict[str, int]:
    """Validate pagination parameters."""
    try:
        page_int = max(1, int(page)) if page else 1
    except (ValueError, TypeError):
        raise InputValidationError("Page must be a valid positive integer")

    try:
        limit_int = int(limit) if limit else 50
    except (ValueError, TypeError):
        raise InputValidationError("Limit must be a valid integer")

    # Cap limit to prevent resource exhaustion
    if limit_int < 1:
        limit_int = 1
    elif limit_int > 1000:
        limit_int = 1000

    return {'page': page_int, 'limit': limit_int}


def validate_date_string(date_str: str) -> str:
    """Validate date string in ISO format."""
    if not date_str or not isinstance(date_str, str):
        raise InputValidationError("Date must be a non-empty string")

    date_str = date_str.strip()

    # Allow common date formats
    date_patterns = [
        r'^\d{4}-\d{2}-\d{2}$',  # YYYY-MM-DD
        r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z?$',  # ISO datetime
        r'^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$',  # YYYY-MM-DD HH:MM:SS
    ]

    if not any(re.match(pattern, date_str) for pattern in date_patterns):
        raise InputValidationError("Date must be in valid format (YYYY-MM-DD or ISO datetime)")

    # Try to parse to ensure it's a valid date
    try:
        # Try different parsing approaches
        if 'T' in date_str:
            datetime.fromisoformat(date_str.rstrip('Z'))
        elif ' ' in date_str:
            datetime.strptime(date_str, '%Y-%m-%d %H:%M:%S')
        else:
            datetime.strptime(date_str, '%Y-%m-%d')
    except ValueError:
        raise InputValidationError("Invalid date value")

    return date_str


def validate_alphanumeric_with_special(text: str, max_length: int = 255,
                                     allowed_chars: str = "-_. ") -> str:
    """Validate text allowing alphanumeric and specified special characters."""
    if not isinstance(text, str):
        raise InputValidationError("Text must be a string")

    text = text.strip()

    if len(text) > max_length:
        raise InputValidationError(f"Text too long (max {max_length} characters)")

    # Create pattern with allowed characters
    pattern = rf'^[a-zA-Z0-9{re.escape(allowed_chars)}]*$'
    if not re.match(pattern, text):
        raise InputValidationError(f"Text contains invalid characters. Allowed: letters, numbers, {allowed_chars}")

    return text


# validate_certificate_fingerprint removed: superseded by
# validate_certificate_fingerprint_or_404 / _or_400 in app.utils.validation.

def validate_query_param(param_name: str, param_value: str,
                        allowed_values: Optional[List[str]] = None,
                        max_length: int = 255) -> str:
    """Validate query parameter value."""
    if not isinstance(param_value, str):
        raise InputValidationError(f"Parameter {param_name} must be a string")

    param_value = param_value.strip()

    if len(param_value) > max_length:
        raise InputValidationError(f"Parameter {param_name} too long (max {max_length} characters)")

    if allowed_values and param_value not in allowed_values:
        raise InputValidationError(f"Parameter {param_name} must be one of: {', '.join(allowed_values)}")

    # Check for common injection patterns
    dangerous_patterns = [
        r'<script',
        r'javascript:',
        r'vbscript:',
        r'onload=',
        r'onerror=',
        r'onclick=',
        r'<iframe',
        r'<object',
        r'<embed',
    ]

    for pattern in dangerous_patterns:
        if re.search(pattern, param_value, re.IGNORECASE):
            raise InputValidationError(f"Parameter {param_name} contains potentially dangerous content")

    return param_value


# validate_form_field removed: superseded by WTForms validators used by
# form classes throughout this application.

def validate_search_filter(filter_name: str, filter_value: str) -> str:
    """Validate search filter parameters to prevent injection."""
    if not isinstance(filter_value, str):
        raise InputValidationError(f"Filter {filter_name} must be a string")

    filter_value = filter_value.strip()

    # Limit length to prevent DoS
    if len(filter_value) > 500:
        raise InputValidationError(f"Filter {filter_name} too long (max 500 characters)")

    # Block SQL injection patterns
    sql_patterns = [
        r"(?:;|--|#|/\*|\*/)",  # SQL comment markers
        r"(?:union|select|insert|update|delete|drop|create|alter|exec|execute)[\s\*/]",  # SQL keywords with space or comment
        r"(?:script|javascript|vbscript):",  # Script injection
        r"(?:<|>|&lt;|&gt;)",  # HTML tags
        r"'.*(?:or|and).*'",  # SQL condition injection
        r"(?:\s|^)or\s+['\"]*\d",  # OR injection patterns
        r"(?:\s|^)and\s+['\"]*\d",  # AND injection patterns
    ]

    for pattern in sql_patterns:
        if re.search(pattern, filter_value, re.IGNORECASE):
            raise InputValidationError(f"Filter {filter_name} contains invalid characters")

    return filter_value


def sanitize_for_logging(value: str, max_length: int = 100) -> str:
    """Sanitize value for safe logging."""
    if not isinstance(value, str):
        value = str(value)

    # Truncate long values
    if len(value) > max_length:
        value = value[:max_length] + "..."

    # Remove control characters and potential log injection
    value = re.sub(r'[\x00-\x1F\x7F-\x9F]', '', value)

    # Remove newlines to prevent log injection
    value = value.replace('\n', ' ').replace('\r', ' ')

    return value