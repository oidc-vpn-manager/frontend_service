"""
Tests for input validation utilities.
"""

import pytest
from app.utils.validation import (
    is_valid_certificate_fingerprint,
    validate_certificate_fingerprint_or_404,
    validate_certificate_fingerprint_or_400
)
from flask import Flask
from werkzeug.exceptions import NotFound, BadRequest


class TestCertificateFingerprintValidation:
    """Tests for certificate fingerprint validation."""

    def test_is_valid_certificate_fingerprint_valid(self):
        """Test valid SHA-256 fingerprints."""
        # Valid 64-character hex strings
        valid_fingerprints = [
            "A1B2C3D4E5F6789012345678901234567890ABCDEF1234567890ABCDEF123456",
            "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF",
            "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
            "1234567890ABCDEFabcdef1234567890ABCDEFabcdef1234567890ABCDEFabcd",
        ]

        for fingerprint in valid_fingerprints:
            assert is_valid_certificate_fingerprint(fingerprint), f"Should be valid: {fingerprint}"

    def test_is_valid_certificate_fingerprint_invalid(self):
        """Test invalid fingerprint formats."""
        invalid_fingerprints = [
            None,
            "",
            "short",
            "A1B2C3D4E5F6789012345678901234567890ABCDEF1234567890ABCDEF12345",  # 63 chars
            "A1B2C3D4E5F6789012345678901234567890ABCDEF1234567890ABCDEF1234567",  # 65 chars
            "G1B2C3D4E5F6789012345678901234567890ABCDEF1234567890ABCDEF123456",  # Invalid char G
            "A1B2C3D4E5F6789012345678901234567890ABCDEF1234567890ABCDEF12345@",  # Invalid char @
            "admin/certificates",  # Path traversal attempt
            "../admin/certificates",  # Path traversal attempt
            "A1B2C3D4E5F6789012345678901234567890ABCDEF/admin/certificates",  # Partial valid + path
            "A1B2C3D4E5F678901234567890 34567890ABCDEF1234567890ABCDEF123456",  # Space
            "A1B2C3D4E5F6789012345678901234567890ABCDEF1234567890ABCDEF123456\n",  # Newline
        ]

        for fingerprint in invalid_fingerprints:
            assert not is_valid_certificate_fingerprint(fingerprint), f"Should be invalid: {fingerprint}"

    def test_validate_certificate_fingerprint_or_404_valid(self):
        """Test that valid fingerprints don't raise exceptions."""
        valid_fingerprint = "A1B2C3D4E5F6789012345678901234567890ABCDEF1234567890ABCDEF123456"

        # Should not raise any exception
        validate_certificate_fingerprint_or_404(valid_fingerprint)

    def test_validate_certificate_fingerprint_or_404_invalid(self):
        """Test that invalid fingerprints raise 404."""
        invalid_fingerprints = [
            "admin/certificates",
            "../admin/certificates",
            "short",
            "A1B2C3D4E5F6789012345678901234567890ABCDEF1234567890ABCDEF12345",  # 63 chars
        ]

        for fingerprint in invalid_fingerprints:
            with pytest.raises(NotFound):
                validate_certificate_fingerprint_or_404(fingerprint)

    def test_validate_certificate_fingerprint_or_400_valid(self):
        """Test that valid fingerprints don't raise exceptions."""
        valid_fingerprint = "A1B2C3D4E5F6789012345678901234567890ABCDEF1234567890ABCDEF123456"

        # Should not raise any exception
        validate_certificate_fingerprint_or_400(valid_fingerprint)

    def test_validate_certificate_fingerprint_or_400_invalid(self):
        """Test that invalid fingerprints raise 400."""
        invalid_fingerprints = [
            "admin/certificates",
            "../admin/certificates",
            "short",
            "A1B2C3D4E5F6789012345678901234567890ABCDEF1234567890ABCDEF12345",  # 63 chars
        ]

        for fingerprint in invalid_fingerprints:
            with pytest.raises(BadRequest):
                validate_certificate_fingerprint_or_400(fingerprint)

    def test_validate_certificate_fingerprint_logging(self):
        """Test that validation functions log invalid attempts."""
        from unittest.mock import MagicMock

        logger = MagicMock()
        invalid_fingerprint = "admin/certificates"

        # Test 404 validation with logging
        with pytest.raises(NotFound):
            validate_certificate_fingerprint_or_404(invalid_fingerprint, logger)

        logger.warning.assert_called_once_with(f"Invalid certificate fingerprint format attempted: {invalid_fingerprint}")

        # Test 400 validation with logging
        logger.reset_mock()
        with pytest.raises(BadRequest):
            validate_certificate_fingerprint_or_400(invalid_fingerprint, logger)

        logger.warning.assert_called_once_with(f"Invalid certificate fingerprint format attempted: {invalid_fingerprint}")

    def test_path_traversal_specific_cases(self):
        """Test specific path traversal cases that were causing security issues."""
        # These are the exact patterns from the E2E test that were bypassing security
        path_traversal_patterns = [
            "admin/certificates",
            "../admin/certificates",
            "certificates/../admin/certificates",
            "/admin/certificates",
            "profile/admin/certificates",
            "admin\\certificates",  # Windows path separator
            "admin%2Fcertificates",  # URL encoded slash
        ]

        for pattern in path_traversal_patterns:
            assert not is_valid_certificate_fingerprint(pattern), f"Path traversal pattern should be invalid: {pattern}"

            with pytest.raises(NotFound):
                validate_certificate_fingerprint_or_404(pattern)

            with pytest.raises(BadRequest):
                validate_certificate_fingerprint_or_400(pattern)