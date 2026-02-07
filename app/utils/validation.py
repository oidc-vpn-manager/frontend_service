"""
Input validation utilities for the OIDC VPN Manager frontend.
"""

def is_valid_certificate_fingerprint(fingerprint: str) -> bool:
    """
    Validate that a certificate fingerprint is a valid SHA-256 hex string.

    Args:
        fingerprint: The fingerprint string to validate

    Returns:
        bool: True if valid SHA-256 hex string, False otherwise
    """
    if not fingerprint:
        return False

    # SHA-256 fingerprints are exactly 64 hexadecimal characters
    if len(fingerprint) != 64:
        return False

    # Check that all characters are valid hexadecimal (0-9, A-F, a-f)
    return all(c in '0123456789ABCDEFabcdef' for c in fingerprint)


def validate_certificate_fingerprint_or_404(fingerprint: str, logger=None) -> None:
    """
    Validate certificate fingerprint and return 404 if invalid.

    Args:
        fingerprint: The fingerprint to validate
        logger: Optional logger to log validation failures

    Raises:
        werkzeug.exceptions.NotFound: If fingerprint is invalid
    """
    if not is_valid_certificate_fingerprint(fingerprint):
        if logger:
            logger.warning(f"Invalid certificate fingerprint format attempted: {fingerprint}")
        from flask import abort
        abort(404)


def validate_certificate_fingerprint_or_400(fingerprint: str, logger=None) -> None:
    """
    Validate certificate fingerprint and return 400 if invalid.

    Args:
        fingerprint: The fingerprint to validate
        logger: Optional logger to log validation failures

    Raises:
        werkzeug.exceptions.BadRequest: If fingerprint is invalid
    """
    if not is_valid_certificate_fingerprint(fingerprint):
        if logger:
            logger.warning(f"Invalid certificate fingerprint format attempted: {fingerprint}")
        from flask import abort
        abort(400)