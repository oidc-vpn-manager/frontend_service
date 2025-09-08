"""
Utility functions for parsing X.509 certificates and extracting metadata.
"""

from datetime import datetime, timezone
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from flask import current_app
from app.utils.tracing import trace


def parse_certificate_validity(cert_pem: str) -> dict:
    """
    Parse a PEM-encoded certificate and extract validity period information.
    
    Args:
        cert_pem: PEM-encoded certificate string
        
    Returns:
        Dictionary containing validity information:
        {
            'not_before': datetime,  # Certificate valid from (UTC)
            'not_after': datetime,   # Certificate valid until (UTC)
            'validity_days': int,    # Total validity period in days
            'subject_cn': str,       # Subject Common Name
            'serial_number': str,    # Certificate serial number as hex
            'fingerprint_sha256': str # SHA256 fingerprint
        }
        
    Raises:
        ValueError: If the certificate cannot be parsed
    """
    trace(current_app, 'utils.certificate_parser.parse_certificate_validity', {'cert_pem': cert_pem})
    try:
        # Load the certificate from PEM
        cert = x509.load_pem_x509_certificate(cert_pem.encode('utf-8'))
        
        # Extract validity dates (UTC timezone-aware)
        not_before = cert.not_valid_before_utc
        not_after = cert.not_valid_after_utc
        
        # Calculate validity period in days
        validity_period = not_after - not_before
        validity_days = validity_period.days
        
        # Extract subject common name
        subject_cn = None
        try:
            cn_attributes = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
            if cn_attributes:
                subject_cn = cn_attributes[0].value
        except Exception as e:
            current_app.logger.warning(f"Could not extract subject CN: {e}")
            subject_cn = "Unknown"
        
        # If no CN found (no exception but no attributes), set to Unknown
        if subject_cn is None:
            subject_cn = "Unknown"
        
        # Get serial number as hex string
        serial_hex = format(cert.serial_number, 'x').upper()
        
        # Calculate SHA256 fingerprint
        fingerprint = cert.fingerprint(hashes.SHA256())
        fingerprint_sha256 = fingerprint.hex().upper()
        
        return {
            'not_before': not_before,
            'not_after': not_after,
            'validity_days': validity_days,
            'subject_cn': subject_cn,
            'serial_number': serial_hex,
            'fingerprint_sha256': fingerprint_sha256
        }
        
    except Exception as e:
        current_app.logger.error(f"Failed to parse certificate: {e}")
        raise ValueError(f"Invalid certificate format: {e}")


def get_certificate_expiry_date(cert_pem: str) -> datetime:
    """
    Extract just the expiry date from a PEM certificate.
    
    Args:
        cert_pem: PEM-encoded certificate string
        
    Returns:
        datetime: Certificate expiry date in UTC
        
    Raises:
        ValueError: If the certificate cannot be parsed
    """
    trace(current_app, 'utils.certificate_parser.get_certificate_expiry_date', {'cert_pem': cert_pem})
    cert_info = parse_certificate_validity(cert_pem)
    return cert_info['not_after']


def is_certificate_expired(cert_pem: str) -> bool:
    """
    Check if a certificate is expired.
    
    Args:
        cert_pem: PEM-encoded certificate string
        
    Returns:
        bool: True if certificate is expired, False otherwise
        
    Raises:
        ValueError: If the certificate cannot be parsed
    """
    trace(current_app, 'utils.certificate_parser.is_certificate_expired', {'cert_pem': cert_pem})
    expiry_date = get_certificate_expiry_date(cert_pem)
    return datetime.now(timezone.utc) > expiry_date


def get_certificate_days_until_expiry(cert_pem: str) -> int:
    """
    Get the number of days until certificate expiry.
    
    Args:
        cert_pem: PEM-encoded certificate string
        
    Returns:
        int: Days until expiry (negative if already expired)
        
    Raises:
        ValueError: If the certificate cannot be parsed
    """
    trace(current_app, 'utils.certificate_parser.get_certificate_days_until_expiry', {'cert_pem': cert_pem})
    expiry_date = get_certificate_expiry_date(cert_pem)
    time_remaining = expiry_date - datetime.now(timezone.utc)
    return time_remaining.days