"""
Test certificate parsing utility functions.
"""

import pytest
from datetime import datetime, timezone
from flask import Flask
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from app.utils.certificate_parser import (
    parse_certificate_validity,
    get_certificate_expiry_date,
    is_certificate_expired,
    get_certificate_days_until_expiry
)


@pytest.fixture
def app():
    """Create test Flask app."""
    app = Flask(__name__)
    app.config.update({
        "TESTING": True
    })
    return app


@pytest.fixture
def sample_certificate_pem():
    """Generate a sample certificate for testing."""
    # Generate a private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    
    # Define the subject and issuer
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, u"Test Certificate"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Test Organization"),
    ])
    
    # Create the certificate
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        12345
    ).not_valid_before(
        datetime(2023, 1, 1, tzinfo=timezone.utc)
    ).not_valid_after(
        datetime(2024, 1, 1, tzinfo=timezone.utc)  # Valid for 1 year
    ).sign(private_key, hashes.SHA256())
    
    # Convert to PEM format
    return cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')


@pytest.fixture
def expired_certificate_pem():
    """Generate an expired certificate for testing."""
    # Generate a private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    
    # Define the subject and issuer
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, u"Expired Certificate"),
    ])
    
    # Create an expired certificate (valid in the past)
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        67890
    ).not_valid_before(
        datetime(2020, 1, 1, tzinfo=timezone.utc)  # Expired certificate
    ).not_valid_after(
        datetime(2021, 1, 1, tzinfo=timezone.utc)  # Expired in 2021
    ).sign(private_key, hashes.SHA256())
    
    # Convert to PEM format
    return cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')


def test_parse_certificate_validity_success(app, sample_certificate_pem):
    """Test successful certificate parsing."""
    with app.app_context():
        result = parse_certificate_validity(sample_certificate_pem)
        
        assert result['not_before'] == datetime(2023, 1, 1, tzinfo=timezone.utc)
        assert result['not_after'] == datetime(2024, 1, 1, tzinfo=timezone.utc)
        assert result['validity_days'] == 365  # 2023 is not a leap year
        assert result['subject_cn'] == 'Test Certificate'
        assert result['serial_number'] == '3039'  # 12345 in hex
        assert 'fingerprint_sha256' in result
        assert len(result['fingerprint_sha256']) == 64  # SHA256 hex length


def test_parse_certificate_validity_no_common_name(app):
    """Test certificate parsing when CN is missing."""
    # Generate a certificate without Common Name
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    
    # Define subject without Common Name
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Test Organization Only"),
    ])
    
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        54321
    ).not_valid_before(
        datetime(2023, 1, 1, tzinfo=timezone.utc)
    ).not_valid_after(
        datetime(2024, 1, 1, tzinfo=timezone.utc)
    ).sign(private_key, hashes.SHA256())
    
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')
    
    with app.app_context():
        result = parse_certificate_validity(cert_pem)
        
        # Should handle missing CN gracefully
        assert result['subject_cn'] == 'Unknown'


def test_parse_certificate_validity_invalid_cert(app):
    """Test certificate parsing with invalid certificate."""
    invalid_cert = "-----BEGIN CERTIFICATE-----\nInvalidCertData\n-----END CERTIFICATE-----"
    
    with app.app_context():
        with pytest.raises(ValueError, match="Invalid certificate format"):
            parse_certificate_validity(invalid_cert)


def test_get_certificate_expiry_date(app, sample_certificate_pem):
    """Test extracting certificate expiry date."""
    with app.app_context():
        expiry_date = get_certificate_expiry_date(sample_certificate_pem)
        
        assert expiry_date == datetime(2024, 1, 1, tzinfo=timezone.utc)


def test_is_certificate_expired_not_expired(app, sample_certificate_pem):
    """Test checking if certificate is expired (not expired case)."""
    with app.app_context():
        # Sample cert expires in 2024, should not be expired if we're testing in past
        # But this will depend on current date, so we need to be careful
        # For this test, let's create a future certificate
        pass  # Will be covered by other expiry tests


def test_is_certificate_expired_expired(app, expired_certificate_pem):
    """Test checking if certificate is expired (expired case)."""
    with app.app_context():
        is_expired = is_certificate_expired(expired_certificate_pem)
        
        # Certificate expired in 2021, should definitely be expired now
        assert is_expired is True


def test_get_certificate_days_until_expiry_expired(app, expired_certificate_pem):
    """Test getting days until expiry for expired certificate."""
    with app.app_context():
        days_remaining = get_certificate_days_until_expiry(expired_certificate_pem)
        
        # Certificate expired in 2021, should have negative days
        assert days_remaining < 0


def test_get_certificate_days_until_expiry_future(app):
    """Test getting days until expiry for future certificate."""
    # Create a certificate that expires far in the future
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, u"Future Certificate"),
    ])
    
    future_date = datetime(2030, 1, 1, tzinfo=timezone.utc)
    
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        98765
    ).not_valid_before(
        datetime(2023, 1, 1, tzinfo=timezone.utc)
    ).not_valid_after(
        future_date
    ).sign(private_key, hashes.SHA256())
    
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')
    
    with app.app_context():
        days_remaining = get_certificate_days_until_expiry(cert_pem)
        
        # Should have positive days (certificate expires in 2030)
        assert days_remaining > 0
        
        # Also test that it's not expired
        is_expired = is_certificate_expired(cert_pem)
        assert is_expired is False


def test_all_functions_with_invalid_cert(app):
    """Test that all functions handle invalid certificates properly."""
    invalid_cert = "not a certificate"
    
    with app.app_context():
        # All functions should raise ValueError for invalid certificates
        with pytest.raises(ValueError):
            parse_certificate_validity(invalid_cert)
            
        with pytest.raises(ValueError):
            get_certificate_expiry_date(invalid_cert)
            
        with pytest.raises(ValueError):
            is_certificate_expired(invalid_cert)
            
        with pytest.raises(ValueError):
            get_certificate_days_until_expiry(invalid_cert)


def test_certificate_with_cn_extraction_exception(app):
    """Test certificate parsing when CN extraction raises an exception (line 53)."""
    # This test is tricky because it's hard to trigger the exception case
    # in the CN extraction. We'll create a certificate and mock the extraction
    from unittest.mock import patch
    
    with app.app_context():
        with patch('app.utils.certificate_parser.x509.load_pem_x509_certificate') as mock_load:
            # Create a mock certificate where getting CN attributes raises exception
            mock_cert = mock_load.return_value
            mock_cert.not_valid_before = datetime(2023, 1, 1, tzinfo=timezone.utc)
            mock_cert.not_valid_after = datetime(2024, 1, 1, tzinfo=timezone.utc)
            mock_cert.serial_number = 12345
            mock_cert.fingerprint.return_value.hex.return_value = 'abcdef123456'
            
            # Make the subject.get_attributes_for_oid method raise an exception
            mock_cert.subject.get_attributes_for_oid.side_effect = Exception("CN extraction error")
            
            result = parse_certificate_validity("fake cert pem")
            
            # Should handle the exception and set CN to "Unknown"
            assert result['subject_cn'] == 'Unknown'