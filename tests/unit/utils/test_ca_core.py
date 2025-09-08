"""
Unit tests for the CA core utility functions.
"""

import pytest
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import rsa, ed25519
from flask import Flask
from datetime import datetime, timezone

from app.utils.ca_core import generate_key_and_csr

@pytest.fixture
def app():
    """Provides a basic Flask app with default CA config."""
    app = Flask(__name__)
    app.config['CA_COUNTRY_NAME'] = 'GB'
    app.config['CA_STATE_OR_PROVINCE_NAME'] = 'Test State'
    app.config['CA_LOCALITY_NAME'] = 'Test City'
    app.config['CA_ORGANIZATION_NAME'] = 'Test Org'
    return app

class TestGenerateKeyAndCsr:
    """
    Tests for the generate_key_and_csr function.
    """
    def test_generates_ed25519_key_by_default(self, app):
        with app.app_context():
            private_key, csr = generate_key_and_csr("test.host.com")
        
        assert isinstance(private_key, ed25519.Ed25519PrivateKey)
        assert isinstance(csr, x509.CertificateSigningRequest)

    def test_mangles_email_common_name(self, app):
        email = "user@example.com"
        timestamp_before = int(datetime.now(timezone.utc).timestamp())
        
        with app.app_context():
            _, csr = generate_key_and_csr(email)
        
        timestamp_after = int(datetime.now(timezone.utc).timestamp())
        
        cn_value = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        assert cn_value.startswith(f"{email}-")
        
        cn_timestamp = int(cn_value.split('-')[-1])
        assert timestamp_before <= cn_timestamp <= timestamp_after

    def test_csr_uses_defaults_from_config(self, app):
        with app.app_context():
            _, csr = generate_key_and_csr("test.host.com")

        assert csr.subject.get_attributes_for_oid(NameOID.COUNTRY_NAME)[0].value == 'GB'

    def test_generates_rsa_key(self, app):
        """Tests that an RSA key can be explicitly requested."""
        with app.app_context():
            private_key, csr = generate_key_and_csr("test.host.com", key_type='rsa')
        
        assert isinstance(private_key, rsa.RSAPrivateKey)
        assert isinstance(csr, x509.CertificateSigningRequest)

    def test_raises_error_for_unsupported_key_type(self, app):
        """Tests that an unsupported key type raises a ValueError."""
        with app.app_context():
            with pytest.raises(ValueError, match="Unsupported key type specified."):
                generate_key_and_csr("test.host.com", key_type='dsa')