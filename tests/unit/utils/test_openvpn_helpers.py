"""
Unit tests for the openvpn_helpers utility.
"""

import pytest
from app import create_app
from app.utils.openvpn_helpers import process_tls_crypt_key

TLS_CRYPT_V1_KEY = """
-----BEGIN OpenVPN Static key V1-----
2718e22b5161325d087957d9241e3b2e
-----END OpenVPN Static key V1-----
"""

TLS_CRYPT_V2_SERVER_KEY = """
-----BEGIN OpenVPN TLS Crypt V2 Server Key-----
a1a2a3a4a5a6a7a8a1a2a3a4a5a6a7a8a1a2a3a4a5a6a7a8a1a2a3a4a5a6a7a8
b1b2b3b4b5b6b7b8b1b2b3b4b5b6b7b8b1b2b3b4b5b6b7b8b1b2b3b4b5b6b7b8
c1c2c3c4c5c6c7c8c1c2c3c4c5c6c7c8c1c2c3c4c5c6c7c8c1c2c3c4c5c6c7c8
d1d2d3d4d5d6d7d8d1d2d3d4d5d6d7d8d1d2d3d4d5d6d7d8d1d2d3d4d5d6d7d8
-----END OpenVPN TLS Crypt V2 Server Key-----
"""

class TestProcessTlsCryptKey:
    """
    Tests for the process_tls_crypt_key function.
    """

    @pytest.fixture
    def app(self):
        """Create a test Flask app."""
        import os
        # Set required environment variables for testing
        os.environ['FLASK_SECRET_KEY'] = 'test-secret-key-for-testing-only'
        os.environ['FERNET_ENCRYPTION_KEY'] = 'test-encryption-key-for-testing-only-32-chars-long'
        os.environ['TESTING'] = 'True'
        
        app = create_app('testing')
        app.config.update({
            'TESTING': True,
            'SECRET_KEY': 'test-secret-key-for-testing-only',
        })
        
        with app.app_context():
            yield app

    def test_handles_v1_key(self, app):
        version, client_key = process_tls_crypt_key(TLS_CRYPT_V1_KEY)
        assert version == 1
        assert client_key == TLS_CRYPT_V1_KEY

    def test_handles_v2_key(self, app):
        version, client_key = process_tls_crypt_key(TLS_CRYPT_V2_SERVER_KEY)
        assert version == 2
        assert client_key is not None
        assert client_key != TLS_CRYPT_V2_SERVER_KEY
        assert client_key.startswith("-----BEGIN OpenVPN TLS Crypt V2 Client Key-----")

    def test_handles_empty_key(self, app):
        version, client_key = process_tls_crypt_key(None)
        assert version is None
        assert client_key is None

    def test_raises_error_for_unrecognized_format(self, app):
        bad_key = "-----BEGIN FOO-----\nbar\n-----END FOO-----"
        with pytest.raises(ValueError, match="Unrecognized TLS-Crypt key format."):
            process_tls_crypt_key(bad_key)

    def test_raises_error_for_invalid_v2_key_length(self, app):
        """
        Tests that a V2 key with an incorrect length raises a ValueError.
        """
        # This key is too short (254 hex characters instead of 256)
        bad_v2_key = """
-----BEGIN OpenVPN TLS Crypt V2 Server Key-----
a1a2a3a4a5a6a7a8a1a2a3a4a5a6a7a8a1a2a3a4a5a6a7a8a1a2a3a4a5a6a7a8
b1b2b3b4b5b6b7b8b1b2b3b4b5b6b7b8b1b2b3b4b5b6b7b8b1b2b3b4b5b6b7b8
c1c2c3c4c5c6c7c8c1c2c3c4c5c6c7c8c1c2c3c4c5c6c7c8c1c2c3c4c5c6c7c8
d1d2d3d4d5d6d7d8d1d2d3d4d5d6d7d8d1d2d3d4d5d6d7d8d1d2d3d4d5d6d7
-----END OpenVPN TLS Crypt V2 Server Key-----
"""
        with pytest.raises(ValueError, match="TLS-Crypt-V2 key must be 128 bytes."):
            process_tls_crypt_key(bad_v2_key)