import pytest
from datetime import datetime, timezone, timedelta
from freezegun import freeze_time
from flask import Flask
import hashlib

from app.models.presharedkey import PreSharedKey

@pytest.fixture
def app():
    """Provides a basic Flask app."""
    app = Flask(__name__)
    return app

class TestPreSharedKey:
    """Tests the logic within the PreSharedKey model."""

    def test_key_hashing_verification(self, app):
        """Tests that the key is properly hashed and can be verified."""
        with app.app_context():
            original_key = "my-secret-uuid"
            psk = PreSharedKey(description="test.com", key=original_key)
            
            # Check that the internal, stored value is a hash (string)
            assert isinstance(psk.key_hash, str)
            assert len(psk.key_hash) == 64  # SHA256 hex string length
            assert psk.key_hash != original_key
            
            # Check that verification works
            assert psk.verify_key(original_key) is True
            assert psk.verify_key("wrong-key") is False
            
            # Check that the hash matches what we expect
            expected_hash = hashlib.sha256(original_key.encode('utf-8')).hexdigest()
            assert psk.key_hash == expected_hash

    def test_is_valid_active_key(self, app):
        """Tests that an active key without an expiry is valid."""
        with app.app_context():
            key = PreSharedKey(description="test.com", expires_at=None)
            key.is_enabled = True  # Set directly to bypass mass assignment protection
        assert key.is_valid() is True

    def test_is_valid_disabled_key(self, app):
        """Tests that a disabled key is not valid."""
        with app.app_context():
            key = PreSharedKey(description="test.com")
            key.is_enabled = False  # Set directly to bypass mass assignment protection
        assert key.is_valid() is False

    def test_is_valid_unexpired_key(self, app):
        """Tests that a key within its expiry window is valid."""
        expiry = datetime.now(timezone.utc) + timedelta(days=1)
        with app.app_context():
            key = PreSharedKey(description="test.com", expires_at=expiry)
            key.is_enabled = True  # Set directly to bypass mass assignment protection
        
        with freeze_time(datetime.now(timezone.utc)):
            assert key.is_valid() is True

    def test_is_valid_expired_key(self, app):
        """Tests that an expired key is not valid."""
        expiry = datetime.now(timezone.utc) - timedelta(days=1)
        with app.app_context():
            key = PreSharedKey(description="test.com", expires_at=expiry)
            key.is_enabled = True  # Set directly to bypass mass assignment protection
        
        with freeze_time(datetime.now(timezone.utc)):
            assert key.is_valid() is False

    def test_is_valid_naive_datetime_expiry(self, app):
        """Tests handling of naive datetime in expiry (line 52)."""
        # Create a naive datetime (no timezone info)
        expiry_naive = datetime.now() + timedelta(days=1)  # No timezone.utc
        
        with app.app_context():
            key = PreSharedKey(description="test.com", expires_at=expiry_naive)
            key.is_enabled = True  # Set directly to bypass mass assignment protection
        
        # This should trigger line 52 where naive datetime is made timezone-aware
        with freeze_time(datetime.now(timezone.utc)):
            assert key.is_valid() is True

    def test_revoke_method(self, app):
        """Tests the revoke method (line 60)."""
        with app.app_context():
            key = PreSharedKey(description="test.com")
            key.is_enabled = True  # Set directly to bypass mass assignment protection
            
            # Key should start as enabled
            assert key.is_enabled is True
            
            # Revoke the key
            key.revoke()
            
            # Key should now be disabled
            assert key.is_enabled is False

    def test_default_psk_type_is_server(self, app):
        """Tests that PSKs default to 'server' type."""
        with app.app_context():
            psk = PreSharedKey(description="test-server")
            assert psk.psk_type == 'server'
            assert psk.is_server_psk() is True
            assert psk.is_computer_psk() is False

    def test_computer_psk_type(self, app):
        """Tests creating a computer-identity PSK."""
        with app.app_context():
            psk = PreSharedKey(description="test-computer", psk_type="computer")
            assert psk.psk_type == 'computer'
            assert psk.is_computer_psk() is True
            assert psk.is_server_psk() is False

    def test_get_certificate_type_server(self, app):
        """Tests get_certificate_type for server PSKs."""
        with app.app_context():
            psk = PreSharedKey(description="test-server", psk_type="server")
            assert psk.get_certificate_type() == 'server'

    def test_get_certificate_type_computer(self, app):
        """Tests get_certificate_type for computer PSKs."""
        with app.app_context():
            psk = PreSharedKey(description="test-computer", psk_type="computer")
            assert psk.get_certificate_type() == 'computer'

    def test_get_certificate_type_default(self, app):
        """Tests get_certificate_type with default PSK type."""
        with app.app_context():
            psk = PreSharedKey(description="test-default")
            # Should default to server type
            assert psk.get_certificate_type() == 'server'