"""
Unit tests for the EncryptedString custom SQLAlchemy type.
"""

import pytest
from flask import Flask
from cryptography.fernet import Fernet
from app.models.types import EncryptedString

@pytest.fixture
def app():
    """Provides a basic Flask app instance with an encryption key."""
    app = Flask(__name__)
    app.config['ENCRYPTION_KEY'] = Fernet.generate_key().decode('utf-8')
    return app

class TestEncryptedStringType:
    """
    Tests the encryption and decryption logic of the EncryptedString TypeDecorator.
    """

    def test_encryption_decryption_roundtrip(self, app):
        """
        Tests that a value can be encrypted and then decrypted back to the original.
        """
        custom_type = EncryptedString()
        original_value = "this-is-a-secret-key"

        with app.app_context():
            # Simulate writing to the database
            encrypted = custom_type.process_bind_param(original_value, None)
            
            # Assert that the stored value is encrypted (binary and different)
            assert isinstance(encrypted, bytes)
            assert encrypted != original_value.encode('utf-8')
            
            # Simulate reading from the database
            decrypted = custom_type.process_result_value(encrypted, None)
        
        # Assert that the decrypted value matches the original
        assert decrypted == original_value

    def test_handles_none_value(self, app):
        """
        Tests that the type decorator correctly handles None values.
        """
        custom_type = EncryptedString()
        
        with app.app_context():
            # Ensure None remains None through the process
            assert custom_type.process_bind_param(None, None) is None
            assert custom_type.process_result_value(None, None) is None