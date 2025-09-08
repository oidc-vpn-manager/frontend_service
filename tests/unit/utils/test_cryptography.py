"""
Unit tests for cryptography utility functions.
"""

import pytest
from flask import Flask
from cryptography.fernet import Fernet

from app.utils.cryptography import get_fernet

class TestGetFernet:
    """
    Tests for the get_fernet function.
    """
    def test_get_fernet_success(self):
        """
        Tests that a Fernet instance is created and cached successfully.
        """
        app = Flask(__name__)
        app.config['ENCRYPTION_KEY'] = Fernet.generate_key().decode('utf-8')
        with app.app_context():
            fernet_instance_1 = get_fernet()
            fernet_instance_2 = get_fernet()
            assert isinstance(fernet_instance_1, Fernet)
            assert fernet_instance_1 is fernet_instance_2
            assert 'fernet_instance' in app.config

    def test_get_fernet_missing_key_raises_error(self):
        """
        Tests that a RuntimeError is raised if ENCRYPTION_KEY is not set.
        """
        app = Flask(__name__)
        with app.app_context():
            with pytest.raises(RuntimeError, match="ENCRYPTION_KEY must be set for data encryption."):
                get_fernet()

    def test_get_fernet_default_key_logs_warning(self, caplog):
        """
        Tests that a critical warning is logged when using the default insecure key.
        """
        app = Flask(__name__)
        app.config['ENCRYPTION_KEY'] = 'YenxIAHqvrO7OHbNXvzAxEhthHCaitvnV9CALkQvvCc='
        with app.app_context():
            with caplog.at_level('CRITICAL'):
                fernet_instance = get_fernet()
                assert isinstance(fernet_instance, Fernet)
                assert 'You are using an untrusted and insecure key' in caplog.text
            
            # Ensure the warning is only logged once
            caplog.clear()
            get_fernet()
            assert 'You are using an untrusted and insecure key' not in caplog.text

    def test_get_fernet_default_key_in_prod_raises_error(self, monkeypatch):
        """
        Tests that a RuntimeError is raised if the default key is used in a production environment.
        """
        monkeypatch.setenv('FLASK_ENV', 'production')
        app = Flask(__name__)
        app.config['ENCRYPTION_KEY'] = 'YenxIAHqvrO7OHbNXvzAxEhthHCaitvnV9CALkQvvCc='
        with app.app_context():
            with pytest.raises(RuntimeError, match="Cannot start in production"):
                get_fernet()