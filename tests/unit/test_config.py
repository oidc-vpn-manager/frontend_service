"""
Unit tests for configuration loading functions.
"""

import os
import pytest
from app.config import loadConfigValueFromFileOrEnvironment, loadBoolConfigValue, Config

def _setup_mock_tls_key(monkeypatch, tmp_path):
    """Helper function to create mock certificate and key files for config reload tests."""
    # Mock TLS key file
    tls_key_file = tmp_path / "tls-crypt.key"
    tls_key_file.write_text("-----BEGIN OpenVPN Static key V1-----\ndummy\n-----END OpenVPN Static key V1-----")
    monkeypatch.setenv('OPENVPN_TLS_CRYPT_KEY_FILE', str(tls_key_file))
    
    # Mock certificate files
    root_ca_file = tmp_path / "root-ca.crt"
    root_ca_file.write_text("-----BEGIN CERTIFICATE-----\nROOT CA DATA\n-----END CERTIFICATE-----")
    monkeypatch.setenv('ROOT_CA_CERTIFICATE_FILE', str(root_ca_file))
    
    intermediate_ca_file = tmp_path / "intermediate-ca.crt"
    intermediate_ca_file.write_text("-----BEGIN CERTIFICATE-----\nINTERMEDIATE CA DATA\n-----END CERTIFICATE-----")
    monkeypatch.setenv('INTERMEDIATE_CA_CERTIFICATE_FILE', str(intermediate_ca_file))
    
    # Required security keys for configuration tests
    monkeypatch.setenv('FLASK_SECRET_KEY', 'test-secret-key-for-unit-tests-only')
    monkeypatch.setenv('FERNET_ENCRYPTION_KEY', 'test-encryption-key-for-unit-tests-only-never-use-in-production')
    
    return tls_key_file

class TestLoadConfigValueFromFileOrEnvironment:
    """
    Tests for the loadConfigValueFromFileOrEnvironment function.
    """

    def test_load_from_environment_variable(self, monkeypatch):
        """
        Tests that the function correctly retrieves a value from an environment variable.
        """
        monkeypatch.setenv('TEST_KEY', 'env_value')
        result = loadConfigValueFromFileOrEnvironment('TEST_KEY', 'default_value')
        assert result == 'env_value'

    def test_load_from_default_value(self):
        """
        Tests that the function returns the default value when no environment variable or file is set.
        """
        result = loadConfigValueFromFileOrEnvironment('NON_EXISTENT_KEY', 'default_value')
        assert result == 'default_value'

    def test_load_from_file_overrides_environment(self, monkeypatch, tmp_path):
        """
        Tests that a value loaded from a file correctly overrides an environment variable.
        """
        file_path = tmp_path / "secret.txt"
        file_path.write_text("file_value")
        monkeypatch.setenv('TEST_KEY_FILE', str(file_path))
        monkeypatch.setenv('TEST_KEY', 'env_value')
        
        result = loadConfigValueFromFileOrEnvironment('TEST_KEY', 'default_value')
        assert result == "file_value"
    
    def test_load_from_default_path(self, tmp_path):
        """
        Tests that the function uses the default_path if the _FILE environment variable is not set.
        """
        file_path = tmp_path / "default_secret.txt"
        file_path.write_text("default_path_value")

        result = loadConfigValueFromFileOrEnvironment(
            'TEST_KEY', 
            default_path=str(file_path)
        )
        assert result == "default_path_value"

    def test_file_not_found_error(self, monkeypatch):
        """
        Tests that a FileNotFoundError is raised if the specified file does not exist.
        """
        monkeypatch.setenv('TEST_KEY_FILE', '/non/existent/path/secret.txt')
        with pytest.raises(FileNotFoundError, match='TEST_KEY_FILE is set to /non/existent/path/secret.txt but the path does not exist.'):
            loadConfigValueFromFileOrEnvironment('TEST_KEY')

    def test_path_is_not_a_file_error(self, monkeypatch, tmp_path):
        """
        Tests that a FileNotFoundError is raised if the path is a directory.
        """
        # Arrange: Set the _FILE variable to a path that is a directory
        monkeypatch.setenv('TEST_KEY_FILE', str(tmp_path))
        
        # Act & Assert
        with pytest.raises(FileNotFoundError, match=f"is not a file"):
            loadConfigValueFromFileOrEnvironment('TEST_KEY')

    def test_fallback_when_file_is_empty(self, monkeypatch, tmp_path):
        """
        Tests that the function falls back to environment variables or defaults if the specified file is empty.
        """
        file_path = tmp_path / "empty_secret.txt"
        file_path.write_text("")
        monkeypatch.setenv('TEST_KEY_FILE', str(file_path))
        monkeypatch.setenv('TEST_KEY', 'env_value')
        
        result = loadConfigValueFromFileOrEnvironment('TEST_KEY', 'default_value')
        assert result == 'env_value'

    def test_load_multiline_from_file(self, monkeypatch, tmp_path):
        """
        Tests that a multi-line value (like a certificate) is loaded correctly from a file.
        """
        multiline_content = "-----BEGIN CERTIFICATE-----\nline2\nline3\n-----END CERTIFICATE-----"
        file_path = tmp_path / "cert.pem"
        file_path.write_text(multiline_content)
        monkeypatch.setenv('TEST_MULTILINE_FILE', str(file_path))
        
        # Create dummy TLS key file to avoid config reload issues
        _setup_mock_tls_key(monkeypatch, tmp_path)
        
        # We need to reload the config module to re-run the `load...` functions
        from importlib import reload
        import app.config as config
        reload(config)
        
        result = config.loadConfigValueFromFileOrEnvironment('TEST_MULTILINE')
        assert result == multiline_content

class TestLoadBoolConfigValue:
    """
    Tests for the loadBoolConfigValue function.
    """
    
    @pytest.mark.parametrize("value, expected", [
        ('false', False), ('no', False), ('off', False), ('0', False),
        ('true', True), ('yes', True), ('on', True), ('1', True),
        ('any_other_string', True), ('', True)
    ])
    def test_default_preference(self, monkeypatch, value, expected):
        """
        Tests the default preference (prefer=False), where most values are considered True.
        """
        monkeypatch.setenv('BOOL_KEY', value)
        result = loadBoolConfigValue('BOOL_KEY', 'false', prefer=False)
        assert result is expected

    @pytest.mark.parametrize("value, expected", [
        ('true', True), ('yes', True), ('on', True), ('1', True),
        ('false', False), ('no', False), ('off', False), ('0', False),
        ('any_other_string', False), ('', False)
    ])
    def test_prefer_true_preference(self, monkeypatch, value, expected):
        """
        Tests the prefer=True preference, where only explicit True strings evaluate to True.
        """
        monkeypatch.setenv('BOOL_KEY', value)
        result = loadBoolConfigValue('BOOL_KEY', 'false', prefer=True)
        assert result is expected

    def test_default_value_usage(self):
        """
        Tests that the function correctly uses the default value when the environment variable is not set.
        """
        # Test default preference (prefer=False)
        assert loadBoolConfigValue('UNSET_KEY', 'true', prefer=False) is True
        assert loadBoolConfigValue('UNSET_KEY', 'false', prefer=False) is False

        # Test prefer-true preference (prefer=True)
        assert loadBoolConfigValue('UNSET_KEY', 'true', prefer=True) is True
        assert loadBoolConfigValue('UNSET_KEY', 'false', prefer=True) is False

class TestDatabaseURI:
    """
    Tests the logic for constructing the SQLALCHEMY_DATABASE_URI.
    """
    def test_builds_uri_with_port(self, monkeypatch, tmp_path):
        """
        Tests that the URI is built correctly when all parts, including port, are provided.
        """
        monkeypatch.setenv('DATABASE_TYPE', 'postgresql')
        monkeypatch.setenv('DATABASE_HOSTNAME', 'db.host.com')
        monkeypatch.setenv('DATABASE_USERNAME', 'user')
        monkeypatch.setenv('DATABASE_PASSWORD', 'pass')
        monkeypatch.setenv('DATABASE_NAME', 'testdb')
        monkeypatch.setenv('DATABASE_PORT', '5432')
        
        # Create dummy TLS key file to avoid config reload issues
        _setup_mock_tls_key(monkeypatch, tmp_path)
        
        # We need to reload the config module to re-run the logic at the class level
        from importlib import reload
        import app.config as config
        reload(config)
        
        expected_uri = "postgresql://user:pass@db.host.com:5432/testdb"
        config_instance = config.Config()
        assert config_instance.SQLALCHEMY_DATABASE_URI == expected_uri

    def test_builds_uri_without_port(self, monkeypatch, tmp_path):
        """
        Tests that the URI is built correctly when the port is omitted.
        """
        monkeypatch.setenv('DATABASE_TYPE', 'mysql')
        monkeypatch.setenv('DATABASE_HOSTNAME', 'db.host.com')
        monkeypatch.setenv('DATABASE_USERNAME', 'user')
        monkeypatch.setenv('DATABASE_PASSWORD', 'pass')
        monkeypatch.setenv('DATABASE_NAME', 'testdb')
        # Ensure DATABASE_PORT is not set
        monkeypatch.delenv('DATABASE_PORT', raising=False)
        
        # Create dummy TLS key file to avoid config reload issues
        _setup_mock_tls_key(monkeypatch, tmp_path)
        
        from importlib import reload
        import app.config as config
        reload(config)
        
        expected_uri = "mysql://user:pass@db.host.com/testdb"
        config_instance = config.Config()
        assert config_instance.SQLALCHEMY_DATABASE_URI == expected_uri

    def test_fallback_to_sqlite(self, monkeypatch, tmp_path):
        """
        Tests that the URI falls back to sqlite if database env vars are missing.
        """
        # Ensure env vars that would build the URI are not set
        monkeypatch.delenv('DATABASE_TYPE', raising=False)
        monkeypatch.delenv('DATABASE_HOSTNAME', raising=False)
        
        # Create dummy TLS key file to avoid config reload issues
        _setup_mock_tls_key(monkeypatch, tmp_path)
        
        from importlib import reload
        import app.config as config
        reload(config)

        config_instance = config.Config()
        assert config_instance.SQLALCHEMY_DATABASE_URI == 'sqlite:////data/sqlite/frontend.db'

class TestTemplatingAndOptions:
    def test_ovpn_options_loaded_from_yaml(self, monkeypatch, tmp_path):
        """
        Tests that OVPN_OPTIONS are correctly loaded from a YAML file.
        """
        # Create a dummy YAML file for the test
        yaml_content = """
        use_tcp:
          display_name: 'Use TCP'
          settings: { protocol: 'tcp-client', port: 443 }
        """
        yaml_path = tmp_path / "options.yaml"
        yaml_path.write_text(yaml_content)
        
        # Point the config to our dummy file
        monkeypatch.setenv('OVPN_OPTIONS_PATH', str(yaml_path))
        
        # Create dummy TLS key file to avoid config reload issues
        _setup_mock_tls_key(monkeypatch, tmp_path)

        # We must reload the config module to re-trigger the loading logic
        from importlib import reload
        import app.config as config
        reload(config)
        
        # Assert that the options were loaded
        config_instance = config.Config()
        assert 'use_tcp' in config_instance.OVPN_OPTIONS
        assert config_instance.OVPN_OPTIONS['use_tcp']['settings']['port'] == 443

    def test_ovpn_options_handles_missing_file(self, monkeypatch, tmp_path):
        """
        Tests that OVPN_OPTIONS defaults to an empty dict if the YAML file is not found.
        """
        # Point the config to a file that does not exist
        monkeypatch.setenv('OVPN_OPTIONS_PATH', '/non/existent/path/options.yaml')
        
        # Create dummy TLS key file to avoid config reload issues
        _setup_mock_tls_key(monkeypatch, tmp_path)

        # We must reload the config module to re-trigger the loading logic
        from importlib import reload
        import app.config as config
        reload(config)
        
        # Assert that the options defaulted to an empty dictionary without crashing
        config_instance = config.Config()
        assert isinstance(config_instance.OVPN_OPTIONS, dict)
        assert len(config_instance.OVPN_OPTIONS) == 0


def test_missing_secret_key_raises_runtime_error(monkeypatch, tmp_path):
    """
    Test that missing FLASK_SECRET_KEY raises a RuntimeError (line 24).
    """
    # Set up required files but deliberately omit FLASK_SECRET_KEY
    _setup_mock_tls_key(monkeypatch, tmp_path)
    monkeypatch.delenv('FLASK_SECRET_KEY', raising=False)  # Remove if set
    
    with pytest.raises(RuntimeError, match="FLASK_SECRET_KEY must be set"):
        Config()


def test_missing_encryption_key_raises_runtime_error(monkeypatch, tmp_path):
    """
    Test that missing FERNET_ENCRYPTION_KEY raises a RuntimeError (line 28).
    """
    # Set up required files with SECRET_KEY but deliberately omit FERNET_ENCRYPTION_KEY  
    _setup_mock_tls_key(monkeypatch, tmp_path)
    monkeypatch.setenv('FLASK_SECRET_KEY', 'test-secret-key')
    monkeypatch.delenv('FERNET_ENCRYPTION_KEY', raising=False)  # Remove if set
    
    with pytest.raises(RuntimeError, match="FERNET_ENCRYPTION_KEY must be set"):
        Config()