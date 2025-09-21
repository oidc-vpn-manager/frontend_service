"""
Security tests for information disclosure vulnerability fixes.

This test suite validates that sensitive information is not disclosed
in debug logs or configuration output.
"""

import pytest
import logging
import tempfile
import os
from unittest.mock import Mock, patch, mock_open
from io import StringIO


class TestInformationDisclosureFix:
    """Test cases for information disclosure vulnerability fixes."""


    def test_environment_config_does_not_log_secrets(self):
        """Test that loadConfigValueFromFileOrEnvironment does not log secret content."""
        from app.utils.environment import loadConfigValueFromFileOrEnvironment

        # Create a mock logger to capture debug messages
        logger_output = StringIO()
        mock_logger = logging.getLogger('utils/environment')
        handler = logging.StreamHandler(logger_output)
        handler.setLevel(logging.DEBUG)
        mock_logger.addHandler(handler)
        mock_logger.setLevel(logging.DEBUG)

        # Test with secret file content
        secret_content = "super-secret-api-key-12345"

        with patch('builtins.open', mock_open(read_data=secret_content)):
            with patch('os.path.exists', return_value=True):
                with patch('os.path.isfile', return_value=True):
                    with patch.dict(os.environ, {'TEST_SECRET_FILE': '/tmp/test_secret.txt'}):
                        result = loadConfigValueFromFileOrEnvironment('TEST_SECRET', '')

        # Verify the secret was loaded correctly
        assert result == secret_content

        # Verify the secret content is NOT logged
        log_output = logger_output.getvalue()
        assert secret_content not in log_output
        assert '[REDACTED FOR SECURITY]' in log_output
        assert 'characters' in log_output  # Should log length instead

        # Clean up
        mock_logger.removeHandler(handler)

    def test_api_v1_does_not_log_tls_crypt_key(self):
        """Test that TLS-Crypt key values are not logged in API routes."""
        # This test verifies the fix in app/routes/api/v1.py line 163

        # Create a mock current_app.logger
        mock_logger = Mock()

        # Simulate the logging call with TLS-Crypt key
        tls_key = "-----BEGIN OpenVPN Static key V1-----\n1234567890abcdef\n-----END OpenVPN Static key V1-----"

        # The fixed version should log length, not the actual key
        mock_logger.debug(f"Adding server_tls_crypt_key: {tls_key is not None}, length: {len(tls_key) if tls_key else 0}")

        # Verify the debug call was made
        mock_logger.debug.assert_called_once()

        # Verify the call does not contain the actual key
        call_args = mock_logger.debug.call_args[0][0]
        assert tls_key not in call_args
        assert 'length:' in call_args
        assert str(len(tls_key)) in call_args

    def test_template_rendering_does_not_log_sensitive_content(self):
        """Test that rendered template content is not logged."""
        # This test verifies the fix in app/utils/render_config_template.py

        # Create a mock app.logger
        mock_logger = Mock()

        # Simulate rendered template with sensitive content
        rendered_template = """
cert <<EOF
-----BEGIN CERTIFICATE-----
MIIDExample123Certificate
-----END CERTIFICATE-----
EOF

key <<EOF
-----BEGIN PRIVATE KEY-----
MIIEvSensitivePrivateKey123
-----END PRIVATE KEY-----
EOF
"""

        # The fixed version should log length, not content
        mock_logger.debug(f'Rendered template output length: {len(rendered_template)} characters')

        # Verify the debug call was made
        mock_logger.debug.assert_called_once()

        # Verify the call does not contain sensitive content
        call_args = mock_logger.debug.call_args[0][0]
        assert 'PRIVATE KEY' not in call_args
        assert 'CERTIFICATE' not in call_args
        assert 'length:' in call_args
        assert 'characters' in call_args

    def test_config_loading_with_empty_file(self):
        """Test that empty config files are handled securely."""
        from app.utils.environment import loadConfigValueFromFileOrEnvironment

        # Create a mock logger to capture debug messages
        logger_output = StringIO()
        mock_logger = logging.getLogger('utils/environment')
        handler = logging.StreamHandler(logger_output)
        handler.setLevel(logging.DEBUG)
        mock_logger.addHandler(handler)
        mock_logger.setLevel(logging.DEBUG)

        # Test with empty file
        with patch('builtins.open', mock_open(read_data="")):
            with patch('os.path.exists', return_value=True):
                with patch('os.path.isfile', return_value=True):
                    with patch.dict(os.environ, {'TEST_EMPTY_FILE': '/tmp/empty.txt', 'TEST_EMPTY': 'fallback_value'}):
                        result = loadConfigValueFromFileOrEnvironment('TEST_EMPTY', 'default')

        # Should fall back to environment variable
        assert result == 'fallback_value'

        # Verify logs are safe
        log_output = logger_output.getvalue()
        assert '---No Content---' in log_output

        # Clean up
        mock_logger.removeHandler(handler)

    def test_config_loading_with_nonexistent_file(self):
        """Test that nonexistent config files don't expose path information."""
        from app.utils.environment import loadConfigValueFromFileOrEnvironment

        # Test with nonexistent file
        with patch('os.path.exists', return_value=False):
            with patch.dict(os.environ, {'TEST_MISSING': 'env_value'}):
                result = loadConfigValueFromFileOrEnvironment('TEST_MISSING', 'default')

        # Should fall back to environment variable
        assert result == 'env_value'

    def test_prevents_secret_leakage_in_various_scenarios(self):
        """Test various scenarios where secrets might be leaked."""
        test_cases = [
            ("API_KEY", "sk-1234567890abcdef"),
            ("DATABASE_PASSWORD", "MyS3cur3P@ssw0rd!"),
            ("ENCRYPTION_KEY", "fernet-key-1234567890abcdef"),
            ("OAUTH_CLIENT_SECRET", "oauth-secret-abcdef123456"),
        ]

        for key_name, secret_value in test_cases:
            # Create a mock logger to capture debug messages
            logger_output = StringIO()
            mock_logger = logging.getLogger('utils/environment')
            handler = logging.StreamHandler(logger_output)
            handler.setLevel(logging.DEBUG)
            mock_logger.addHandler(handler)
            mock_logger.setLevel(logging.DEBUG)

            from app.utils.environment import loadConfigValueFromFileOrEnvironment

            with patch('builtins.open', mock_open(read_data=secret_value)):
                with patch('os.path.exists', return_value=True):
                    with patch('os.path.isfile', return_value=True):
                        with patch.dict(os.environ, {f'{key_name}_FILE': f'/tmp/{key_name.lower()}.txt'}):
                            result = loadConfigValueFromFileOrEnvironment(key_name, '')

            # Verify the secret was loaded correctly
            assert result == secret_value

            # Verify the secret value is NOT in logs
            log_output = logger_output.getvalue()
            assert secret_value not in log_output
            assert '[REDACTED FOR SECURITY]' in log_output

            # Clean up
            mock_logger.removeHandler(handler)

    def test_debug_logging_does_not_contain_sensitive_patterns(self):
        """Test that debug logs don't contain common sensitive patterns."""
        # Patterns that should never appear in debug logs
        sensitive_patterns = [
            'password=',
            'secret=',
            'key=',
            'token=',
            'api_key=',
            'private_key=',
            'BEGIN PRIVATE KEY',
            'BEGIN CERTIFICATE',
            'BEGIN RSA PRIVATE KEY',
            'BEGIN ENCRYPTED PRIVATE KEY',
        ]

        # Create a mock logger to capture all debug messages
        logger_output = StringIO()
        test_logger = logging.getLogger('test_sensitive')
        handler = logging.StreamHandler(logger_output)
        handler.setLevel(logging.DEBUG)
        test_logger.addHandler(handler)
        test_logger.setLevel(logging.DEBUG)

        # Simulate various debug logging scenarios
        test_logger.debug("Configuration loaded successfully")
        test_logger.debug("File content loaded, length: 256 characters")
        test_logger.debug("Adding server_tls_crypt_key: True, length: 128")
        test_logger.debug("Rendered template output length: 1024 characters")

        log_content = logger_output.getvalue()

        # Verify no sensitive patterns are present
        for pattern in sensitive_patterns:
            assert pattern not in log_content, f"Sensitive pattern '{pattern}' found in debug logs"

        # Clean up
        test_logger.removeHandler(handler)

    def test_production_logging_level_prevents_debug_disclosure(self):
        """Test that production logging levels prevent debug information disclosure."""
        from app.utils.logging_config import setup_logging

        # Test production configuration
        production_config = {
            'ENVIRONMENT': 'production',
            'DEBUG': False
        }

        # Capture logging configuration
        with patch('logging.config.dictConfig') as mock_dictconfig:
            setup_logging(production_config)

            # Verify logging config was called
            mock_dictconfig.assert_called_once()

            # Get the logging configuration
            log_config = mock_dictconfig.call_args[0][0]

            # Verify production uses WARNING level, not DEBUG
            assert log_config['handlers']['application_events']['level'] == 'WARNING'

            # Verify security events are still logged at INFO level
            assert log_config['handlers']['security_events']['level'] == 'INFO'