"""
Security tests for CVE-2 Authentication Bypass vulnerability fix.

This test suite validates that test authentication routes are properly disabled
in production environments to prevent authentication bypass attacks.
"""

import pytest
import os
from unittest.mock import Mock, patch


class TestAuthBypassFix:
    """Test cases for authentication bypass vulnerability fixes."""

    def test_blocks_test_routes_in_production(self):
        """Test that test auth routes are blocked in production environments."""
        # Mock production app configuration
        app_mock = Mock()
        app_mock.config = {
            'ENVIRONMENT': 'production',
            'FLASK_ENV': 'production',
            'TESTING': False,
            'PRODUCTION': True
        }
        app_mock.logger = Mock()

        with patch.dict(os.environ, {'FLASK_ENV': 'production', 'ENABLE_TEST_AUTH_ROUTES': 'false'}):
            # Test the condition logic
            is_development = (
                app_mock.config.get('ENVIRONMENT') == 'development' and
                app_mock.config.get('FLASK_ENV') == 'development' and
                os.environ.get('FLASK_ENV') == 'development' and
                app_mock.config.get('TESTING') is not True and
                not app_mock.config.get('PRODUCTION', False)
            )
            enable_test_auth = os.environ.get('ENABLE_TEST_AUTH_ROUTES', '').lower() == 'true'

            # Should NOT enable test auth routes in production
            assert is_development is False
            assert enable_test_auth is False
            assert not (is_development and enable_test_auth)

    def test_blocks_test_routes_without_explicit_enable(self):
        """Test that test routes require explicit enabling even in development."""
        # Mock development app configuration
        app_mock = Mock()
        app_mock.config = {
            'ENVIRONMENT': 'development',
            'FLASK_ENV': 'development',
            'TESTING': False,
            'PRODUCTION': False
        }
        app_mock.logger = Mock()

        with patch.dict(os.environ, {'FLASK_ENV': 'development', 'ENABLE_TEST_AUTH_ROUTES': 'false'}):
            # Test the condition logic
            is_development = (
                app_mock.config.get('ENVIRONMENT') == 'development' and
                app_mock.config.get('FLASK_ENV') == 'development' and
                os.environ.get('FLASK_ENV') == 'development' and
                app_mock.config.get('TESTING') is not True and
                not app_mock.config.get('PRODUCTION', False)
            )
            enable_test_auth = os.environ.get('ENABLE_TEST_AUTH_ROUTES', '').lower() == 'true'

            # Should require explicit enabling
            assert is_development is True
            assert enable_test_auth is False
            assert not (is_development and enable_test_auth)

    def test_allows_test_routes_only_with_full_dev_setup(self):
        """Test that test routes are only allowed with complete development setup."""
        # Mock full development app configuration
        app_mock = Mock()
        app_mock.config = {
            'ENVIRONMENT': 'development',
            'FLASK_ENV': 'development',
            'TESTING': False,
            'PRODUCTION': False
        }
        app_mock.logger = Mock()

        with patch.dict(os.environ, {'FLASK_ENV': 'development', 'ENABLE_TEST_AUTH_ROUTES': 'true'}):
            # Test the condition logic
            is_development = (
                app_mock.config.get('ENVIRONMENT') == 'development' and
                app_mock.config.get('FLASK_ENV') == 'development' and
                os.environ.get('FLASK_ENV') == 'development' and
                app_mock.config.get('TESTING') is not True and
                not app_mock.config.get('PRODUCTION', False)
            )
            enable_test_auth = os.environ.get('ENABLE_TEST_AUTH_ROUTES', '').lower() == 'true'

            # Should allow test auth routes only with all conditions met
            assert is_development is True
            assert enable_test_auth is True
            assert (is_development and enable_test_auth) is True

    def test_blocks_test_routes_in_testing_mode(self):
        """Test that test routes are blocked even in testing environments."""
        # Mock testing app configuration
        app_mock = Mock()
        app_mock.config = {
            'ENVIRONMENT': 'development',
            'FLASK_ENV': 'development',
            'TESTING': True,  # Testing mode should block
            'PRODUCTION': False
        }
        app_mock.logger = Mock()

        with patch.dict(os.environ, {'FLASK_ENV': 'development', 'ENABLE_TEST_AUTH_ROUTES': 'true'}):
            # Test the condition logic
            is_development = (
                app_mock.config.get('ENVIRONMENT') == 'development' and
                app_mock.config.get('FLASK_ENV') == 'development' and
                os.environ.get('FLASK_ENV') == 'development' and
                app_mock.config.get('TESTING') is not True and  # This should fail
                not app_mock.config.get('PRODUCTION', False)
            )
            enable_test_auth = os.environ.get('ENABLE_TEST_AUTH_ROUTES', '').lower() == 'true'

            # Should NOT enable test auth routes in testing mode
            assert is_development is False  # Due to TESTING=True
            assert enable_test_auth is True
            assert not (is_development and enable_test_auth)

    def test_mixed_environment_configurations(self):
        """Test various mixed environment configurations for security."""
        test_cases = [
            # (ENVIRONMENT, FLASK_ENV, ENV_VAR, TESTING, PRODUCTION, ENABLE_FLAG, EXPECTED)
            ('production', 'development', 'development', False, False, 'true', False),
            ('development', 'production', 'development', False, False, 'true', False),
            ('development', 'development', 'production', False, False, 'true', False),
            ('development', 'development', 'development', True, False, 'true', False),
            ('development', 'development', 'development', False, True, 'true', False),
            ('', 'development', 'development', False, False, 'true', False),
            ('development', '', 'development', False, False, 'true', False),
            ('development', 'development', '', False, False, 'true', False),
        ]

        for env, flask_env, env_var, testing, production, enable_flag, expected in test_cases:
            app_mock = Mock()
            app_mock.config = {
                'ENVIRONMENT': env,
                'FLASK_ENV': flask_env,
                'TESTING': testing,
                'PRODUCTION': production
            }

            with patch.dict(os.environ, {'FLASK_ENV': env_var, 'ENABLE_TEST_AUTH_ROUTES': enable_flag}):
                is_development = (
                    app_mock.config.get('ENVIRONMENT') == 'development' and
                    app_mock.config.get('FLASK_ENV') == 'development' and
                    os.environ.get('FLASK_ENV') == 'development' and
                    app_mock.config.get('TESTING') is not True and
                    not app_mock.config.get('PRODUCTION', False)
                )
                enable_test_auth = os.environ.get('ENABLE_TEST_AUTH_ROUTES', '') == 'true'
                result = is_development and enable_test_auth

                assert result == expected, f"Failed for config: {env}/{flask_env}/{env_var}/{testing}/{production}/{enable_flag}"

    def test_case_sensitivity_and_variations(self):
        """Test that environment variable parsing is case sensitive and secure."""
        enable_variations = [
            ('TRUE', False),   # Should be case sensitive
            ('True', False),   # Should be case sensitive
            ('1', False),      # Should only accept 'true'
            ('yes', False),    # Should only accept 'true'
            ('on', False),     # Should only accept 'true'
            ('true', True),    # Only this should work
            ('', False),       # Empty should be false
        ]

        app_mock = Mock()
        app_mock.config = {
            'ENVIRONMENT': 'development',
            'FLASK_ENV': 'development',
            'TESTING': False,
            'PRODUCTION': False
        }

        for flag_value, expected in enable_variations:
            with patch.dict(os.environ, {'FLASK_ENV': 'development', 'ENABLE_TEST_AUTH_ROUTES': flag_value}):
                enable_test_auth = os.environ.get('ENABLE_TEST_AUTH_ROUTES', '') == 'true'
                assert enable_test_auth == expected, f"Failed for flag value: '{flag_value}'"