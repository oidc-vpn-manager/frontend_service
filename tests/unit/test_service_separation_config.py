"""
Tests for service separation configuration validation.
"""

import pytest
import os
from unittest.mock import patch
from app.config import Config


# Required config values for tests
REQUIRED_ENV = {
    'FLASK_SECRET_KEY': 'test-secret-key-12345',
    'FERNET_ENCRYPTION_KEY': 'test-fernet-key-1234567890123456789012345678901='
}


class TestServiceSeparationConfig:
    """Test configuration validation for service separation."""
    
    def test_no_url_bases_configured(self):
        """Config allows both URL bases to be empty (default behavior)."""
        with patch.dict(os.environ, REQUIRED_ENV, clear=False):
            config = Config()
            assert config.ADMIN_URL_BASE == ''
            assert config.USER_URL_BASE == ''
    
    def test_only_admin_url_base_configured(self):
        """Config allows only ADMIN_URL_BASE (user service deployment)."""
        env = dict(REQUIRED_ENV)
        env['ADMIN_URL_BASE'] = 'http://admin.example.com'
        with patch.dict(os.environ, env, clear=False):
            config = Config()
            assert config.ADMIN_URL_BASE == 'http://admin.example.com'
            assert config.USER_URL_BASE == ''
    
    def test_only_user_url_base_configured(self):
        """Config allows only USER_URL_BASE (admin service deployment)."""
        env = dict(REQUIRED_ENV)
        env['USER_URL_BASE'] = 'http://user.example.com'
        with patch.dict(os.environ, env, clear=False):
            config = Config()
            assert config.USER_URL_BASE == 'http://user.example.com'
            assert config.ADMIN_URL_BASE == ''
    
    def test_both_url_bases_configured_raises_error(self):
        """Config raises RuntimeError when both URL bases configured (misconfiguration)."""
        env = dict(REQUIRED_ENV)
        env.update({
            'ADMIN_URL_BASE': 'http://admin.example.com',
            'USER_URL_BASE': 'http://user.example.com'
        })
        with patch.dict(os.environ, env, clear=False):
            with pytest.raises(RuntimeError) as exc_info:
                Config()
            
            error_message = str(exc_info.value)
            assert "Configuration error" in error_message
            assert "Both ADMIN_URL_BASE and USER_URL_BASE are configured" in error_message
            assert "User service: configure ADMIN_URL_BASE" in error_message
            assert "Admin service: configure USER_URL_BASE" in error_message
            assert "Combined service: configure neither" in error_message
    
    def test_empty_string_url_bases_allowed(self):
        """Config allows empty string URL bases (equivalent to not configured)."""
        env = dict(REQUIRED_ENV)
        env.update({
            'ADMIN_URL_BASE': '',
            'USER_URL_BASE': ''
        })
        with patch.dict(os.environ, env, clear=False):
            config = Config()
            assert config.ADMIN_URL_BASE == ''
            assert config.USER_URL_BASE == ''
    
    def test_whitespace_only_url_bases_treated_as_configured(self):
        """Config treats whitespace-only URL bases as configured (misconfiguration)."""
        env = dict(REQUIRED_ENV)
        env.update({
            'ADMIN_URL_BASE': '   ',
            'USER_URL_BASE': '\t\n'
        })
        with patch.dict(os.environ, env, clear=False):
            with pytest.raises(RuntimeError):
                Config()


class TestServiceSeparationDeploymentScenarios:
    """Test realistic deployment scenarios."""
    
    def test_user_service_deployment_config(self):
        """Test user service deployment configuration."""
        env = dict(REQUIRED_ENV)
        env.update({
            'ADMIN_URL_BASE': 'https://admin.vpn.example.com',
            'SITE_NAME': 'VPN Service'
        })
        with patch.dict(os.environ, env, clear=False):
            config = Config()
            assert config.ADMIN_URL_BASE == 'https://admin.vpn.example.com'
            assert config.USER_URL_BASE == ''
            assert config.SITE_NAME == 'VPN Service'
    
    def test_admin_service_deployment_config(self):
        """Test admin service deployment configuration."""
        env = dict(REQUIRED_ENV)
        env.update({
            'USER_URL_BASE': 'https://vpn.example.com',
            'SITE_NAME': 'VPN Admin'
        })
        with patch.dict(os.environ, env, clear=False):
            config = Config()
            assert config.USER_URL_BASE == 'https://vpn.example.com'
            assert config.ADMIN_URL_BASE == ''
            assert config.SITE_NAME == 'VPN Admin'
    
    def test_combined_service_deployment_config(self):
        """Test combined service deployment (current behavior).""" 
        env = dict(REQUIRED_ENV)
        env['SITE_NAME'] = 'VPN Manager'
        with patch.dict(os.environ, env, clear=True):
            config = Config()
            assert config.ADMIN_URL_BASE == ''
            assert config.USER_URL_BASE == ''
            assert config.SITE_NAME == 'VPN Manager'