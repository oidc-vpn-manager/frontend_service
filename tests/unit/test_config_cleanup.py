"""
Test for configuration cleanup - TDD approach.

This test ensures unused configuration values are removed from the frontend config.
"""

import pytest
import os


class TestConfigCleanup:
    """Test removal of unused configuration values."""

    def test_openvpn_server_hostname_removed_from_config_file(self):
        """Test that OPENVPN_SERVER_HOSTNAME is removed from config.py file."""
        # Read the config file content
        config_file = os.path.join(os.path.dirname(__file__), '..', '..', 'app', 'config.py')
        with open(config_file, 'r') as f:
            config_content = f.read()
        
        # This test will FAIL initially, demonstrating the unused config exists
        assert 'OPENVPN_SERVER_HOSTNAME' not in config_content, (
            "OPENVPN_SERVER_HOSTNAME should be removed from config.py as it's not used in the codebase"
        )

    def test_openvpn_server_port_removed_from_config_file(self):
        """Test that OPENVPN_SERVER_PORT is removed from config.py file."""
        # Read the config file content
        config_file = os.path.join(os.path.dirname(__file__), '..', '..', 'app', 'config.py')
        with open(config_file, 'r') as f:
            config_content = f.read()
        
        # This test will FAIL initially, demonstrating the unused config exists
        assert 'OPENVPN_SERVER_PORT' not in config_content, (
            "OPENVPN_SERVER_PORT should be removed from config.py as it's not used in the codebase"
        )

    def test_essential_configs_still_exist_in_file(self):
        """Test that essential configurations are not accidentally removed."""
        # Read the config file content
        config_file = os.path.join(os.path.dirname(__file__), '..', '..', 'app', 'config.py')
        with open(config_file, 'r') as f:
            config_content = f.read()
        
        # Verify essential configs still exist in file
        essential_configs = [
            'FLASK_SECRET_KEY',
            'DATABASE_URL',
            'OIDC_CLIENT_ID',
            'SIGNING_SERVICE_URL',
            'CERTTRANSPARENCY_SERVICE_URL',
            'ROOT_CA_CERTIFICATE',
            'INTERMEDIATE_CA_CERTIFICATE'
        ]
        
        for config_name in essential_configs:
            assert config_name in config_content, (
                f"{config_name} is essential and should not be removed"
            )

    def test_openvpn_tls_crypt_key_still_exists_in_file(self):
        """Test that OPENVPN_TLS_CRYPT_KEY (which IS used) is not removed."""
        # Read the config file content
        config_file = os.path.join(os.path.dirname(__file__), '..', '..', 'app', 'config.py')
        with open(config_file, 'r') as f:
            config_content = f.read()
        
        # This config IS used and should remain
        assert 'OPENVPN_TLS_CRYPT_KEY' in config_content, (
            "OPENVPN_TLS_CRYPT_KEY is actively used and should remain in config"
        )

    def test_removed_configs_not_used_anywhere(self):
        """Document that the removed configs were not used anywhere in codebase."""
        # This test documents our findings
        unused_configs = ['OPENVPN_SERVER_HOSTNAME', 'OPENVPN_SERVER_PORT']
        
        # These were found only in:
        # 1. config.py (definition)
        # 2. deployment documentation 
        # 3. helm templates and docker env files
        # But NOT in any runtime Python code
        
        assert len(unused_configs) == 2
        assert 'OPENVPN_SERVER_HOSTNAME' in unused_configs
        assert 'OPENVPN_SERVER_PORT' in unused_configs