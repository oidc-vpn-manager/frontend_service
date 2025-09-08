"""
Integration tests for development CLI commands.
"""

import pytest
from click.testing import CliRunner
from unittest.mock import patch

from app.models import PreSharedKey


class TestDevelopmentCLIIntegration:
    """Integration tests for development CLI commands with real database."""

    def test_create_psk_full_integration(self, app):
        """Test full PSK creation integration with database."""
        with app.app_context():
            # Ensure we're in development mode
            app.config['ENVIRONMENT'] = 'development'
            
            # Import the command function
            from app.commands import create_psk_command
            
            runner = CliRunner()
            result = runner.invoke(create_psk_command, [
                '--description', 'integration-test-server',
                '--expires-days', '7'
            ])
            
            assert result.exit_code == 0
            assert 'DEVELOPMENT MODE PSK CREATED' in result.output
            
            # Verify the PSK exists in the database and is valid
            psk = PreSharedKey.query.filter_by(description='integration-test-server').first()
            assert psk is not None
            assert psk.description == 'integration-test-server'
            assert psk.is_enabled is True
            assert psk.expires_at is not None
            assert psk.is_valid() is True
            
            # Verify the key hash exists and is valid
            assert psk.key_hash is not None
            assert len(psk.key_hash) == 64  # SHA256 hex string
            assert 'integration-test-server' in result.output

    def test_create_multiple_psks_different_hostnames(self, app):
        """Test creating multiple PSKs with different hostnames."""
        with app.app_context():
            app.config['ENVIRONMENT'] = 'development'
            
            from app.commands import create_psk_command
            runner = CliRunner()
            
            # Create first PSK
            result1 = runner.invoke(create_psk_command, ['--description', 'server1'])
            assert result1.exit_code == 0
            
            # Create second PSK
            result2 = runner.invoke(create_psk_command, ['--description', 'server2'])
            assert result2.exit_code == 0
            
            # Verify both exist and are different
            psk1 = PreSharedKey.query.filter_by(description='server1').first()
            psk2 = PreSharedKey.query.filter_by(description='server2').first()
            
            assert psk1 is not None
            assert psk2 is not None
            assert psk1.key_hash != psk2.key_hash
            assert psk1.description != psk2.description

    def test_create_psk_production_mode_integration(self, app):
        """Test PSK creation is properly blocked in production mode."""
        with app.app_context():
            # Set production mode
            app.config['ENVIRONMENT'] = 'production'
            
            from app.commands import create_psk_command
            runner = CliRunner()
            
            result = runner.invoke(create_psk_command, ['--description', 'blocked-server'])
            assert result.exit_code == 0
            assert 'ERROR: This command is only available in development mode!' in result.output
            
            # Verify no PSK was created
            psk = PreSharedKey.query.filter_by(description='blocked-server').first()
            assert psk is None

    def test_dev_auth_command_integration(self, app):
        """Test development auth command integration."""
        with app.app_context():
            app.config['ENVIRONMENT'] = 'development'
            app.config['OIDC_ADMIN_GROUP'] = 'integration-admins'
            
            from app.commands import create_dev_auth_command
            runner = CliRunner()
            
            result = runner.invoke(create_dev_auth_command, [
                '--username', 'integration-user',
                '--email', 'integration@test.com',
                '--admin'
            ])
            
            assert result.exit_code == 0
            assert 'DEVELOPMENT MODE AUTH TOKEN' in result.output
            assert 'Username: integration-user' in result.output
            assert 'Email: integration@test.com' in result.output
            assert 'Groups: [\'integration-admins\']' in result.output
            assert 'dev-auth-' in result.output
            assert 'X-Dev-Auth:' in result.output

    def test_psk_creation_with_database_constraints(self, app):
        """Test PSK creation respects database constraints."""
        with app.app_context():
            app.config['ENVIRONMENT'] = 'development'
            
            from app.commands import create_psk_command
            runner = CliRunner()
            
            # Create first PSK
            result1 = runner.invoke(create_psk_command, ['--description', 'constraint-test'])
            assert result1.exit_code == 0
            
            # Try to create duplicate - should fail
            result2 = runner.invoke(create_psk_command, ['--description', 'constraint-test'])
            assert result2.exit_code == 0
            assert 'ERROR: PSK for description "constraint-test" already exists!' in result2.output
            
            # Verify only one PSK exists
            psks = PreSharedKey.query.filter_by(description='constraint-test').all()
            assert len(psks) == 1