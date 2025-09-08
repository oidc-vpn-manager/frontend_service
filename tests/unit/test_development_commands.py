"""
Unit tests for development-only CLI commands.
"""

import pytest
from unittest.mock import patch, MagicMock
from click.testing import CliRunner
from datetime import datetime, timezone, timedelta

from app import create_app
from app.extensions import db
from app.commands import create_psk_command, create_dev_auth_command
from app.models import PreSharedKey


@pytest.fixture(scope='function')
def app(monkeypatch):
    """Create application instance for testing."""
    # Set TESTING environment variable to ensure in-memory database is used
    monkeypatch.setenv('TESTING', 'True')
    monkeypatch.setenv('FLASK_SECRET_KEY', 'test-secret-key-for-cli-testing')
    monkeypatch.setenv('FERNET_ENCRYPTION_KEY', 'test-encryption-key-for-cli-testing-32-chars-long')
    
    app = create_app('development')
    app.config.update({
        "TESTING": True,
        "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
        "WTF_CSRF_ENABLED": False,
    })

    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()


@pytest.fixture(scope='function')
def client(app):
    """A test client for the app."""
    return app.test_client()


class TestDevelopmentCommands:
    """Test development-only CLI commands."""

    def test_create_psk_development_mode_allowed(self, app):
        """Test PSK creation is allowed in development mode."""
        with app.app_context():
            # Mock development mode
            with patch.object(app.config, 'get') as mock_config:
                mock_config.side_effect = lambda key, default=None: 'development' if key == 'ENVIRONMENT' else default
                
                runner = CliRunner()
                result = runner.invoke(create_psk_command, ['--description', 'test-server-dev'])
                
                assert result.exit_code == 0
                assert 'DEVELOPMENT MODE PSK CREATED' in result.output
                assert 'Description: test-server-dev' in result.output
                assert 'PSK:' in result.output
                
                # Verify PSK was created in database
                psk = PreSharedKey.query.filter_by(description='test-server-dev').first()
                assert psk is not None
                assert psk.description == 'test-server-dev'

    def test_create_psk_production_mode_blocked(self, app):
        """Test PSK creation is blocked in production mode."""
        with app.app_context():
            # Mock production mode
            with patch.object(app.config, 'get') as mock_config:
                mock_config.side_effect = lambda key, default=None: 'production' if key == 'ENVIRONMENT' else default
                
                runner = CliRunner()
                result = runner.invoke(create_psk_command, ['--description', 'test-server-prod'])
                
                assert result.exit_code == 0
                assert 'ERROR: This command is only available in development mode!' in result.output
                assert 'Set ENVIRONMENT=development' in result.output
                
                # Verify no PSK was created
                psk = PreSharedKey.query.filter_by(description='test-server-prod').first()
                assert psk is None

    def test_create_psk_with_expiration(self, app):
        """Test PSK creation with expiration date."""
        with app.app_context():
            with patch.object(app.config, 'get') as mock_config:
                mock_config.side_effect = lambda key, default=None: 'development' if key == 'ENVIRONMENT' else default
                
                runner = CliRunner()
                result = runner.invoke(create_psk_command, [
                    '--description', 'test-server-expires',
                    '--expires-days', '30'
                ])
                
                assert result.exit_code == 0
                assert 'Expires:' in result.output
                
                psk = PreSharedKey.query.filter_by(description='test-server-expires').first()
                assert psk is not None
                assert psk.expires_at is not None
                # Should expire roughly 30 days from now
                expected_expiry = datetime.now(timezone.utc) + timedelta(days=30)
                # Handle timezone-aware datetime comparison
                if psk.expires_at.tzinfo is None:
                    # If PSK expiry is naive, compare with naive datetime
                    expected_expiry = expected_expiry.replace(tzinfo=None)
                assert abs((psk.expires_at - expected_expiry).total_seconds()) < 60

    def test_create_psk_duplicate_hostname(self, app):
        """Test PSK creation fails for duplicate hostname."""
        with app.app_context():
            # Create existing PSK
            existing_psk = PreSharedKey(description='existing-server')
            db.session.add(existing_psk)
            db.session.commit()
            
            with patch.object(app.config, 'get') as mock_config:
                mock_config.side_effect = lambda key, default=None: 'development' if key == 'ENVIRONMENT' else default
                
                runner = CliRunner()
                result = runner.invoke(create_psk_command, ['--description', 'existing-server'])
                
                assert result.exit_code == 0
                assert 'ERROR: PSK for description "existing-server" already exists!' in result.output

    def test_create_dev_auth_development_mode(self, app):
        """Test development auth token creation in development mode."""
        with app.app_context():
            with patch.object(app.config, 'get') as mock_config:
                mock_config.side_effect = lambda key, default=None: {
                    'ENVIRONMENT': 'development',
                    'OIDC_ADMIN_GROUP': 'test-admins'
                }.get(key, default)
                
                runner = CliRunner()
                result = runner.invoke(create_dev_auth_command, [
                    '--username', 'testuser',
                    '--email', 'test@example.com',
                    '--admin'
                ])
                
                assert result.exit_code == 0
                assert 'DEVELOPMENT MODE AUTH TOKEN' in result.output
                assert 'Username: testuser' in result.output
                assert 'Email: test@example.com' in result.output
                assert 'Groups: [\'test-admins\']' in result.output
                assert 'Auth Token: dev-auth-' in result.output
                assert 'X-Dev-Auth:' in result.output

    def test_create_dev_auth_production_mode_blocked(self, app):
        """Test development auth token creation is blocked in production."""
        with app.app_context():
            with patch.object(app.config, 'get') as mock_config:
                mock_config.side_effect = lambda key, default=None: 'production' if key == 'ENVIRONMENT' else default
                
                runner = CliRunner()
                result = runner.invoke(create_dev_auth_command, ['--username', 'testuser'])
                
                assert result.exit_code == 0
                assert 'ERROR: This command is only available in development mode!' in result.output

    def test_create_dev_auth_without_admin(self, app):
        """Test development auth token creation without admin flag."""
        with app.app_context():
            with patch.object(app.config, 'get') as mock_config:
                mock_config.side_effect = lambda key, default=None: 'development' if key == 'ENVIRONMENT' else default
                
                runner = CliRunner()
                result = runner.invoke(create_dev_auth_command, ['--username', 'testuser'])
                
                assert result.exit_code == 0
                assert 'Groups: []' in result.output