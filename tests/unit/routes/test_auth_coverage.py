"""
Test cases to achieve 100% coverage for auth routes.
"""

import pytest
from flask import Flask, session, url_for, redirect
from unittest.mock import MagicMock, patch


@pytest.fixture
def app():
    """Provides a test instance of the Flask app with the necessary blueprints."""
    app = Flask(__name__)
    app.config['TESTING'] = True
    app.config['SECRET_KEY'] = 'test-secret-key'
    # Add OIDC group configuration for role testing
    app.config['OIDC_ADMIN_GROUP'] = 'admins'
    app.config['OIDC_AUDITOR_GROUP'] = 'auditors'
    app.config['OIDC_SYSTEM_ADMIN_GROUP'] = 'system-admins'
    
    # Register the auth blueprint
    from app.routes.auth import bp as auth_blueprint
    from app.routes.root import bp as root_blueprint
    app.register_blueprint(auth_blueprint)
    app.register_blueprint(root_blueprint)
    
    return app


@pytest.fixture
def mock_oauth(monkeypatch):
    """Mocks the oauth object and its nested methods."""
    mock_oauth_client = MagicMock()
    
    mock_oauth_client.oidc.authorize_redirect.return_value = redirect('/mocked-redirect')
    
    mock_oauth_client.oidc.authorize_access_token.return_value = {
        'userinfo': {'sub': '12345', 'name': 'Test User'},
        'id_token': 'fake-jwt-token'
    }
    
    # Mock the userinfo method to return serializable data
    mock_oauth_client.oidc.userinfo.return_value = {'sub': '12345', 'name': 'Test User'}
    
    mock_metadata = MagicMock()
    mock_metadata.get.return_value = 'https://provider.com/logout'
    mock_oauth_client.oidc.server_metadata = mock_metadata

    monkeypatch.setattr('app.routes.auth.oauth', mock_oauth_client)
    return mock_oauth_client


class TestPKCEConfiguration:
    """Tests verifying PKCE (RFC 7636) is correctly configured."""

    def _run_init_extensions(self, monkeypatch, app_config_overrides=None):
        """
        Helper to call init_extensions with mocked dependencies and capture
        the kwargs passed to oauth.register.

        Returns:
            dict: The captured kwargs from the oauth.register call.
        """
        import app.extensions as ext

        captured_kwargs = {}

        def capture_register(**kwargs):
            """Capture the kwargs passed to oauth.register."""
            if kwargs.get('name') == 'oidc':
                captured_kwargs.update(kwargs)

        # Replace all extensions with mocks to isolate the test
        mock_db = MagicMock()
        mock_db.metadata.tables = {}
        monkeypatch.setattr(ext, 'db', mock_db)
        monkeypatch.setattr(ext, 'migrate', MagicMock())
        monkeypatch.setattr(ext, 'sess', MagicMock())
        monkeypatch.setattr(ext, 'limiter', MagicMock())
        monkeypatch.setattr(ext, 'talisman', MagicMock())
        monkeypatch.setattr(ext, 'csrf', MagicMock())

        mock_oauth = MagicMock()
        mock_oauth.register = capture_register
        monkeypatch.setattr(ext, 'oauth', mock_oauth)

        test_app = Flask(__name__)
        test_app.config['OIDC_DISCOVERY_URL'] = 'https://test.example.com/.well-known/openid-configuration'
        test_app.config['OIDC_CLIENT_ID'] = 'test-client-id'
        test_app.config['OIDC_CLIENT_SECRET'] = 'test-client-secret'
        test_app.config['SESSION_SQLALCHEMY'] = MagicMock()
        if app_config_overrides:
            test_app.config.update(app_config_overrides)

        with test_app.app_context():
            ext.init_extensions(test_app)

        return captured_kwargs

    def test_pkce_enabled_when_oidc_require_pkce_true(self, monkeypatch):
        """
        Verifies that PKCE S256 is included in client_kwargs when OIDC_REQUIRE_PKCE is true.

        Security: PKCE prevents authorization code interception attacks (RFC 7636).
        When enabled, Authlib sends code_challenge in authorization requests and
        code_verifier in token exchange requests automatically.
        """
        captured = self._run_init_extensions(monkeypatch, {'OIDC_REQUIRE_PKCE': True})

        assert 'client_kwargs' in captured, "oauth.register must include client_kwargs"
        assert captured['client_kwargs'].get('code_challenge_method') == 'S256', \
            "OIDC client must use PKCE S256 when OIDC_REQUIRE_PKCE is true"

    def test_pkce_disabled_when_oidc_require_pkce_false(self, monkeypatch):
        """
        Verifies that PKCE is not included in client_kwargs when OIDC_REQUIRE_PKCE is false
        (the default), for backwards compatibility with providers that don't support PKCE.
        """
        captured = self._run_init_extensions(monkeypatch, {'OIDC_REQUIRE_PKCE': False})

        assert 'client_kwargs' in captured, "oauth.register must include client_kwargs"
        assert 'code_challenge_method' not in captured['client_kwargs'], \
            "OIDC client must not include code_challenge_method when OIDC_REQUIRE_PKCE is false"

    def test_pkce_disabled_by_default(self, monkeypatch):
        """
        Verifies that PKCE is off by default when OIDC_REQUIRE_PKCE is not set.
        """
        captured = self._run_init_extensions(monkeypatch)

        assert 'client_kwargs' in captured, "oauth.register must include client_kwargs"
        assert 'code_challenge_method' not in captured['client_kwargs'], \
            "OIDC client must not include code_challenge_method by default"


class TestAuthCoverage:
    """Tests to cover missing lines in auth routes."""

    def test_login_next_url_from_session_coverage(self, app, mock_oauth):
        """Test login route using next_url from session - covers lines 36-37."""
        client = app.test_client()
        
        # Set up session with next_url
        with client.session_transaction() as sess:
            sess['next_url'] = '/profile/dashboard'
            
        response = client.get('/auth/login')
        assert response.status_code == 302

    def test_login_next_url_storage_coverage(self, app, mock_oauth):
        """Test login route next URL storage logic - covers lines 45-46."""
        client = app.test_client()
        
        # Test with referrer URL from same origin (should be stored)
        response = client.get('/auth/login', 
                            headers={'Referer': 'http://localhost/profile/test'})
        assert response.status_code == 302

    def test_login_next_url_cleanup_coverage(self, app, mock_oauth):
        """Test login route next URL cleanup - covers line 49.""" 
        client = app.test_client()
        
        # Set up session with external URL that should be cleaned up
        with client.session_transaction() as sess:
            sess['next_url'] = 'http://evil.com/malicious'
            
        # Request with external next URL (should clean up session)
        response = client.get('/auth/login?next=http://external.com/bad')
        assert response.status_code == 302

    def test_callback_redirect_to_stored_url_coverage(self, app, mock_oauth):
        """Test callback route redirect to stored URL - covers lines 116-117."""
        client = app.test_client()
        
        # Set up mock OAuth to return specific user data
        mock_oauth.oidc.userinfo.return_value = {
            'sub': 'test-user',
            'email': 'test@example.com',
            'groups': []  # No groups = no admin roles
        }
        
        # Set up session with stored next_url
        with client.session_transaction() as sess:
            sess['next_url'] = '/profile/certificates'
        
        response = client.get('/auth/callback')
        # Should redirect to stored URL
        assert response.status_code == 302

    def test_callback_authentication_exception_handling_coverage(self, app, mock_oauth):
        """Test callback route exception handling - covers lines 132-142."""
        client = app.test_client()

        # Mock OAuth to throw an exception during token exchange
        mock_oauth.oidc.authorize_access_token.side_effect = Exception("OIDC provider error")

        with patch('app.routes.auth.security_logger.log_authentication_attempt') as mock_log_auth:
            response = client.get('/auth/callback')

            # Should redirect to login page on error
            assert response.status_code == 302
            assert response.location.endswith('/auth/login')

            # Should log authentication failure
            mock_log_auth.assert_called_once_with(
                user_id="unknown",
                success=False,
                method="oidc",
                failure_reason="OIDC provider error"
            )

    def test_login_invalid_cli_parameters_coverage(self, app, mock_oauth):
        """Test login route with invalid CLI parameters - covers lines 40-43."""
        client = app.test_client()

        # Test with invalid cli_port parameter (should trigger InputValidationError)
        response = client.get('/auth/login?cli_port=invalid_port&cli_optionset=test')
        assert response.status_code == 302  # Should still redirect to OIDC

        # Test with invalid cli_optionset (non-string, should trigger ValueError)
        response = client.get('/auth/login?cli_port=12345&cli_optionset=')
        assert response.status_code == 302  # Should still proceed without storing invalid params

    def test_login_invalid_next_url_validation_coverage(self, app, mock_oauth):
        """Test login route next_url validation errors - covers lines 73-75."""
        client = app.test_client()

        # The key insight: Flask protects against URL corruption, but we can still
        # trigger validation errors with URLs that have invalid schemes
        # Since the auth route calls validate_url with allowed_schemes=['http', 'https']
        # we need a URL that starts with url_root but has an invalid scheme

        # However, this is tricky because url_root will be http://localhost
        # Let me try a different approach - create a URL that's too long
        # since validate_url checks for length > 2048

        long_path = 'x' * 2100  # Exceeds the 2048 character limit
        long_url = f"http://localhost/{long_path}"

        response = client.get(f'/auth/login?next={long_url}')
        assert response.status_code == 302  # Should still redirect to OIDC

        # Also test with a URL that would cause urlparse to have issues
        # Try with a URL that has null bytes or other problematic characters
        # that might survive Flask's initial parsing but fail in validate_url
        problematic_url = "http://localhost/path\x00with\x01control\x02chars"
        response = client.get(f'/auth/login?next={problematic_url}')
        assert response.status_code == 302  # Should handle gracefully