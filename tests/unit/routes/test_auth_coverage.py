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