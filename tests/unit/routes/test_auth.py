"""
Unit tests for the OIDC authentication routes.
"""

import pytest
from flask import Flask, session, url_for, redirect
from unittest.mock import MagicMock

# Import both blueprints needed for the tests
from app.routes.auth import bp as auth_blueprint
from app.routes.root import bp as root_blueprint

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
    
    # Register both blueprints so url_for can find all routes
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


def test_login_route(app, mock_oauth):
    """
    Tests that the /login route calls authorize_redirect and returns a redirect.
    """
    with app.test_request_context():
        client = app.test_client()
        response = client.get('/auth/login')
        
        assert response.status_code == 302
        
        mock_oauth.oidc.authorize_redirect.assert_called_once()
        expected_redirect_uri = url_for('auth.callback', _external=True)
        mock_oauth.oidc.authorize_redirect.assert_called_with(expected_redirect_uri)

def test_callback_route(app, mock_oauth):
    """
    Tests that the /callback route fetches the token, sets the session, and redirects.
    """
    client = app.test_client()
    response = client.get('/auth/callback')

    # Generate the expected URL within a request context
    with app.test_request_context():
        expected_redirect_location = url_for('root.index')
        
    assert response.status_code == 302
    assert response.location == expected_redirect_location
    
    with client.session_transaction() as sess:
        expected_user = {
            'sub': '12345', 
            'name': 'Test User',
            'is_admin': False,
            'is_auditor': False,
            'is_system_admin': False
        }
        assert sess['user'] == expected_user
        assert sess['id_token_jwt'] == 'fake-jwt-token'

def test_logout_route(app, mock_oauth):
    """
    Tests that the /logout route clears the session and redirects to the OIDC provider.
    """
    with app.test_client() as client:
        with client.session_transaction() as sess:
            sess['user'] = {'sub': '12345', 'name': 'Test User'}
            sess['id_token_jwt'] = 'fake-jwt-token'
        
        response = client.get('/auth/logout')

        assert response.status_code == 302
        assert 'https://provider.com/logout' in response.location
        assert 'id_token_hint=fake-jwt-token' in response.location
    
    with client.session_transaction() as sess:
        assert 'user' not in sess

def test_logout_route_no_endpoint(app, mock_oauth):
    """
    Tests the logout fallback behaviour when the OIDC provider has no end_session_endpoint.
    """
    mock_oauth.oidc.server_metadata = {}

    with app.test_client() as client:
        with client.session_transaction() as sess:
            sess['user'] = {'sub': '12345'}
        
        response = client.get('/auth/logout')

        # Generate the expected URL within a request context
        with app.test_request_context():
            expected_redirect_location = url_for('root.index')

        assert response.status_code == 302
        assert response.location == expected_redirect_location
    
    with client.session_transaction() as sess:
        assert 'user' not in sess

def test_logout_with_idp_flow_disabled(app, mock_oauth):
    """
    Tests that the user is logged out locally and redirected home
    when the OIDC provider logout flow is disabled in the config.
    """
    # Arrange: Disable the IDP logout flow
    app.config['OIDC_DISABLE_IDP_LOGOUT_FLOW'] = True
    
    with app.test_client() as client:
        # Simulate a logged-in user
        with client.session_transaction() as sess:
            sess['user'] = {'sub': '12345'}
            sess['id_token_jwt'] = 'fake-jwt-token'

        # Act
        response = client.get('/auth/logout')

    # Assert: User is redirected to the home page, not the OIDC provider
    with app.test_request_context():
        expected_redirect_location = url_for('root.index')

    assert response.status_code == 302
    assert response.location == expected_redirect_location
    
    # Assert that the OIDC logout endpoint was NOT called
    mock_oauth.oidc.server_metadata.get.assert_not_called()

    # Session should still be cleared
    with client.session_transaction() as sess:
        assert 'user' not in sess


def test_callback_admin_role_assignment(app, mock_oauth):
    """
    Tests that admin role is correctly assigned when user has admin group.
    """
    # Mock userinfo with admin group
    mock_oauth.oidc.userinfo.return_value = {
        'sub': '12345', 
        'name': 'Admin User',
        'groups': ['users', 'admins']
    }
    
    client = app.test_client()
    response = client.get('/auth/callback')
    
    with client.session_transaction() as sess:
        assert sess['user']['is_admin'] == True
        assert sess['user']['is_auditor'] == False
        assert sess['user']['is_system_admin'] == False


def test_callback_auditor_role_assignment(app, mock_oauth):
    """
    Tests that auditor role is correctly assigned when user has auditor group.
    """
    # Mock userinfo with auditor group
    mock_oauth.oidc.userinfo.return_value = {
        'sub': '12345', 
        'name': 'Auditor User',
        'groups': ['users', 'auditors']
    }
    
    client = app.test_client()
    response = client.get('/auth/callback')
    
    with client.session_transaction() as sess:
        assert sess['user']['is_admin'] == False
        assert sess['user']['is_auditor'] == True
        assert sess['user']['is_system_admin'] == False


def test_callback_system_admin_role_assignment(app, mock_oauth):
    """
    Tests that system admin role is correctly assigned when user has system-admins group.
    """
    # Mock userinfo with system admin group
    mock_oauth.oidc.userinfo.return_value = {
        'sub': '12345', 
        'name': 'System Admin User',
        'groups': ['users', 'system-admins']
    }
    
    client = app.test_client()
    response = client.get('/auth/callback')
    
    with client.session_transaction() as sess:
        assert sess['user']['is_admin'] == False
        assert sess['user']['is_auditor'] == False
        assert sess['user']['is_system_admin'] == True


def test_callback_multiple_roles(app, mock_oauth):
    """
    Tests that multiple roles are correctly assigned when user has multiple groups.
    """
    # Mock userinfo with multiple admin groups
    mock_oauth.oidc.userinfo.return_value = {
        'sub': '12345', 
        'name': 'Multi Role User',
        'groups': ['users', 'admins', 'auditors']
    }
    
    client = app.test_client()
    response = client.get('/auth/callback')
    
    with client.session_transaction() as sess:
        assert sess['user']['is_admin'] == True
        assert sess['user']['is_auditor'] == True
        assert sess['user']['is_system_admin'] == False


def test_callback_single_group_as_string(app, mock_oauth):
    """
    Tests that role assignment works when groups is a single string instead of array.
    """
    # Mock userinfo with single group as string
    mock_oauth.oidc.userinfo.return_value = {
        'sub': '12345', 
        'name': 'Single Group User',
        'groups': 'admins'  # Single string instead of array
    }
    
    client = app.test_client()
    response = client.get('/auth/callback')
    
    with client.session_transaction() as sess:
        assert sess['user']['is_admin'] == True
        assert sess['user']['is_auditor'] == False
        assert sess['user']['is_system_admin'] == False


def test_callback_comma_separated_groups_assignment(app, mock_oauth):
    """
    Tests comma-separated groups string handling - covers line 38.
    """
    # Mock userinfo with comma-separated groups string
    mock_oauth.oidc.userinfo.return_value = {
        'sub': '12345',
        'name': 'Multi Group User',
        'groups': 'users, admins, auditors'  # Comma-separated string
    }

    client = app.test_client()
    response = client.get('/auth/callback')

    with client.session_transaction() as sess:
        assert sess['user']['is_admin'] == True
        assert sess['user']['is_auditor'] == True
        assert sess['user']['is_system_admin'] == False


class TestVuln01OpenRedirect:
    """VULN-01: The ?next= parameter must reject protocol-relative URLs like //evil.com.

    The previous check `startswith('/')` accepted `//evil.com` because it starts
    with `/`. Browsers treat `//host/path` as protocol-relative and follow it to
    an external domain after the OIDC login completes.
    """

    def test_double_slash_host_rejected(self, app, mock_oauth):
        """//evil.com must not be stored as next_url in the session."""
        client = app.test_client()
        client.get('/auth/login?next=//evil.com')
        with client.session_transaction() as sess:
            assert sess.get('next_url') != '//evil.com'

    def test_double_slash_host_with_path_rejected(self, app, mock_oauth):
        """//attacker.com/path must not be stored as next_url in the session."""
        client = app.test_client()
        client.get('/auth/login?next=//attacker.com/path')
        with client.session_transaction() as sess:
            assert sess.get('next_url') != '//attacker.com/path'

    def test_absolute_http_url_rejected(self, app, mock_oauth):
        """http://evil.com must not be stored as next_url in the session."""
        client = app.test_client()
        client.get('/auth/login?next=http://evil.com')
        with client.session_transaction() as sess:
            assert sess.get('next_url') != 'http://evil.com'

    def test_relative_path_accepted(self, app, mock_oauth):
        """/profile is a safe relative URL and must be stored in the session."""
        client = app.test_client()
        client.get('/auth/login?next=/profile')
        with client.session_transaction() as sess:
            assert sess.get('next_url') == '/profile'

    def test_relative_path_with_segments_accepted(self, app, mock_oauth):
        """/profile/certificates is a safe relative URL and must be stored."""
        client = app.test_client()
        client.get('/auth/login?next=/profile/certificates')
        with client.session_transaction() as sess:
            assert sess.get('next_url') == '/profile/certificates'


@pytest.fixture
def test_auth_app():
    """Flask app with the mock OIDC test blueprints registered."""
    import os
    os.environ['ENABLE_TEST_AUTH_ROUTES'] = 'true'
    app = Flask(__name__)
    app.config['TESTING'] = True
    app.config['SECRET_KEY'] = 'test-secret-key-vuln17'

    from app.routes.test_auth import bp_root as test_auth_root_bp
    app.register_blueprint(test_auth_root_bp)

    return app


class TestVuln17MockOidcCallbackOpenRedirect:
    """VULN-17: mock_oidc_callback must validate redirect_uri to prevent open redirect.

    Before fix: redirect_uri from POST body is used directly with no validation,
    so an attacker-controlled value like http://attacker.com causes the server to
    redirect the victim's browser to an external site after mock login.

    After fix: same startswith('/') and not startswith('//') guard as auth.py;
    external URLs fall back to '/'.
    """

    def test_external_url_rejected(self, test_auth_app):
        """http://attacker.com as redirect_uri must not redirect to that host."""
        client = test_auth_app.test_client()
        response = client.post('/mock_oidc_callback', data={
            'email': 'user@example.com',
            'redirect_uri': 'http://attacker.com/steal',
        })
        assert response.status_code == 302
        assert 'attacker.com' not in response.location

    def test_protocol_relative_url_rejected(self, test_auth_app):
        """//evil.com as redirect_uri must not redirect to that host."""
        client = test_auth_app.test_client()
        response = client.post('/mock_oidc_callback', data={
            'email': 'user@example.com',
            'redirect_uri': '//evil.com',
        })
        assert response.status_code == 302
        assert 'evil.com' not in response.location

    def test_relative_path_accepted(self, test_auth_app):
        """/dashboard is a safe relative URL and must be followed."""
        client = test_auth_app.test_client()
        response = client.post('/mock_oidc_callback', data={
            'email': 'user@example.com',
            'redirect_uri': '/dashboard',
        })
        assert response.status_code == 302
        assert response.location == '/dashboard'
