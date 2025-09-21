"""
Test the test authentication routes used for development/testing.
"""

import pytest
import json
from unittest.mock import patch
from flask import Flask
from app.routes.test_auth import bp as test_auth_blueprint, bp_root as test_auth_root_blueprint


@pytest.fixture
def app():
    """Create test Flask app."""
    app = Flask(__name__)
    app.config.update({
        "TESTING": True,
        "SECRET_KEY": "test-secret"
    })
    
    app.register_blueprint(test_auth_blueprint)
    app.register_blueprint(test_auth_root_blueprint)
    return app


def test_set_session_with_data(app):
    """Test setting session with provided data."""
    with app.test_client() as client:
        response = client.post('/test/set-session', 
                              json={
                                  'user_id': 'custom-user',
                                  'email': 'custom@example.com',
                                  'name': 'Custom User',
                                  'groups': ['admins', 'users']
                              })
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['status'] == 'success'
        assert data['user_id'] == 'custom-user'
        assert data['groups'] == ['admins', 'users']


def test_set_session_with_defaults(app):
    """Test setting session with default values."""
    with app.test_client() as client:
        response = client.post('/test/set-session', json={})
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['status'] == 'success'
        assert data['user_id'] == 'test-user'  # Default value
        assert data['groups'] == ['users']     # Default value


def test_set_session_with_empty_json(app):
    """Test setting session with empty JSON data."""
    with app.test_client() as client:
        response = client.post('/test/set-session', data='{}', 
                              headers={'Content-Type': 'application/json'})
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['status'] == 'success'
        assert data['user_id'] == 'test-user'  # Default value when empty JSON


def test_clear_session(app):
    """Test clearing session data."""
    with app.test_client() as client:
        # First set a session
        client.post('/test/set-session', json={'user_id': 'temp-user'})
        
        # Then clear it
        response = client.post('/test/clear-session')
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['status'] == 'success'
        assert data['message'] == 'Session cleared'


def test_get_session_with_user(app):
    """Test getting session data when user is set."""
    with app.test_client() as client:
        # Set session data
        client.post('/test/set-session', 
                   json={
                       'user_id': 'get-user',
                       'email': 'get@example.com',
                       'name': 'Get User',
                       'groups': ['testers']
                   })
        
        # Get session data
        response = client.get('/test/get-session')
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['user_id'] == 'get-user'
        assert data['email'] == 'get@example.com'
        assert data['name'] == 'Get User'
        assert data['groups'] == ['testers']


def test_get_session_without_user(app):
    """Test getting session data when no user is set."""
    with app.test_client() as client:
        # Clear any existing session
        client.post('/test/clear-session')
        
        # Get session data
        response = client.get('/test/get-session')
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['user_id'] is None
        assert data['email'] is None
        assert data['name'] is None
        assert data['groups'] == []  # Default empty list


@patch('flask.render_template')
def test_mock_oidc_login_default_redirect(mock_render_template, app):
    """Test mock OIDC login page with default redirect URI."""
    mock_render_template.return_value = 'mock_template_content_/auth/callback'

    with app.test_client() as client:
        response = client.get('/mock_oidc_login')

        assert response.status_code == 200
        mock_render_template.assert_called_once_with('test_mock_oidc_login.html', redirect_uri='/auth/callback')


@patch('flask.render_template')
def test_mock_oidc_login_custom_redirect(mock_render_template, app):
    """Test mock OIDC login page with custom redirect URI."""
    mock_render_template.return_value = 'mock_template_content_/custom/callback'

    with app.test_client() as client:
        response = client.get('/mock_oidc_login?redirect_uri=/custom/callback')

        assert response.status_code == 200
        mock_render_template.assert_called_once_with('test_mock_oidc_login.html', redirect_uri='/custom/callback')


def test_mock_oidc_callback_with_form_data(app):
    """Test mock OIDC callback handler with form data."""
    with app.test_client() as client:
        response = client.post('/mock_oidc_callback', data={
            'email': 'test@mock.com',
            'name': 'Mock Test User',
            'groups': 'admins,users',
            'redirect_uri': '/test/redirect'
        })

        assert response.status_code == 302  # Redirect response
        assert response.location == '/test/redirect'


def test_mock_oidc_callback_with_defaults(app):
    """Test mock OIDC callback handler with default values."""
    with app.test_client() as client:
        response = client.post('/mock_oidc_callback', data={})

        assert response.status_code == 302  # Redirect response
        assert response.location == '/'  # Default redirect


def test_mock_oidc_callback_sets_session(app):
    """Test mock OIDC callback sets session data correctly."""
    with app.test_client() as client:
        with client.session_transaction() as session:
            # Clear any existing session data
            session.clear()

        # Perform the callback
        response = client.post('/mock_oidc_callback', data={
            'email': 'session@test.com',
            'name': 'Session Test',
            'groups': 'testers'
        })

        assert response.status_code == 302

        # Check session was set correctly
        with client.session_transaction() as session:
            assert 'user' in session
            assert session['user']['email'] == 'session@test.com'
            assert session['user']['name'] == 'Session Test'
            assert session['user']['groups'] == ['testers']
            assert 'oidc_token' in session
            assert session['oidc_token']['access_token'] == 'mock-access-token'