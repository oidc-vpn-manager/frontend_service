"""
Test the test authentication routes used for development/testing.
"""

import pytest
import json
from flask import Flask
from app.routes.test_auth import bp as test_auth_blueprint


@pytest.fixture
def app():
    """Create test Flask app."""
    app = Flask(__name__)
    app.config.update({
        "TESTING": True,
        "SECRET_KEY": "test-secret"
    })
    
    app.register_blueprint(test_auth_blueprint)
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