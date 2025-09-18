"""
Unit tests for custom decorators.
"""

import pytest
import json
from flask import Flask, jsonify, Blueprint
from unittest.mock import MagicMock

from app.utils.decorators import psk_required, admin_required
from app.models.presharedkey import PreSharedKey

# --- Test Setup ---

@pytest.fixture
def app():
    """Provides a basic Flask app for testing the decorator."""
    app = Flask(__name__)
    app.config['TESTING'] = True

    # Create a dummy route protected by the decorator
    @app.route('/protected', methods=['POST'])
    @psk_required
    def protected_route(psk_object):
        return jsonify(status="success", hostname=psk_object.description)

    return app

@pytest.fixture
def mock_psk_model(monkeypatch):
    """Mocks the PreSharedKey model to simulate database queries."""
    mock_model = MagicMock()
    monkeypatch.setattr('app.utils.decorators.PreSharedKey', mock_model)
    return mock_model

# --- Test Cases ---

def test_psk_required_success(app, mock_psk_model):
    """
    Tests that a valid PSK grants access.
    """
    # Arrange: Configure the mock model to return a valid key object
    valid_key = "a-valid-key-string"
    valid_hostname = "server1.vpn.com"
    
    mock_psk_entry = MagicMock()
    mock_psk_entry.key = valid_key
    mock_psk_entry.description = valid_hostname
    mock_psk_entry.is_valid.return_value = True
    mock_psk_entry.verify_key.return_value = True  # Key verification succeeds
    
    # Mock the query to return enabled PSKs (new decorator searches all enabled PSKs)
    mock_psk_model.query.filter_by.return_value.all.return_value = [mock_psk_entry]
    
    client = app.test_client()

    # Act - No JSON body required anymore, just Authorization header
    response = client.post(
        '/protected',
        headers={'Authorization': f'Bearer {valid_key}'}
    )

    # Assert
    assert response.status_code == 200
    assert response.json['status'] == 'success'
    assert response.json['hostname'] == valid_hostname

def test_psk_required_invalid_key(app, mock_psk_model):
    """
    Tests that an invalid key is rejected.
    """
    # Mock a valid PSK in database that doesn't match the sent key
    mock_psk_entry = MagicMock()
    mock_psk_entry.key = "the-real-key" # The key in the DB
    mock_psk_entry.is_valid.return_value = True
    mock_psk_entry.verify_key.return_value = False  # Key verification fails
    mock_psk_model.query.filter_by.return_value.all.return_value = [mock_psk_entry]
    
    client = app.test_client()
    response = client.post(
        '/protected',
        headers={'Authorization': 'Bearer a-wrong-key'} # The key sent by the client
    )
    
    assert response.status_code == 401
    data = json.loads(response.data)
    assert 'error' in data
    assert "Invalid" in data['error'] and "expired" in data['error']

def test_psk_required_disabled_key(app, mock_psk_model):
    """
    Tests that a disabled key is rejected.
    """
    valid_key = "a-valid-key-string"
    valid_hostname = "server1.vpn.com"

    mock_psk_entry = MagicMock()
    mock_psk_entry.key = valid_key
    mock_psk_entry.is_valid.return_value = False # Key is not valid (e.g., disabled or expired)
    mock_psk_entry.verify_key.return_value = True  # Key would verify but is disabled
    mock_psk_model.query.filter_by.return_value.all.return_value = [mock_psk_entry]

    client = app.test_client()
    response = client.post(
        '/protected',
        headers={'Authorization': f'Bearer {valid_key}'}
    )

    assert response.status_code == 401
    data = json.loads(response.data)
    assert 'error' in data
    assert "Invalid" in data['error'] and "expired" in data['error']

def test_psk_required_missing_header(app, mock_psk_model):
    """
    Tests that a request with a missing Authorization header is rejected.
    """
    client = app.test_client()
    response = client.post('/protected')
    
    assert response.status_code == 401
    data = json.loads(response.data)
    assert 'error' in data
    assert "missing or invalid" in data['error']

def test_psk_required_no_matching_key(app, mock_psk_model):
    """
    Tests that a request with a key that doesn't match any PSK is rejected.
    """
    # Mock that no PSKs match the provided key
    mock_psk_model.query.filter_by.return_value.all.return_value = []
    
    client = app.test_client()
    response = client.post(
        '/protected',
        headers={'Authorization': 'Bearer non-existent-key'}
    )
    
    assert response.status_code == 401
    data = json.loads(response.data)
    assert 'error' in data
    assert "Invalid" in data['error'] and "expired" in data['error']

class TestAdminRequiredDecorator:

    @pytest.fixture
    def app(self):
        """Provides a test app with a protected admin route."""
        app = Flask(__name__)
        app.config.update({
            "TESTING": True, "SECRET_KEY": "test",
            "OIDC_ADMIN_GROUP": "vpn-admins"
        })
        
        # We need an auth blueprint for the login redirect
        auth_bp = Blueprint('auth', __name__)
        @auth_bp.route('/login')
        def login():
            return "login page"
        app.register_blueprint(auth_bp)

        # The protected admin route
        @app.route('/admin-only')
        @admin_required
        def admin_only_route():
            return jsonify(status="success")
            
        return app

    def test_admin_access_success(self, app):
        """Tests that a user in the admin group can access the route."""
        with app.test_client() as client:
            with client.session_transaction() as sess:
                sess['user'] = {
                    'sub': 'admin@example.com',
                    'groups': ['vpn-admins', 'users'],
                    'name': 'Admin User',
                    'email': 'admin@example.com'
                }
            
            response = client.get('/admin-only')
        
        assert response.status_code == 200
        assert response.json['status'] == 'success'

    def test_non_admin_is_forbidden(self, app):
        """Tests that a user not in the admin group gets a 403 error."""
        with app.test_client() as client:
            with client.session_transaction() as sess:
                sess['user'] = {
                    'sub': 'user@example.com',
                    'groups': ['users'],
                    'name': 'Regular User',
                    'email': 'user@example.com'
                }
            
            response = client.get('/admin-only')
        
        assert response.status_code == 403

    def test_logged_out_user_is_redirected(self, app):
        """Tests that a user who is not logged in is redirected to login."""
        with app.test_client() as client:
            response = client.get('/admin-only')
        
        assert response.status_code == 302
        assert response.location == '/login'
