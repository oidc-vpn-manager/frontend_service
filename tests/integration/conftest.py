import pytest
import socket
from unittest.mock import MagicMock
from flask import redirect
from pytest_flask.live_server import LiveServer

import os, sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app
from app.app import cleanup_temp_instance_dirs
from app.extensions import db

def find_free_port():
    """Finds and returns an unused TCP port on localhost."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]

@pytest.fixture(scope='function')
def app(httpserver, monkeypatch):
    """
    Creates the frontend app, configured to use the mock httpserver.
    Scope must be 'function' to allow injection of the function-scoped httpserver.
    """
    # Set environment variables to avoid file loading issues
    monkeypatch.setenv('ROOT_CA_CERTIFICATE_FILE', '')
    monkeypatch.setenv('INTERMEDIATE_CA_CERTIFICATE_FILE', '')
    monkeypatch.setenv('OPENVPN_TLS_CRYPT_KEY_FILE', '')
    monkeypatch.setenv('SIGNING_SERVICE_API_SECRET_FILE', '')
    monkeypatch.setenv('DATABASE_URL_FILE', '')
    monkeypatch.setenv('DATABASE_URL', 'sqlite:///:memory:')
    monkeypatch.setenv('DEV_DATABASE_URI', 'sqlite:///:memory:')
    
    # Required security keys for configuration tests
    monkeypatch.setenv('FLASK_SECRET_KEY', 'test-secret-key-for-functional-tests-only')
    monkeypatch.setenv('FERNET_ENCRYPTION_KEY', 'YenxIAHqvrO7OHbNXvzAxEhthHCaitvnV9CALkQvvCc=')
    
    # Set TESTING in environment so test routes get registered during app creation
    monkeypatch.setenv('TESTING', 'True')
    # Enable test auth routes for functional testing
    monkeypatch.setenv('ENABLE_TEST_AUTH_ROUTES', 'true')
    # Set FLASK_ENV for test auth route registration
    monkeypatch.setenv('FLASK_ENV', 'development')
    
    app = create_app('development')
    
    # Configure test server templates directory
    import os as path_os
    test_templates_dir = path_os.path.join(path_os.path.dirname(path_os.path.dirname(__file__)), 'test_data', 'server_templates')
    
    app.config.update({
        "TESTING": True, "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
        "WTF_CSRF_ENABLED": False,
        "ENVIRONMENT": "development",
        "FLASK_CONFIG": "development",
        "ROOT_CA_CERTIFICATE": "test-root-ca-cert",
        "INTERMEDIATE_CA_CERTIFICATE": "test-intermediate-ca-cert",
        "OPENVPN_TLS_CRYPT_KEY": "-----BEGIN OpenVPN Static key V1-----\ne4b9c6f8a1d2e3f4b5c8d1e6f7a0c3d6\nf1e4d7a0c3f6b9e2c5f8a1d4e7b0c3f6\na3f6b9c2e5f8a1d4e7b0c3f6b9c2e5f8\nd6f9c2e5a8b1d4e7b0c3f6b9c2e5f8a1\n-----END OpenVPN Static key V1-----",
        "OVPN_OPTIONS": {
            'use_tcp': {
                'display_name': 'Use TCP (Port 443)',
                'description': 'Forces the connection over TCP port 443.',
                'settings': { 'protocol': 'tcp-client', 'port': 443 }
            }
        },
        "TEMPLATE_COLLECTION": [{
            "priority": 999, "group_name": "default", "file_name": "default.ovpn",
            "content": "proto {{ protocol }}\nport {{ port }}\n{{ device_cert_pem }}"
        }],
        # Configure the app to use the mock server's URL
        "SIGNING_SERVICE_URL": httpserver.url_for("/"),
        "SIGNING_SERVICE_API_SECRET": "test-signing-secret",
        # Configure server templates for functional tests
        "SERVER_TEMPLATES_DIR": path_os.path.abspath(test_templates_dir),
        "SERVER_TEMPLATES_DIR": path_os.path.abspath(test_templates_dir)
    })
    
    mock_oauth_client = MagicMock()
    mock_oauth_client.oidc.authorize_redirect.side_effect = lambda redirect_uri: redirect(f"/mock_oidc_login?redirect_uri={redirect_uri}")
    with app.app_context():
        from app.extensions import oauth
        oauth._clients['oidc'] = mock_oauth_client.oidc
        db.create_all()
    yield app
    with app.app_context():
        db.session.remove()
        db.drop_all()
        try:
            db.engine.dispose()
        except AttributeError:
            # Fallback for older Flask-SQLAlchemy versions
            db.get_engine().dispose()
    # Clean up temporary instance directories
    cleanup_temp_instance_dirs()

@pytest.fixture(scope='function')  
def live_server(app):
    """Starts a live server for the application on a free port."""
    port = find_free_port()
    server = LiveServer(app=app, host='127.0.0.1', port=port, wait=5)
    server.start()
    yield server
    server.stop()

@pytest.fixture(scope='function')
def production_app(httpserver, monkeypatch, tmp_path):
    """Creates a production-mode frontend app with proper isolation for testing production behavior."""
    import uuid
    import os
    
    # Use unique temporary database file to ensure complete isolation
    unique_db_file = tmp_path / f"production_test_{uuid.uuid4().hex}.db"
    unique_db_uri = f'sqlite:///{unique_db_file}'
    
    # Aggressive environment reset - clear everything database related first
    database_env_vars = [
        'ROOT_CA_CERTIFICATE_FILE', 'INTERMEDIATE_CA_CERTIFICATE_FILE', 'OPENVPN_TLS_CRYPT_KEY_FILE',
        'SIGNING_SERVICE_API_SECRET_FILE', 'DATABASE_URL_FILE', 'DATABASE_URL', 'DEV_DATABASE_URI',
        'DATABASE_TYPE', 'DATABASE_HOSTNAME', 'DATABASE_USERNAME', 'DATABASE_PASSWORD', 
        'DATABASE_NAME', 'DATABASE_PORT', 'FLASK_ENV', 'FLASK_CONFIG', 'ENVIRONMENT'
    ]
    
    # First unset all potentially problematic variables
    for var in database_env_vars:
        monkeypatch.delenv(var, raising=False)
    
    # Then set them to our desired values
    monkeypatch.setenv('DATABASE_URL', unique_db_uri)
    monkeypatch.setenv('DEV_DATABASE_URI', unique_db_uri)
    # Required security keys for configuration tests
    monkeypatch.setenv('FLASK_SECRET_KEY', 'test-secret-key-for-production-tests-only')
    monkeypatch.setenv('FERNET_ENCRYPTION_KEY', 'YenxIAHqvrO7OHbNXvzAxEhthHCaitvnV9CALkQvvCc=')
    for var in database_env_vars[:-3]:  # Exclude DATABASE_URL, DEV_DATABASE_URI which we set above
        if var not in ['DATABASE_URL', 'DEV_DATABASE_URI']:
            monkeypatch.setenv(var, '')
    
    try:
        app = create_app('production')
        
        app.config.update({
            "TESTING": True, 
            "SQLALCHEMY_DATABASE_URI": unique_db_uri,
            "WTF_CSRF_ENABLED": False,
            "FLASK_ENV": "production",
            "FLASK_CONFIG": "production",
            "ROOT_CA_CERTIFICATE": "test-root-ca-cert",
            "INTERMEDIATE_CA_CERTIFICATE": "test-intermediate-ca-cert",
        "OPENVPN_TLS_CRYPT_KEY": "-----BEGIN OpenVPN Static key V1-----\ne4b9c6f8a1d2e3f4b5c8d1e6f7a0c3d6\nf1e4d7a0c3f6b9e2c5f8a1d4e7b0c3f6\na3f6b9c2e5f8a1d4e7b0c3f6b9c2e5f8\nd6f9c2e5a8b1d4e7b0c3f6b9c2e5f8a1\n-----END OpenVPN Static key V1-----",
        "OVPN_OPTIONS": {
            'use_tcp': {
                'display_name': 'Use TCP (Port 443)',
                'description': 'Forces the connection over TCP port 443.',
                'settings': { 'protocol': 'tcp-client', 'port': 443 }
            }
        },
        "TEMPLATE_COLLECTION": [{
            "priority": 999, "group_name": "default", "file_name": "default.ovpn",
            "content": "proto {{ protocol }}\nport {{ port }}\n{{ device_cert_pem }}"
        }],
        "SIGNING_SERVICE_URL": httpserver.url_for("/"),
        "SIGNING_SERVICE_API_SECRET": "test-signing-secret"
    })
    
        mock_oauth_client = MagicMock()
        mock_oauth_client.oidc.authorize_redirect.side_effect = lambda redirect_uri: redirect(f"/mock_oidc_login?redirect_uri={redirect_uri}")
        with app.app_context():
            from app.extensions import oauth
            oauth._clients['oidc'] = mock_oauth_client.oidc
            db.create_all()
        
        yield app
        
        # Cleanup - ensure complete isolation
        with app.app_context():
            try:
                db.session.remove()
                db.drop_all()
                try:
                    db.engine.dispose()
                except AttributeError:
                    # Fallback for older Flask-SQLAlchemy versions
                    db.get_engine().dispose()
            except:
                pass
            
    finally:
        # File cleanup 
        try:
            unique_db_file.unlink(missing_ok=True)
        except:
            pass
        # Clean up temporary instance directories
        cleanup_temp_instance_dirs()

@pytest.fixture(scope='function')
def production_live_server(production_app):
    """Starts a live server for the production app on a free port."""
    port = find_free_port()
    server = LiveServer(app=production_app, host='127.0.0.1', port=port, wait=5)
    server.start()
    yield server
    server.stop()

@pytest.fixture(scope='function')
def browser_context_args(browser_context_args):
    """Configure browser context for Playwright."""
    return {
        **browser_context_args,
        "accept_downloads": True,
    }

@pytest.fixture(scope='function')
def page(page, tmp_path):
    """Provides a Playwright page instance with download directory."""
    download_dir = tmp_path / "downloads" 
    download_dir.mkdir(exist_ok=True)
    page.download_dir = download_dir
    yield page