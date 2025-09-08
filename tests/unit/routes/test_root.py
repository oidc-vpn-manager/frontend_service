"""
Unit tests for the root blueprint routes.
"""

import pytest
from flask import Flask, session
from unittest.mock import MagicMock

from app.routes.root import bp as root_blueprint
from app.routes.auth import bp as auth_blueprint # Needed for url_for

@pytest.fixture
def app():
    """Provides a test instance of the Flask app with necessary blueprints."""
    app = Flask(__name__)
    app.config['TESTING'] = True
    app.config['SECRET_KEY'] = 'test-secret'
    app.register_blueprint(root_blueprint)
    app.register_blueprint(auth_blueprint)
    return app

def test_index_route_unauthenticated(app, monkeypatch):
    """
    Tests that an unauthenticated user is redirected to the login page.
    """
    # Patch render_template to ensure it's not called
    mock_render_template = MagicMock()
    monkeypatch.setattr('app.routes.root.render_template', mock_render_template)

    client = app.test_client()
    response = client.get('/')

    # Assert we are redirected to the login page
    assert response.status_code == 302
    assert response.location == '/auth/login'
    
    # Assert the session contains the intended destination
    with client.session_transaction() as sess:
        assert sess['next_url'] == '/'

    # Assert that the page was not rendered
    mock_render_template.assert_not_called()

def test_index_route_authenticated(app, monkeypatch):
    """
    Tests that an authenticated user sees the index page.
    """
    mock_render_template = MagicMock(return_value="mocked output")
    monkeypatch.setattr('app.routes.root.render_template', mock_render_template)

    with app.test_client() as client:
        # Simulate a logged-in user by setting the session cookie
        with client.session_transaction() as sess:
            sess['user'] = {'sub': '12345', 'name': 'Test User'}
        
        response = client.get('/')

    assert response.status_code == 200
    assert response.data == b'mocked output'
    # Verify render_template was called with index.html and the expected context
    assert mock_render_template.call_count == 1
    call_args = mock_render_template.call_args
    assert call_args[0][0] == 'index.html'  # First positional argument
    assert 'form' in call_args[1]  # form should be in keyword arguments
    assert 'ovpn_options' in call_args[1]  # ovpn_options should be in keyword arguments

def test_index_route_post_successful(app, monkeypatch):
    """
    Tests successful profile generation via POST request.
    """
    # Configure app with required settings
    app.config.update({
        'WTF_CSRF_ENABLED': False,
        'OPENVPN_TLS_CRYPT_KEY': '-----BEGIN OpenVPN Static key V1-----\ntest-key-data\n-----END OpenVPN Static key V1-----',
        'ROOT_CA_CERTIFICATE': '-----BEGIN CERTIFICATE-----\ntest-root-ca\n-----END CERTIFICATE-----',
        'INTERMEDIATE_CA_CERTIFICATE': '-----BEGIN CERTIFICATE-----\ntest-intermediate-ca\n-----END CERTIFICATE-----',
        'TEMPLATE_COLLECTION': [
            {
                'priority': 1,
                'group_name': 'default',
                'file_name': 'default.ovpn',
                'content': 'client\nproto {{ protocol | default("udp") }}\n{{ device_cert_pem }}'
            }
        ],
        'OVPN_OPTIONS': {
            'tcp_option': {
                'display_name': 'Use TCP',
                'settings': {'protocol': 'tcp-client'}
            }
        }
    })
    
    # Mock dependencies
    mock_generate_key_csr = MagicMock()
    mock_private_key = MagicMock()
    mock_csr = MagicMock()
    mock_private_key.private_bytes.return_value = b'-----BEGIN PRIVATE KEY-----\ntest-private-key\n-----END PRIVATE KEY-----'
    mock_csr.subject.get_attributes_for_oid.return_value = [MagicMock(value='test@example.com')]
    mock_csr.public_bytes.return_value = b'-----BEGIN CERTIFICATE REQUEST-----\ntest-csr\n-----END CERTIFICATE REQUEST-----'
    mock_generate_key_csr.return_value = (mock_private_key, mock_csr)
    monkeypatch.setattr('app.routes.root.generate_key_and_csr', mock_generate_key_csr)
    
    mock_request_signed_cert = MagicMock(return_value='-----BEGIN CERTIFICATE-----\ntest-signed-cert\n-----END CERTIFICATE-----')
    monkeypatch.setattr('app.routes.root.request_signed_certificate', mock_request_signed_cert)
    
    mock_process_tls_key = MagicMock(return_value=('v1', 'processed-tls-key'))
    monkeypatch.setattr('app.routes.root.process_tls_crypt_key', mock_process_tls_key)
    
    mock_find_template = MagicMock(return_value=('default.ovpn', 'client\nproto {{ protocol }}\n{{ device_cert_pem }}'))
    monkeypatch.setattr('app.routes.root.find_best_template_match', mock_find_template)
    
    mock_render_config = MagicMock(return_value='# OpenVPN Configuration\nclient\nproto udp\n-----BEGIN CERTIFICATE-----\ntest-signed-cert\n-----END CERTIFICATE-----')
    monkeypatch.setattr('app.routes.root.render_config_template', mock_render_config)
    
    # Mock database operations
    mock_db = MagicMock()
    monkeypatch.setattr('app.routes.root.db', mock_db)
    monkeypatch.setattr('app.routes.root.DownloadToken', MagicMock)
    
    with app.test_client() as client:
        # Set up authenticated session
        with client.session_transaction() as sess:
            sess['user'] = {
                'sub': 'test-user-123',
                'name': 'Test User',
                'email': 'test@example.com',
                'groups': 'default,users'
            }
        
        # Submit form 
        response = client.post('/', data={
            'submit': 'Generate Profile',
            'options': ['tcp_option']
        })

    assert response.status_code == 200
    assert response.headers['Content-Type'] == 'application/x-openvpn-profile'
    assert b'# OpenVPN Configuration' in response.data
    
    # Verify all mocked functions were called
    mock_generate_key_csr.assert_called_once_with(common_name='test@example.com')
    mock_request_signed_cert.assert_called_once()
    mock_process_tls_key.assert_called_once()
    mock_find_template.assert_called_once()
    mock_render_config.assert_called_once()

def test_index_route_post_signing_error(app, monkeypatch):
    """
    Tests error handling when signing service fails.
    """
    # Configure app with minimal required settings
    app.config['WTF_CSRF_ENABLED'] = False
    
    # Mock dependencies - make signing service fail
    mock_generate_key_csr = MagicMock()
    mock_private_key = MagicMock()
    mock_csr = MagicMock()
    mock_csr.subject.get_attributes_for_oid.return_value = [MagicMock(value='test@example.com')]
    mock_csr.public_bytes.return_value = b'-----BEGIN CERTIFICATE REQUEST-----\ntest-csr\n-----END CERTIFICATE REQUEST-----'
    mock_generate_key_csr.return_value = (mock_private_key, mock_csr)
    monkeypatch.setattr('app.routes.root.generate_key_and_csr', mock_generate_key_csr)
    
    from app.utils.signing_client import SigningServiceError
    mock_request_signed_cert = MagicMock(side_effect=SigningServiceError('Signing service unavailable'))
    monkeypatch.setattr('app.routes.root.request_signed_certificate', mock_request_signed_cert)
    
    mock_render_template = MagicMock(return_value='error page')
    monkeypatch.setattr('app.routes.root.render_template', mock_render_template)
    
    with app.test_client() as client:
        # Set up authenticated session
        with client.session_transaction() as sess:
            sess['user'] = {
                'sub': 'test-user-123',
                'name': 'Test User',
                'email': 'test@example.com'
            }
        
        response = client.post('/', data={
            'submit': 'Generate Profile'
        })

    assert response.status_code == 500
    # Verify error template was rendered
    mock_render_template.assert_called()
    call_args = mock_render_template.call_args
    assert call_args[0][0] == 'index.html'

def test_index_route_post_forwarded_ip(app, monkeypatch):
    """
    Tests that X-Forwarded-For header is handled correctly.
    """
    app.config['WTF_CSRF_ENABLED'] = False
    
    # Mock dependencies for successful flow
    mock_generate_key_csr = MagicMock()
    mock_private_key = MagicMock()
    mock_csr = MagicMock()
    mock_private_key.private_bytes.return_value = b'-----BEGIN PRIVATE KEY-----\ntest-key\n-----END PRIVATE KEY-----'
    mock_csr.subject.get_attributes_for_oid.return_value = [MagicMock(value='test@example.com')]
    mock_csr.public_bytes.return_value = b'-----BEGIN CERTIFICATE REQUEST-----\ntest-csr\n-----END CERTIFICATE REQUEST-----'
    mock_generate_key_csr.return_value = (mock_private_key, mock_csr)
    monkeypatch.setattr('app.routes.root.generate_key_and_csr', mock_generate_key_csr)
    
    mock_request_signed_cert = MagicMock(return_value='-----BEGIN CERTIFICATE-----\ntest-cert\n-----END CERTIFICATE-----')
    monkeypatch.setattr('app.routes.root.request_signed_certificate', mock_request_signed_cert)
    
    # Mock other dependencies
    app.config.update({
        'OPENVPN_TLS_CRYPT_KEY': '-----BEGIN OpenVPN Static key V1-----\ntest-key\n-----END OpenVPN Static key V1-----',
        'ROOT_CA_CERTIFICATE': 'test-root-ca',
        'INTERMEDIATE_CA_CERTIFICATE': 'test-intermediate-ca',
        'TEMPLATE_COLLECTION': [{'priority': 1, 'group_name': 'default', 'file_name': 'default.ovpn', 'content': 'client\n{{ device_cert_pem }}'}]
    })
    
    mock_process_tls_key = MagicMock(return_value=('v1', 'processed-tls-key'))
    monkeypatch.setattr('app.routes.root.process_tls_crypt_key', mock_process_tls_key)
    
    mock_find_template = MagicMock(return_value=('default.ovpn', 'client\n{{ device_cert_pem }}'))
    monkeypatch.setattr('app.routes.root.find_best_template_match', mock_find_template)
    
    mock_render_config = MagicMock(return_value='# Config\nclient\ntest-cert')
    monkeypatch.setattr('app.routes.root.render_config_template', mock_render_config)
    
    mock_db = MagicMock()
    monkeypatch.setattr('app.routes.root.db', mock_db)
    monkeypatch.setattr('app.routes.root.DownloadToken', MagicMock)
    
    with app.test_client() as client:
        with client.session_transaction() as sess:
            sess['user'] = {'sub': 'test-user-123', 'email': 'test@example.com', 'groups': []}
        
        # Send request with X-Forwarded-For header
        response = client.post('/', 
                             data={'submit': 'Generate Profile'},
                             headers={'X-Forwarded-For': '192.168.1.100, 10.0.0.1'})

    assert response.status_code == 200
    # Verify that the signing service was called with the forwarded IP
    mock_request_signed_cert.assert_called_once()
    call_args = mock_request_signed_cert.call_args
    assert 'client_ip' in call_args[1]
    assert call_args[1]['client_ip'] == '192.168.1.100'  # First IP from forwarded chain

def test_index_route_post_user_groups_string_parsing(app, monkeypatch):
    """
    Tests that user groups are correctly parsed from comma-separated string.
    """
    app.config['WTF_CSRF_ENABLED'] = False
    
    # Set up minimal mocking for successful flow
    mock_generate_key_csr = MagicMock()
    mock_private_key = MagicMock()
    mock_csr = MagicMock()
    mock_private_key.private_bytes.return_value = b'-----BEGIN PRIVATE KEY-----\ntest-key\n-----END PRIVATE KEY-----'
    mock_csr.subject.get_attributes_for_oid.return_value = [MagicMock(value='test@example.com')]
    mock_csr.public_bytes.return_value = b'-----BEGIN CERTIFICATE REQUEST-----\ntest-csr\n-----END CERTIFICATE REQUEST-----'
    mock_generate_key_csr.return_value = (mock_private_key, mock_csr)
    monkeypatch.setattr('app.routes.root.generate_key_and_csr', mock_generate_key_csr)
    
    mock_request_signed_cert = MagicMock(return_value='test-cert')
    monkeypatch.setattr('app.routes.root.request_signed_certificate', mock_request_signed_cert)
    
    app.config.update({
        'OPENVPN_TLS_CRYPT_KEY': 'test-key',
        'ROOT_CA_CERTIFICATE': 'test-root',
        'INTERMEDIATE_CA_CERTIFICATE': 'test-intermediate',
        'TEMPLATE_COLLECTION': [{'priority': 1, 'group_name': 'admin', 'file_name': 'admin.ovpn', 'content': 'admin-config'}]
    })
    
    mock_process_tls_key = MagicMock(return_value=('v1', 'processed-key'))
    monkeypatch.setattr('app.routes.root.process_tls_crypt_key', mock_process_tls_key)
    
    mock_find_template = MagicMock(return_value=('admin.ovpn', 'admin-config'))
    monkeypatch.setattr('app.routes.root.find_best_template_match', mock_find_template)
    
    mock_render_config = MagicMock(return_value='# Admin Config')
    monkeypatch.setattr('app.routes.root.render_config_template', mock_render_config)
    
    mock_db = MagicMock()
    monkeypatch.setattr('app.routes.root.db', mock_db)
    monkeypatch.setattr('app.routes.root.DownloadToken', MagicMock)
    
    with app.test_client() as client:
        with client.session_transaction() as sess:
            sess['user'] = {'sub': 'test-user-123', 'email': 'test@example.com', 'groups': 'admin, users, developers'}
        
        response = client.post('/', data={'submit': 'Generate Profile'})

    assert response.status_code == 200
    # Verify that find_best_template_match was called with parsed groups
    mock_find_template.assert_called_once()
    call_args = mock_find_template.call_args
    user_groups = call_args[0][1]  # Second argument should be parsed user groups
    assert user_groups == ['admin', 'users', 'developers']

def test_index_route_post_invalid_option(app, monkeypatch):
    """
    Tests profile generation with an invalid option to test the branch coverage.
    """
    app.config.update({
        'WTF_CSRF_ENABLED': False,
        'OPENVPN_TLS_CRYPT_KEY': 'test-key',
        'ROOT_CA_CERTIFICATE': 'root-ca',
        'INTERMEDIATE_CA_CERTIFICATE': 'intermediate-ca',
        'TEMPLATE_COLLECTION': [{'priority': 1, 'group_name': 'default', 'file_name': 'default.ovpn', 'content': 'test-config'}],
        'OVPN_OPTIONS': {
            'valid_option': {
                'display_name': 'Valid Option',
                'settings': {'test_setting': 'test_value'}
            }
        }
    })
    
    # Mock all dependencies
    mock_generate_key_csr = MagicMock()
    mock_private_key = MagicMock()
    mock_csr = MagicMock()
    mock_private_key.private_bytes.return_value = b'test-key'
    mock_csr.subject.get_attributes_for_oid.return_value = [MagicMock(value='test@example.com')]
    mock_csr.public_bytes.return_value = b'test-csr'
    mock_generate_key_csr.return_value = (mock_private_key, mock_csr)
    monkeypatch.setattr('app.routes.root.generate_key_and_csr', mock_generate_key_csr)
    
    mock_request_signed_cert = MagicMock(return_value='test-cert')
    monkeypatch.setattr('app.routes.root.request_signed_certificate', mock_request_signed_cert)
    
    mock_process_tls_key = MagicMock(return_value=('v1', 'test-tls-key'))
    monkeypatch.setattr('app.routes.root.process_tls_crypt_key', mock_process_tls_key)
    
    mock_find_template = MagicMock(return_value=('default.ovpn', 'test-config'))
    monkeypatch.setattr('app.routes.root.find_best_template_match', mock_find_template)
    
    mock_render_config = MagicMock(return_value='# Final Config')
    monkeypatch.setattr('app.routes.root.render_config_template', mock_render_config)
    
    mock_db = MagicMock()
    monkeypatch.setattr('app.routes.root.db', mock_db)
    monkeypatch.setattr('app.routes.root.DownloadToken', MagicMock)
    
    with app.test_client() as client:
        with client.session_transaction() as sess:
            sess['user'] = {'sub': 'test-user-123', 'email': 'test@example.com', 'groups': []}
        
        # Submit form with both valid and invalid options
        response = client.post('/', data={
            'submit': 'Generate Profile',
            'options': ['valid_option', 'invalid_option']  # Mix of valid and invalid
        })

    assert response.status_code == 200
    # Verify the context was updated with valid option settings
    mock_render_config.assert_called_once()
    call_args = mock_render_config.call_args
    context = call_args[1]  # Keyword arguments 
    # Should contain the setting from the valid option
    assert 'test_setting' in context
    assert context['test_setting'] == 'test_value'