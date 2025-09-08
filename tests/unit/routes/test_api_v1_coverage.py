"""
Unit tests to achieve 100% coverage for API v1 routes.
Tests missing coverage paths including X-Forwarded-For header processing
and file exception handling.
"""

import io
import json
import os
import pytest
from unittest.mock import patch, MagicMock, mock_open
from flask import Flask
from app import create_app
from app.extensions import db
from app.models.presharedkey import PreSharedKey
from app.utils.signing_client import SigningServiceError


class TestAPIv1Coverage:
    """Unit tests for missing coverage paths in API v1 routes."""

    @pytest.fixture
    def app(self):
        """Create a test Flask app with database."""
        import os
        # Set required environment variables for testing
        os.environ['FLASK_SECRET_KEY'] = 'test-secret-key-for-testing-only'
        os.environ['FERNET_ENCRYPTION_KEY'] = 'test-encryption-key-for-testing-only-32-chars-long'
        os.environ['TESTING'] = 'True'
        
        app = create_app('testing')
        app.config.update({
            'TESTING': True,
            'SQLALCHEMY_DATABASE_URI': 'sqlite:///:memory:',
            'WTF_CSRF_ENABLED': False,
            'SECRET_KEY': 'test-secret-key-for-testing-only',
            'ENCRYPTION_KEY': 'test-encryption-key-for-testing-only-32-chars',
            'ROOT_CA_CERTIFICATE': 'test-root-ca',
            'INTERMEDIATE_CA_CERTIFICATE': 'test-intermediate-ca',
            'OPENVPN_TLS_CRYPT_KEY': '-----BEGIN OpenVPN Static key V1-----\ntest-key\n-----END OpenVPN Static key V1-----',
        })
        
        with app.app_context():
            db.create_all()
            # Create test PSK for server endpoint
            test_server_key = 'a47ac10b-58cc-4372-a567-0e02b2c3d480'  # UUID for server testing
            test_server_psk = PreSharedKey(
                description='test-server',
                key=test_server_key,
                is_enabled=True
            )
            db.session.add(test_server_psk)
            db.session.commit()
            
            yield app

    @pytest.fixture
    def client(self, app):
        """Create a test client."""
        return app.test_client()


    def test_server_bundle_x_forwarded_for_processing(self, client):
        """Test X-Forwarded-For header processing in server_bundle - lines 96-98."""
        with patch('app.routes.api.v1.generate_key_and_csr') as mock_gen_key, \
             patch('app.routes.api.v1.request_signed_certificate') as mock_sign_cert, \
             patch('os.path.exists') as mock_exists:
            
            # Setup mocks
            mock_key = MagicMock()
            mock_key.private_bytes.return_value = b'server-private-key'
            mock_csr = MagicMock()
            mock_csr.public_bytes.return_value = b'server-csr'
            mock_gen_key.return_value = (mock_key, mock_csr)
            mock_sign_cert.return_value = 'server-certificate'
            mock_exists.return_value = False  # No server templates
            
            # Test with X-Forwarded-For header containing multiple IPs
            response = client.post('/api/v1/server/bundle',
                                 headers={
                                     'Authorization': 'Bearer a47ac10b-58cc-4372-a567-0e02b2c3d480',
                                     'X-Forwarded-For': '203.0.113.195, 198.51.100.178'
                                 },
                                 json={'description': 'test-server'})
            
            assert response.status_code == 200
            
            # Verify that the first IP from X-Forwarded-For was used
            mock_sign_cert.assert_called_once_with(
                'server-csr', 
                certificate_type='server', 
                client_ip='203.0.113.195'  # First IP should be extracted and stripped
            )

    def test_server_bundle_file_read_exception(self, client):
        """Test exception handling when reading server config files - lines 164-165."""
        with patch('app.routes.api.v1.generate_key_and_csr') as mock_gen_key, \
             patch('app.routes.api.v1.request_signed_certificate') as mock_sign_cert, \
             patch('os.path.exists') as mock_exists, \
             patch('os.listdir') as mock_listdir, \
             patch('builtins.open') as mock_file_open:
            
            # Setup mocks for certificate generation
            mock_key = MagicMock()
            mock_key.private_bytes.return_value = b'server-private-key'
            mock_csr = MagicMock()
            mock_csr.public_bytes.return_value = b'server-csr'
            mock_gen_key.return_value = (mock_key, mock_csr)
            mock_sign_cert.return_value = 'server-certificate'
            
            # Setup mocks for file system - directory exists and contains a .ovpn file that matches Default template set
            mock_exists.return_value = True
            mock_listdir.return_value = ['Default.100.ovpn']
            
            # Make file opening raise an exception (e.g., permission denied)
            mock_file_open.side_effect = IOError("Permission denied")
            
            # Configure app with SERVER_TEMPLATES_DIR
            client.application.config['SERVER_TEMPLATES_DIR'] = '/test/server/templates'
            
            # Make request
            response = client.post('/api/v1/server/bundle',
                                 headers={'Authorization': 'Bearer a47ac10b-58cc-4372-a567-0e02b2c3d480'},
                                 json={'description': 'test-server'})
            
            # Should still return 200 even if file reading fails
            assert response.status_code == 200
            
            # Verify that file opening was attempted for the matching template file
            mock_file_open.assert_called_once_with('/test/server/templates/Default.100.ovpn', 'r')


