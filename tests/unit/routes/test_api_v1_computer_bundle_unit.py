"""
Unit tests for the computer bundle API endpoint.
"""

import io
import json
import os
import tarfile
import tempfile
import uuid
import pytest
from unittest.mock import patch, MagicMock, mock_open
from flask import Flask
from app import create_app
from app.extensions import db
from app.models.presharedkey import PreSharedKey
from app.utils.signing_client import SigningServiceError


class TestComputerBundleUnit:
    """Unit tests for computer bundle functionality."""

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
            # Create a test computer PSK with a fixed UUID key for consistent testing
            test_key = 'c47ac10b-58cc-4372-a567-0e02b2c3d479'  # Fixed UUID for testing
            test_psk = PreSharedKey(
                description='test-computer',
                key=test_key,
                psk_type='computer',
                is_enabled=True
            )
            db.session.add(test_psk)
            db.session.commit()

            yield app

    @pytest.fixture
    def client(self, app):
        """Create a test client."""
        return app.test_client()

    def test_computer_bundle_successful_generation(self, client):
        """Test successful computer bundle generation."""
        with patch('app.routes.api.v1.generate_key_and_csr') as mock_gen_key, \
             patch('app.routes.api.v1.request_signed_certificate') as mock_sign_cert, \
             patch('app.routes.api.v1.find_best_template_match') as mock_find_template, \
             patch('app.routes.api.v1.render_config_template') as mock_render:

            # Setup mocks for certificate generation
            mock_key = MagicMock()
            mock_key.private_bytes.return_value = b'computer-private-key'
            mock_csr = MagicMock()
            mock_csr.public_bytes.return_value = b'computer-csr'
            mock_gen_key.return_value = (mock_key, mock_csr)
            mock_sign_cert.return_value = 'computer-certificate'

            # Setup template mocks
            mock_find_template.return_value = ('Default.100.ovpn', 'template content')
            mock_render.return_value = 'rendered OVPN configuration content'

            # Make the POST request
            response = client.post('/api/v1/computer/bundle',
                                   headers={'Authorization': 'Bearer c47ac10b-58cc-4372-a567-0e02b2c3d479'},
                                   json={'description': 'test-computer'})

            # Assertions
            assert response.status_code == 200
            assert response.content_type == 'application/x-openvpn-profile'
            assert 'computer-test-computer.ovpn' in response.headers['Content-Disposition']
            assert response.get_data(as_text=True) == 'rendered OVPN configuration content'

            # Verify certificate type was set correctly
            mock_sign_cert.assert_called_once_with('computer-csr', certificate_type='client', client_ip='127.0.0.1')

            # Verify template functions were called
            mock_find_template.assert_called_once()
            mock_render.assert_called_once()

    def test_computer_bundle_requires_computer_psk(self, client):
        """Test that computer bundle endpoint requires computer PSK type."""
        # Create a server PSK
        with client.application.app_context():
            server_psk = PreSharedKey(
                description='test-server',
                key='s47ac10b-58cc-4372-a567-0e02b2c3d479',
                psk_type='server',
                is_enabled=True
            )
            db.session.add(server_psk)
            db.session.commit()

        # Try to use server PSK with computer endpoint
        response = client.post('/api/v1/computer/bundle',
                               headers={'Authorization': 'Bearer s47ac10b-58cc-4372-a567-0e02b2c3d479'},
                               json={'description': 'test-computer'})

        assert response.status_code == 403
        assert 'computer PSK' in response.get_json()['error']

    def test_computer_bundle_psk_usage_recorded(self, client):
        """Test that PSK usage is recorded for computer bundle."""
        with patch('app.routes.api.v1.generate_key_and_csr') as mock_gen_key, \
             patch('app.routes.api.v1.request_signed_certificate') as mock_sign_cert, \
             patch('app.routes.api.v1.find_best_template_match') as mock_find_template, \
             patch('app.routes.api.v1.render_config_template') as mock_render:

            # Setup mocks
            mock_key = MagicMock()
            mock_key.private_bytes.return_value = b'computer-private-key'
            mock_csr = MagicMock()
            mock_csr.public_bytes.return_value = b'computer-csr'
            mock_gen_key.return_value = (mock_key, mock_csr)
            mock_sign_cert.return_value = 'computer-certificate'

            # Setup template mocks
            mock_find_template.return_value = ('Default.100.ovpn', 'template content')
            mock_render.return_value = 'rendered OVPN configuration content'

            # Get initial usage count
            with client.application.app_context():
                psk = PreSharedKey.query.filter_by(psk_type='computer').first()
                initial_usage = psk.use_count or 0

            # Make request
            response = client.post('/api/v1/computer/bundle',
                                   headers={'Authorization': 'Bearer c47ac10b-58cc-4372-a567-0e02b2c3d479'})

            assert response.status_code == 200

            # Check usage was incremented
            with client.application.app_context():
                psk = PreSharedKey.query.filter_by(psk_type='computer').first()
                assert psk.use_count == initial_usage + 1
                assert psk.last_used_at is not None

    def test_computer_bundle_signing_service_error(self, client):
        """Test handling of signing service errors."""
        with patch('app.routes.api.v1.generate_key_and_csr') as mock_gen_key, \
             patch('app.routes.api.v1.request_signed_certificate') as mock_sign_cert:

            # Setup mocks
            mock_key = MagicMock()
            mock_csr = MagicMock()
            mock_csr.public_bytes.return_value = b'computer-csr'
            mock_gen_key.return_value = (mock_key, mock_csr)
            mock_sign_cert.side_effect = SigningServiceError("Signing service unavailable")

            # Make request
            response = client.post('/api/v1/computer/bundle',
                                   headers={'Authorization': 'Bearer c47ac10b-58cc-4372-a567-0e02b2c3d479'})

            assert response.status_code == 503
            assert 'Signing service unavailable' in response.get_json()['error']

    def test_computer_bundle_x_forwarded_for_handling(self, client):
        """Test X-Forwarded-For header handling in computer bundle."""
        with patch('app.routes.api.v1.generate_key_and_csr') as mock_gen_key, \
             patch('app.routes.api.v1.request_signed_certificate') as mock_sign_cert, \
             patch('app.routes.api.v1.find_best_template_match') as mock_find_template, \
             patch('app.routes.api.v1.render_config_template') as mock_render:

            # Setup mocks
            mock_key = MagicMock()
            mock_key.private_bytes.return_value = b'computer-private-key'
            mock_csr = MagicMock()
            mock_csr.public_bytes.return_value = b'computer-csr'
            mock_gen_key.return_value = (mock_key, mock_csr)
            mock_sign_cert.return_value = 'computer-certificate'

            # Setup template mocks
            mock_find_template.return_value = ('Default.100.ovpn', 'template content')
            mock_render.return_value = 'rendered OVPN configuration content'

            # Test with X-Forwarded-For header
            response = client.post('/api/v1/computer/bundle',
                                   headers={
                                       'Authorization': 'Bearer c47ac10b-58cc-4372-a567-0e02b2c3d479',
                                       'X-Forwarded-For': '203.0.113.100'
                                   })

            assert response.status_code == 200

            # Verify the correct IP was used
            mock_sign_cert.assert_called_once_with('computer-csr', certificate_type='client', client_ip='203.0.113.100')

    def test_server_bundle_still_requires_server_psk(self, client):
        """Test that server bundle endpoint now requires server PSK type."""
        # Try to use computer PSK with server endpoint
        response = client.post('/api/v1/server/bundle',
                               headers={'Authorization': 'Bearer c47ac10b-58cc-4372-a567-0e02b2c3d479'},
                               json={'description': 'test-server'})

        assert response.status_code == 403
        assert 'server PSK' in response.get_json()['error']

