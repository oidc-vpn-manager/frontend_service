"""
Integration tests for the server bundle API endpoint.
"""

import io
import json
import os
import tarfile
import tempfile
import uuid
import pytest
from unittest.mock import patch, MagicMock
from app import create_app
from app.extensions import db
from app.models.presharedkey import PreSharedKey
from app.utils.signing_client import SigningServiceError


class TestServerBundleAPI:
    """Test the /api/v1/server/bundle endpoint."""

    @pytest.fixture
    def app(self):
        """Create a test Flask app."""
        import os
        # Set required environment variables for testing
        os.environ['FLASK_SECRET_KEY'] = 'test-secret-key-for-testing-only'
        os.environ['FERNET_ENCRYPTION_KEY'] = 'test-encryption-key-for-testing-only-32-chars-long'
        os.environ['TESTING'] = 'True'
        
        app = create_app('testing')
        
        # Get the absolute path to test server templates
        import os
        test_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        SERVER_TEMPLATES_DIR = os.path.join(test_dir, 'test_data', 'server_templates')
        
        app.config.update({
            'TESTING': True,
            'SQLALCHEMY_DATABASE_URI': 'sqlite:///:memory:',
            'WTF_CSRF_ENABLED': False,
            'SECRET_KEY': 'test-secret-key-for-testing-only',
            'ENCRYPTION_KEY': 'test-encryption-key-for-testing-only-32-chars',
            'ROOT_CA_CERTIFICATE': 'test-root-ca-cert',
            'INTERMEDIATE_CA_CERTIFICATE': 'test-intermediate-ca-cert',
            'OPENVPN_TLS_CRYPT_KEY': '-----BEGIN OpenVPN Static key V1-----\ntest-tls-key\n-----END OpenVPN Static key V1-----',
            'SERVER_TEMPLATES_DIR': SERVER_TEMPLATES_DIR,
            'TEMPLATE_COLLECTION': [
                {
                    'name': '999.default.ovpn',
                    'path': 'settings/templates/999.default.ovpn',
                    'priority': 999,
                    'groups': ['default']
                }
            ]
        })
        
        with app.app_context():
            db.create_all()
            # Create a test PSK with a fixed UUID key for consistent testing
            test_key = 'f47ac10b-58cc-4372-a567-0e02b2c3d479'  # Fixed UUID for testing
            test_psk = PreSharedKey(
                description='test-server',
                key=test_key,
                is_enabled=True
            )
            db.session.add(test_psk)
            db.session.commit()
            
            yield app

    @pytest.fixture
    def client(self, app):
        """Create a test client."""
        return app.test_client()

    def test_server_bundle_success(self, client):
        """Test successful server bundle generation."""
        with patch('app.routes.api.v1.generate_key_and_csr') as mock_gen_key, \
             patch('app.routes.api.v1.request_signed_certificate') as mock_sign_cert:
            
            # Setup mocks for external services only
            mock_key = MagicMock()
            mock_key.private_bytes.return_value = b'test-private-key-pem'
            mock_csr = MagicMock()
            mock_csr.public_bytes.return_value = b'test-csr-pem'
            mock_gen_key.return_value = (mock_key, mock_csr)
            mock_sign_cert.return_value = 'test-signed-cert-pem'

            # Make request
            response = client.post('/api/v1/server/bundle', 
                                 headers={'Authorization': f'Bearer f47ac10b-58cc-4372-a567-0e02b2c3d479'},
                                 json={'description': 'test-server'})

            # Verify response
            assert response.status_code == 200
            assert response.mimetype == 'application/gzip'
            assert 'openvpn-server-test-server.tar.gz' in response.headers['Content-Disposition']
            
            # Verify tar file contents
            tar_buffer = io.BytesIO(response.data)
            with tarfile.open(fileobj=tar_buffer, mode='r:gz') as tar:
                file_list = tar.getnames()
                assert 'ca-chain.crt' in file_list
                assert 'server.crt' in file_list
                assert 'server.key' in file_list
                assert 'tls-crypt.key' in file_list
                # Check that some server config files are present (exact names may vary)
                ovpn_files = [f for f in file_list if f.endswith('.ovpn')]
                assert len(ovpn_files) >= 2, f"Expected at least 2 .ovpn files, found: {ovpn_files}"
                
                # Check file contents
                ca_chain = tar.extractfile('ca-chain.crt').read().decode('utf-8')
                assert 'test-intermediate-ca-cert' in ca_chain
                assert 'test-root-ca-cert' in ca_chain
                
                server_cert = tar.extractfile('server.crt').read().decode('utf-8')
                assert server_cert == 'test-signed-cert-pem'
                
                server_key = tar.extractfile('server.key').read().decode('utf-8')
                assert server_key == 'test-private-key-pem'
                
                # Test content of one of the .ovpn files
                test_ovpn_file = ovpn_files[0]  # Just pick the first one
                config_content = tar.extractfile(test_ovpn_file).read().decode('utf-8')
                # Basic OpenVPN configuration checks
                assert 'port ' in config_content
                assert 'proto ' in config_content
                assert 'dev tun' in config_content
                assert 'ca ca.crt' in config_content
                assert 'cert server.crt' in config_content
                assert 'key server.key' in config_content

    def test_server_bundle_invalid_psk(self, client):
        """Test server bundle with invalid PSK."""
        response = client.post('/api/v1/server/bundle',
                             headers={'Authorization': 'Bearer invalid-psk'},
                             json={'description': 'test-server'})
        
        assert response.status_code == 401
        data = json.loads(response.data)
        assert 'error' in data
        assert 'Unauthorized' in data['error']

    def test_server_bundle_invalid_psk(self, client):
        """Test server bundle with invalid PSK."""
        response = client.post('/api/v1/server/bundle',
                             headers={'Authorization': 'Bearer invalid-psk-key'})
        
        assert response.status_code == 401
        data = json.loads(response.data)
        assert 'error' in data
        assert 'Invalid' in data['error'] and 'expired' in data['error']

    def test_server_bundle_signing_service_error(self, client):
        """Test server bundle when signing service fails."""
        with patch('app.routes.api.v1.generate_key_and_csr') as mock_gen_key, \
             patch('app.routes.api.v1.request_signed_certificate') as mock_sign_cert:
            
            # Setup mocks
            mock_key = MagicMock()
            mock_csr = MagicMock()
            mock_csr.public_bytes.return_value = b'test-csr-pem'
            mock_gen_key.return_value = (mock_key, mock_csr)
            mock_sign_cert.side_effect = SigningServiceError("Signing service unavailable")

            # Make request
            response = client.post('/api/v1/server/bundle',
                                 headers={'Authorization': f'Bearer f47ac10b-58cc-4372-a567-0e02b2c3d479'},
                                 json={'description': 'test-server'})

            # Verify error response
            assert response.status_code == 503
            data = json.loads(response.data)
            assert 'Signing service unavailable' in data['error']

    def test_server_bundle_generic_error(self, client):
        """Test server bundle with generic error."""
        with patch('app.routes.api.v1.generate_key_and_csr') as mock_gen_key:
            # Setup mock to raise generic exception
            mock_gen_key.side_effect = ValueError("Test error")

            # Make request
            response = client.post('/api/v1/server/bundle',
                                 headers={'Authorization': f'Bearer f47ac10b-58cc-4372-a567-0e02b2c3d479'},
                                 json={'description': 'test-server'})

            # Verify error response
            assert response.status_code == 500
            data = json.loads(response.data)
            assert 'An internal error occurred' in data['error']

    def test_server_bundle_no_tls_crypt_key(self, client, app):
        """Test server bundle without TLS-Crypt key configured."""
        with app.app_context():
            # Set the proper server template path
            import os
            test_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            SERVER_TEMPLATES_DIR = os.path.join(test_dir, 'test_data', 'server_templates')
            app.config['SERVER_TEMPLATES_DIR'] = SERVER_TEMPLATES_DIR
            app.config['OPENVPN_TLS_CRYPT_KEY'] = None
            
            with patch('app.routes.api.v1.generate_key_and_csr') as mock_gen_key, \
                 patch('app.routes.api.v1.request_signed_certificate') as mock_sign_cert:
                
                # Setup mocks for external services only
                mock_key = MagicMock()
                mock_key.private_bytes.return_value = b'test-private-key-pem'
                mock_csr = MagicMock()
                mock_csr.public_bytes.return_value = b'test-csr-pem'
                mock_gen_key.return_value = (mock_key, mock_csr)
                mock_sign_cert.return_value = 'test-signed-cert-pem'

                # Make request
                response = client.post('/api/v1/server/bundle',
                                     headers={'Authorization': f'Bearer f47ac10b-58cc-4372-a567-0e02b2c3d479'},
                                     json={'description': 'test-server'})

                # Should succeed with empty TLS-Crypt key
                assert response.status_code == 200
                
                # Verify tar file contents
                tar_buffer = io.BytesIO(response.data)
                with tarfile.open(fileobj=tar_buffer, mode='r:gz') as tar:
                    tls_crypt_content = tar.extractfile('tls-crypt.key').read().decode('utf-8')
                    assert tls_crypt_content == ''  # Should be empty

    def test_server_bundle_missing_ca_certificates(self, client, app):
        """Test server bundle with missing CA certificates."""
        with app.app_context():
            # Set the proper server template path
            import os
            test_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            SERVER_TEMPLATES_DIR = os.path.join(test_dir, 'test_data', 'server_templates')
            app.config['SERVER_TEMPLATES_DIR'] = SERVER_TEMPLATES_DIR
            app.config['ROOT_CA_CERTIFICATE'] = ''
            app.config['INTERMEDIATE_CA_CERTIFICATE'] = ''
            
            with patch('app.routes.api.v1.generate_key_and_csr') as mock_gen_key, \
                 patch('app.routes.api.v1.request_signed_certificate') as mock_sign_cert:
                
                # Setup mocks for external services only
                mock_key = MagicMock()
                mock_key.private_bytes.return_value = b'test-private-key-pem'
                mock_csr = MagicMock()
                mock_csr.public_bytes.return_value = b'test-csr-pem'
                mock_gen_key.return_value = (mock_key, mock_csr)
                mock_sign_cert.return_value = 'test-signed-cert-pem'

                # Make request
                response = client.post('/api/v1/server/bundle',
                                     headers={'Authorization': f'Bearer f47ac10b-58cc-4372-a567-0e02b2c3d479'},
                                     json={'description': 'test-server'})

                # Should succeed with empty CA chain
                assert response.status_code == 200
                
                # Verify tar file contents
                tar_buffer = io.BytesIO(response.data)
                with tarfile.open(fileobj=tar_buffer, mode='r:gz') as tar:
                    ca_chain = tar.extractfile('ca-chain.crt').read().decode('utf-8')
                    assert ca_chain == ''  # Should be empty

    def test_server_bundle_file_copying(self, client):
        """Test that server configuration files are copied directly from SERVER_TEMPLATES_DIR."""
        test_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # Go up to tests/ dir
        SERVER_TEMPLATES_DIR = os.path.join(test_dir, 'test_data', 'server_templates')
        
        with client.application.app_context():
            # Create a test PSK with a unique description
            test_key = 'f47ac10b-58cc-4372-a567-0e02b2c3d480'  # Different UUID for this test
            unique_description = 'test-server-file-copying'
            
            # First check if PSK already exists and remove it
            existing_psk = PreSharedKey.query.filter_by(description=unique_description).first()
            if existing_psk:
                db.session.delete(existing_psk)
                db.session.commit()
            
            psk_obj = PreSharedKey(
                description=unique_description,
                key=test_key,
                is_enabled=True
            )
            db.session.add(psk_obj)
            db.session.commit()
            
            # Verify PSK was created and can be found
            created_psk = PreSharedKey.query.filter_by(description=unique_description).first()
            assert created_psk is not None, "PSK was not created successfully"
            assert created_psk.is_valid(), "Created PSK is not valid"
            assert created_psk.verify_key(test_key), "PSK key verification failed"
            
            client.application.config.update({
                'SERVER_TEMPLATES_DIR': SERVER_TEMPLATES_DIR,
                'ROOT_CA_CERTIFICATE': 'test-root-ca',
                'INTERMEDIATE_CA_CERTIFICATE': 'test-intermediate-ca',
                'OPENVPN_TLS_CRYPT_KEY': '-----BEGIN OpenVPN Static key V1-----\ntest-tls-key\n-----END OpenVPN Static key V1-----'
            })
            
            with patch('app.routes.api.v1.generate_key_and_csr') as mock_gen_key, \
                 patch('app.routes.api.v1.request_signed_certificate') as mock_sign_cert:
                
                # Setup mocks
                mock_key = MagicMock()
                mock_key.private_bytes.return_value = b'test-private-key-pem'
                mock_csr = MagicMock()
                mock_gen_key.return_value = (mock_key, mock_csr)
                mock_sign_cert.return_value = 'test-signed-cert-pem'

                # Make request
                response = client.post('/api/v1/server/bundle',
                                     headers={'Authorization': f'Bearer {test_key}'},
                                     json={'description': unique_description})
                
                assert response.status_code == 200, f"Response status: {response.status_code}, data: {response.get_json()}"
                
                # Parse tar response
                import tarfile
                import io
                tar_buffer = io.BytesIO(response.data)
                
                with tarfile.open(fileobj=tar_buffer, mode='r:gz') as tar:
                    file_list = tar.getnames()
                    
                    # Verify core files are present
                    assert 'ca-chain.crt' in file_list
                    assert 'server.crt' in file_list
                    assert 'server.key' in file_list
                    assert 'tls-crypt.key' in file_list
                    
                    # Verify .ovpn files from test_data are included
                    ovpn_files = [f for f in file_list if f.endswith('.ovpn')]
                    assert len(ovpn_files) > 0, "No .ovpn files found in server bundle"
                    
                    # Test that files match the expected naming pattern {GroupingName}.{id}.ovpn
                    expected_patterns = ['Default.100.ovpn', 'Default.200.ovpn', 'Dev.10.ovpn', 'Dev.100.ovpn']
                    found_patterns = [f for f in ovpn_files if f in expected_patterns]
                    assert len(found_patterns) > 0, f"No expected patterns found. Got: {ovpn_files}, Expected: {expected_patterns}"
                    
                    # Verify file contents are copied directly (not rendered templates)
                    test_config = tar.extractfile(found_patterns[0]).read().decode('utf-8')
                    # Should contain actual values, not template variables
                    assert '{{' not in test_config, "File appears to contain unrendered template variables"
                    assert 'port ' in test_config, "OpenVPN config should contain port directive"
                    assert 'proto ' in test_config, "OpenVPN config should contain proto directive"

    def test_server_bundle_disabled_psk(self, client, app):
        """Test server bundle with disabled PSK."""
        with app.app_context():
            # Disable the PSK
            psk = PreSharedKey.query.filter_by(description='test-server').first()
            psk.is_enabled = False
            db.session.commit()

            response = client.post('/api/v1/server/bundle',
                                 headers={'Authorization': f'Bearer f47ac10b-58cc-4372-a567-0e02b2c3d479'},
                                 json={'description': 'test-server'})
            
            assert response.status_code == 401
            data = json.loads(response.data)
            assert 'error' in data
            assert 'Unauthorized' in data['error']

    def test_server_bundle_missing_auth_header(self, client):
        """Test server bundle without Authorization header."""
        response = client.post('/api/v1/server/bundle',
                             json={'description': 'test-server'})
        
        assert response.status_code == 401
        data = json.loads(response.data)
        assert 'error' in data
        assert 'Authorization header' in data['error']