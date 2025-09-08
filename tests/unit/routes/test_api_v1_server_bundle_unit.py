"""
Unit tests for the server bundle API endpoint - file copying workflow.
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


class TestServerBundleUnit:
    """Unit tests for server bundle functionality - file copying approach."""

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

    def test_server_bundle_file_copying_workflow(self, client):
        """Test the new file copying workflow for server bundle generation."""
        # Mock server templates directory with test files
        test_server_files = {
            'Default.100.ovpn': 'proto udp\nport 1194\ndev tun\nca ca.crt\ncert server.crt\nkey server.key',
            'Default.200.ovpn': 'proto tcp\nport 443\ndev tun\nca ca.crt\ncert server.crt\nkey server.key',
            'Dev.10.ovpn': 'proto udp\nport 1195\ndev tun\nca ca.crt\ncert server.crt\nkey server.key'
        }

        with patch('app.routes.api.v1.generate_key_and_csr') as mock_gen_key, \
             patch('app.routes.api.v1.request_signed_certificate') as mock_sign_cert, \
             patch('os.path.exists') as mock_exists, \
             patch('os.listdir') as mock_listdir, \
             patch('builtins.open', mock_open()) as mock_file_open:
            
            # Setup mocks for certificate generation
            mock_key = MagicMock()
            mock_key.private_bytes.return_value = b'server-private-key'
            mock_csr = MagicMock()
            mock_csr.public_bytes.return_value = b'server-csr'
            mock_gen_key.return_value = (mock_key, mock_csr)
            mock_sign_cert.return_value = 'server-certificate'
            
            # Setup mocks for file system
            mock_exists.return_value = True
            mock_listdir.return_value = list(test_server_files.keys())
            
            # Setup file content mocks
            def mock_file_contents(filename, *args, **kwargs):
                if filename.endswith('.ovpn') and os.path.basename(filename) in test_server_files:
                    file_content = test_server_files[os.path.basename(filename)]
                    return mock_open(read_data=file_content)(*args, **kwargs)
                return mock_open()(*args, **kwargs)
            
            mock_file_open.side_effect = mock_file_contents

            # Configure app with SERVER_TEMPLATES_DIR
            client.application.config['SERVER_TEMPLATES_DIR'] = '/test/server/templates'

            # Make request
            response = client.post('/api/v1/server/bundle',
                                 headers={'Authorization': 'Bearer f47ac10b-58cc-4372-a567-0e02b2c3d479'},
                                 json={'description': 'test-server'})

            # Verify response
            assert response.status_code == 200
            assert response.mimetype == 'application/gzip'
            assert 'openvpn-server-test-server.tar.gz' in response.headers['Content-Disposition']

            # Extract and verify tar contents
            tar_buffer = io.BytesIO(response.data)
            with tarfile.open(fileobj=tar_buffer, mode='r:gz') as tar:
                file_names = tar.getnames()
                
                # Core files should be present
                assert 'ca-chain.crt' in file_names
                assert 'server.crt' in file_names
                assert 'server.key' in file_names
                assert 'tls-crypt.key' in file_names
                
                # Only Default template set files should be copied (PSK has Default template set)
                expected_files = ['Default.100.ovpn', 'Default.200.ovpn']
                for config_file in expected_files:
                    assert config_file in file_names
                    
                # Dev template files should NOT be included (filtered out)
                assert 'Dev.10.ovpn' not in file_names
                
                # Verify certificate contents
                ca_chain = tar.extractfile('ca-chain.crt').read().decode('utf-8')
                assert 'test-intermediate-ca' in ca_chain
                assert 'test-root-ca' in ca_chain
                
                server_cert = tar.extractfile('server.crt').read().decode('utf-8')
                assert server_cert == 'server-certificate'
                
                # Verify server config file was copied correctly
                config_content = tar.extractfile('Default.100.ovpn').read().decode('utf-8')
                assert 'proto udp' in config_content
                assert 'port 1194' in config_content

    def test_server_bundle_certificate_generation(self, client):
        """Test certificate generation parameters."""
        with patch('app.routes.api.v1.generate_key_and_csr') as mock_gen_key, \
             patch('app.routes.api.v1.request_signed_certificate') as mock_sign_cert, \
             patch('os.path.exists') as mock_exists, \
             patch('app.models.presharedkey.PreSharedKey.query') as mock_psk_query:
            
            # Setup PSK mock - simulate valid PSK for auth
            mock_psk = MagicMock()
            mock_psk.description = 'test-server'
            mock_psk.is_valid.return_value = True
            mock_psk.verify_key.return_value = True
            mock_psk_query.filter_by.return_value.all.return_value = [mock_psk]
            
            # Setup key generation mocks
            mock_key = MagicMock()
            mock_key.private_bytes.return_value = b'server-private-key'
            mock_csr = MagicMock()
            mock_csr.public_bytes.return_value = b'server-csr'
            mock_gen_key.return_value = (mock_key, mock_csr)
            mock_sign_cert.return_value = 'server-certificate'
            
            # No SERVER_TEMPLATES_DIR configured
            mock_exists.return_value = False

            # Make request using new API structure (GET, no JSON body)
            response = client.get('/api/v1/server/bundle',
                                 headers={'Authorization': 'Bearer f47ac10b-58cc-4372-a567-0e02b2c3d479'})

            # Verify certificate generation called with PSK description and timestamp
            mock_gen_key.assert_called_once()
            call_args = mock_gen_key.call_args[1]
            assert call_args['common_name'].startswith('server-test-server-')
            assert call_args['common_name'].count('-') == 3  # server-test-server-<timestamp>
            
            # Verify CSR was signed with server certificate type and client IP
            mock_sign_cert.assert_called_once_with('server-csr', certificate_type='server', client_ip='127.0.0.1')

    def test_server_bundle_ca_chain_handling(self, client):
        """Test CA certificate chain construction."""
        with patch('app.routes.api.v1.generate_key_and_csr') as mock_gen_key, \
             patch('app.routes.api.v1.request_signed_certificate') as mock_sign_cert, \
             patch('os.path.exists') as mock_exists:
            
            # Setup mocks
            mock_key = MagicMock()
            mock_key.private_bytes.return_value = b'server-private-key'
            mock_csr = MagicMock()
            mock_gen_key.return_value = (mock_key, mock_csr)
            mock_sign_cert.return_value = 'server-certificate'
            mock_exists.return_value = False
            
            # Configure custom CA certificates
            client.application.config.update({
                'ROOT_CA_CERTIFICATE': 'root-ca-cert-pem',
                'INTERMEDIATE_CA_CERTIFICATE': 'intermediate-ca-cert-pem'
            })

            # Make request
            response = client.post('/api/v1/server/bundle',
                                 headers={'Authorization': 'Bearer f47ac10b-58cc-4372-a567-0e02b2c3d479'},
                                 json={'description': 'test-server'})

            # Extract and verify CA chain
            tar_buffer = io.BytesIO(response.data)
            with tarfile.open(fileobj=tar_buffer, mode='r:gz') as tar:
                ca_chain = tar.extractfile('ca-chain.crt').read().decode('utf-8')
                assert 'intermediate-ca-cert-pem' in ca_chain
                assert 'root-ca-cert-pem' in ca_chain

    def test_server_bundle_empty_ca_certificates(self, client):
        """Test handling of empty CA certificates."""
        with patch('app.routes.api.v1.generate_key_and_csr') as mock_gen_key, \
             patch('app.routes.api.v1.request_signed_certificate') as mock_sign_cert, \
             patch('os.path.exists') as mock_exists:
            
            # Setup mocks
            mock_key = MagicMock()
            mock_key.private_bytes.return_value = b'server-private-key'
            mock_csr = MagicMock()
            mock_gen_key.return_value = (mock_key, mock_csr)
            mock_sign_cert.return_value = 'server-certificate'
            mock_exists.return_value = False
            
            # Configure empty CA certificates
            client.application.config.update({
                'ROOT_CA_CERTIFICATE': '',
                'INTERMEDIATE_CA_CERTIFICATE': ''
            })

            # Make request
            response = client.post('/api/v1/server/bundle',
                                 headers={'Authorization': 'Bearer f47ac10b-58cc-4372-a567-0e02b2c3d479'},
                                 json={'description': 'test-server'})

            # Extract and verify CA chain is empty
            tar_buffer = io.BytesIO(response.data)
            with tarfile.open(fileobj=tar_buffer, mode='r:gz') as tar:
                ca_chain = tar.extractfile('ca-chain.crt').read().decode('utf-8')
                assert ca_chain == ''

    def test_server_bundle_no_tls_crypt_key(self, client):
        """Test handling when TLS-Crypt key is not configured."""
        with patch('app.routes.api.v1.generate_key_and_csr') as mock_gen_key, \
             patch('app.routes.api.v1.request_signed_certificate') as mock_sign_cert, \
             patch('os.path.exists') as mock_exists:
            
            # Setup mocks
            mock_key = MagicMock()
            mock_key.private_bytes.return_value = b'server-private-key'
            mock_csr = MagicMock()
            mock_gen_key.return_value = (mock_key, mock_csr)
            mock_sign_cert.return_value = 'server-certificate'
            mock_exists.return_value = False
            
            # Configure no TLS-Crypt key
            client.application.config['OPENVPN_TLS_CRYPT_KEY'] = None

            # Make request
            response = client.post('/api/v1/server/bundle',
                                 headers={'Authorization': 'Bearer f47ac10b-58cc-4372-a567-0e02b2c3d479'},
                                 json={'description': 'test-server'})

            # Extract and verify TLS-Crypt key is empty
            tar_buffer = io.BytesIO(response.data)
            with tarfile.open(fileobj=tar_buffer, mode='r:gz') as tar:
                tls_key = tar.extractfile('tls-crypt.key').read().decode('utf-8')
                assert tls_key == ''

    def test_server_bundle_no_server_templates_dir(self, client):
        """Test behavior when SERVER_TEMPLATES_DIR is not configured."""
        with patch('app.routes.api.v1.generate_key_and_csr') as mock_gen_key, \
             patch('app.routes.api.v1.request_signed_certificate') as mock_sign_cert:
            
            # Setup mocks
            mock_key = MagicMock()
            mock_key.private_bytes.return_value = b'server-private-key'
            mock_csr = MagicMock()
            mock_gen_key.return_value = (mock_key, mock_csr)
            mock_sign_cert.return_value = 'server-certificate'
            
            # Don't configure SERVER_TEMPLATES_DIR
            client.application.config.pop('SERVER_TEMPLATES_DIR', None)

            # Make request
            response = client.post('/api/v1/server/bundle',
                                 headers={'Authorization': 'Bearer f47ac10b-58cc-4372-a567-0e02b2c3d479'},
                                 json={'description': 'test-server'})

            # Should still work but with no config files
            assert response.status_code == 200
            
            # Extract and verify only core files are present
            tar_buffer = io.BytesIO(response.data)
            with tarfile.open(fileobj=tar_buffer, mode='r:gz') as tar:
                file_names = tar.getnames()
                assert 'ca-chain.crt' in file_names
                assert 'server.crt' in file_names
                assert 'server.key' in file_names
                assert 'tls-crypt.key' in file_names
                
                # Should not have any .ovpn files
                ovpn_files = [f for f in file_names if f.endswith('.ovpn')]
                assert len(ovpn_files) == 0

    def test_server_bundle_signing_service_error(self, client):
        """Test server bundle when signing service fails."""
        with patch('app.routes.api.v1.generate_key_and_csr') as mock_gen_key, \
             patch('app.routes.api.v1.request_signed_certificate') as mock_sign_cert:
            
            # Setup mocks
            mock_key = MagicMock()
            mock_csr = MagicMock()
            mock_csr.public_bytes.return_value = b'server-csr'
            mock_gen_key.return_value = (mock_key, mock_csr)
            mock_sign_cert.side_effect = SigningServiceError("Signing service unavailable")

            # Make request
            response = client.post('/api/v1/server/bundle',
                                 headers={'Authorization': 'Bearer f47ac10b-58cc-4372-a567-0e02b2c3d479'},
                                 json={'description': 'test-server'})

            # Verify error response
            assert response.status_code == 503
            data = json.loads(response.data)
            assert 'Signing service unavailable' in data['error']

    def test_server_bundle_generic_exception(self, client):
        """Test server bundle with generic error."""
        with patch('app.routes.api.v1.generate_key_and_csr') as mock_gen_key:
            # Setup mock to raise generic exception
            mock_gen_key.side_effect = ValueError("Test error")

            # Make request
            response = client.post('/api/v1/server/bundle',
                                 headers={'Authorization': 'Bearer f47ac10b-58cc-4372-a567-0e02b2c3d479'},
                                 json={'description': 'test-server'})

            # Verify error response
            assert response.status_code == 500
            data = json.loads(response.data)
            assert 'An internal error occurred' in data['error']

    def test_server_bundle_file_sizes_in_tar(self, client):
        """Test that files in the tar have correct sizes."""
        with patch('app.routes.api.v1.generate_key_and_csr') as mock_gen_key, \
             patch('app.routes.api.v1.request_signed_certificate') as mock_sign_cert, \
             patch('os.path.exists') as mock_exists:
            
            # Setup mocks
            mock_key = MagicMock()
            mock_key.private_bytes.return_value = b'server-private-key-content'  # 26 bytes
            mock_csr = MagicMock()
            mock_gen_key.return_value = (mock_key, mock_csr)
            mock_sign_cert.return_value = 'server-certificate-content'  # 26 bytes
            mock_exists.return_value = False

            # Make request
            response = client.post('/api/v1/server/bundle',
                                 headers={'Authorization': 'Bearer f47ac10b-58cc-4372-a567-0e02b2c3d479'},
                                 json={'description': 'test-server'})

            # Extract and verify file sizes
            tar_buffer = io.BytesIO(response.data)
            with tarfile.open(fileobj=tar_buffer, mode='r:gz') as tar:
                # Check server.key file size
                key_info = tar.getmember('server.key')
                assert key_info.size == 26  # Length of 'server-private-key-content'
                
                # Check server.crt file size  
                cert_info = tar.getmember('server.crt')
                assert cert_info.size == 26  # Length of 'server-certificate-content'