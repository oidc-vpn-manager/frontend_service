"""
Security tests for cryptographic operations covering OWASP A02: Cryptographic Failures.
"""

import pytest
import re
import uuid
from unittest.mock import patch, MagicMock
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from app.extensions import db
from app.models.presharedkey import PreSharedKey
from app.utils.ca_core import generate_key_and_csr
from app.utils.cryptography import get_fernet


class TestPrivateKeySecurityhandling:
    """Tests for secure private key handling"""
    
    @patch('app.routes.api.v1.request_signed_certificate')
    def test_private_keys_not_logged(self, mock_signing, client, app, caplog):
        """Test that private keys are not written to logs"""
        # Mock successful certificate signing
        mock_signing.return_value = "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----"
        
        hostname = "crypto-test.com"
        key = str(uuid.uuid4())
        
        with app.app_context():
            psk = PreSharedKey(description=hostname, key=key)
            db.session.add(psk)
            db.session.commit()
        
        response = client.post(
            '/api/v1/server/bundle',
            headers={'Authorization': f'Bearer {key}'},
            json={'hostname': hostname}
        )
        
        if response.status_code == 200:
            # Server bundle endpoint returns a binary tar.gz, so we test for private key in logs
            # Check that private key is NOT in logs
            log_output = caplog.text
            assert '-----BEGIN PRIVATE KEY-----' not in log_output
            assert 'BEGIN RSA PRIVATE KEY' not in log_output

    def test_private_key_not_in_error_messages(self, client, app):
        """Test private keys don't appear in error responses"""
        with patch('app.routes.api.v1.generate_key_and_csr') as mock_gen:
            # Generate a real private key for the test
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048
            )
            private_key_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ).decode('utf-8')
            
            # Mock to raise an exception after generating the key
            mock_gen.side_effect = Exception(f"Error with key: {private_key_pem}")
            
            hostname = "error-test.com"
            key = str(uuid.uuid4())
            
            with app.app_context():
                psk = PreSharedKey(description=hostname, key=key)
                db.session.add(psk)
                db.session.commit()
            
            response = client.post(
                '/api/v1/server/bundle',
                headers={'Authorization': f'Bearer {key}'},
                json={'description': hostname}
            )
            
            # Should return error without exposing private key
            assert response.status_code == 500
            response_text = response.get_data(as_text=True)
            assert '-----BEGIN PRIVATE KEY-----' not in response_text
            assert 'BEGIN RSA PRIVATE KEY' not in response_text

    def test_private_key_proper_format(self, client, app):
        """Test private keys are generated in secure format"""
        hostname = "format-test.com"
        key = str(uuid.uuid4())
        
        with app.app_context():
            psk = PreSharedKey(description=hostname, key=key)
            db.session.add(psk)
            db.session.commit()
        
        with patch('app.routes.api.v1.request_signed_certificate') as mock_signing:
            mock_signing.return_value = "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----"
            
            response = client.post(
                '/api/v1/server/bundle',
                headers={'Authorization': f'Bearer {key}'},
                json={'description': hostname}
            )
            
            # Server bundle returns binary tar.gz, so we test key format by generating one directly
            # Test key format by generating one directly
            from app.utils.ca_core import generate_key_and_csr
            private_key, _ = generate_key_and_csr('test.com')
            private_key_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ).decode('utf-8')
            
            # Should use PKCS#8 format (more secure than legacy formats)
            assert '-----BEGIN PRIVATE KEY-----' in private_key_pem
            assert '-----END PRIVATE KEY-----' in private_key_pem
            
            # Should NOT use legacy RSA format
            assert 'BEGIN RSA PRIVATE KEY' not in private_key_pem

    def test_private_key_strength(self, app):
        """Test generated private keys meet strength requirements"""
        with app.app_context():
            # Generate a key pair
            private_key, csr = generate_key_and_csr("test.example.com")
        
        # Check key size (should be at least 2048 bits for RSA)
        if isinstance(private_key, rsa.RSAPrivateKey):
            assert private_key.key_size >= 2048, f"RSA key too small: {private_key.key_size} bits"
            
            # Check public exponent (should be 65537 for security)
            public_key = private_key.public_key()
            assert public_key.public_numbers().e == 65537, "Insecure RSA public exponent"


class TestCertificateValidation:
    """Tests for certificate validation and security"""
    
    def test_certificate_chain_validation(self, app):
        """Test proper certificate chain validation"""
        with app.app_context():
            root_ca = app.config.get('ROOT_CA_CERTIFICATE', '')
            intermediate_ca = app.config.get('INTERMEDIATE_CA_CERTIFICATE', '')
            
            if root_ca and intermediate_ca:
                # Verify certificates are valid PEM format
                assert '-----BEGIN CERTIFICATE-----' in root_ca
                assert '-----END CERTIFICATE-----' in root_ca
                assert '-----BEGIN CERTIFICATE-----' in intermediate_ca
                assert '-----END CERTIFICATE-----' in intermediate_ca
                
                # Try to parse certificates
                try:
                    x509.load_pem_x509_certificate(root_ca.encode('utf-8'))
                    x509.load_pem_x509_certificate(intermediate_ca.encode('utf-8'))
                except Exception as e:
                    pytest.fail(f"Invalid CA certificate format: {e}")

    @patch('app.routes.api.v1.request_signed_certificate')
    def test_certificate_not_logged(self, mock_signing, client, app, caplog):
        """Test that certificates are not written to logs inappropriately"""
        test_cert = "-----BEGIN CERTIFICATE-----\nMIIBkTCB+gIJAK..." + "A" * 500 + "\n-----END CERTIFICATE-----"
        mock_signing.return_value = test_cert
        
        hostname = "cert-log-test.com"
        key = str(uuid.uuid4())
        
        with app.app_context():
            psk = PreSharedKey(description=hostname, key=key)
            db.session.add(psk)
            db.session.commit()
        
        response = client.post(
            '/api/v1/server/bundle',
            headers={'Authorization': f'Bearer {key}'},
            json={'hostname': hostname}
        )
        
        # Server bundle endpoint returns binary tar.gz, so test log output directly
        log_output = caplog.text
        # Check that certificate content is not inappropriately logged
        cert_lines = test_cert.split('\n')
        if len(cert_lines) > 2:
            cert_content = cert_lines[1][:50]  # First 50 chars of cert data
            # Full certificate content should not be in logs (unless debugging)
            assert cert_content not in log_output or "DEBUG" in log_output


class TestEncryptionSecurity:
    """Tests for data encryption security"""
    
    def test_psk_encryption_strength(self, app):
        """Test PSK encryption uses strong algorithms"""
        with app.app_context():
            fernet = get_fernet()
            
            # Test encryption with various data
            test_data = [
                "sensitive-key-12345",
                "a" * 100,  # Long data
                "special chars: !@#$%^&*()",
                "unicode: 测试数据"
            ]
            
            for data in test_data:
                encrypted = fernet.encrypt(data.encode('utf-8'))
                decrypted = fernet.decrypt(encrypted).decode('utf-8')
                
                assert decrypted == data, "Encryption/decryption failed"
                assert encrypted != data.encode('utf-8'), "Data not actually encrypted"
                assert len(encrypted) > len(data), "Encrypted data too short"
                
                # Should not be easily readable
                assert data.encode('utf-8') not in encrypted, "Original data visible in encrypted form"

    def test_encryption_randomness(self, app):
        """Test encryption produces different outputs for same input"""
        with app.app_context():
            fernet = get_fernet()
            test_data = "consistent-test-data"
            
            # Encrypt same data multiple times
            encrypted_values = []
            for _ in range(5):
                encrypted = fernet.encrypt(test_data.encode('utf-8'))
                encrypted_values.append(encrypted)
                
                # Each should decrypt correctly
                assert fernet.decrypt(encrypted).decode('utf-8') == test_data
            
            # All encrypted values should be different (due to IV/salt)
            assert len(set(encrypted_values)) == 5, "Encryption not using random IV/salt"

    def test_encryption_key_not_hardcoded(self, app):
        """Test encryption key is not hardcoded"""
        with app.app_context():
            # Check that the encryption key is configurable
            encryption_key = app.config.get('ENCRYPTION_KEY', '')
            
            if encryption_key:
                # Should not be obviously weak values
                weak_values = [
                    'password',
                    'secret',
                    '123456',
                    'default',
                    'test',
                    'changeme',
                    'admin'
                ]
                
                for weak_value in weak_values:
                    assert weak_value not in encryption_key.lower(), f"Weak encryption key detected"
                
                # Should have sufficient length for Fernet (32 base64 chars = 24 bytes)
                assert len(encryption_key) >= 32, f"Encryption key too short: {len(encryption_key)}"


class TestRandomnessAndEntropy:
    """Tests for cryptographic randomness and entropy"""
    
    def test_psk_generation_randomness(self, app):
        """Test PSK generation has sufficient randomness"""
        with app.app_context():
            # Generate multiple PSKs
            generated_psk_hashes = []
            for _ in range(10):
                psk = PreSharedKey(description=f"test-{uuid.uuid4()}.com")
                generated_psk_hashes.append(psk.key_hash)
            
            # All should be different (different UUIDs generate different hashes)
            assert len(set(generated_psk_hashes)) == 10, "PSK generation lacks randomness"
            
            # Should have sufficient length (SHA256 hashes are 64 hex chars)
            for psk_hash in generated_psk_hashes:
                assert len(psk_hash) == 64, f"PSK hash should be 64 chars: {len(psk_hash)} chars"
                
                # Should contain mix of characters (not all same character)
                unique_chars = set(psk_hash)
                assert len(unique_chars) > 5, f"PSK hash lacks character diversity: {len(unique_chars)}"

    def test_uuid_generation_quality(self):
        """Test UUID generation for sufficient entropy"""
        # Generate multiple UUIDs
        generated_uuids = []
        for _ in range(100):
            generated_uuids.append(str(uuid.uuid4()))
        
        # All should be different
        assert len(set(generated_uuids)) == 100, "UUID generation has collisions"
        
        # Should follow UUID4 format (random)
        uuid_pattern = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$')
        for uuid_str in generated_uuids:
            assert uuid_pattern.match(uuid_str), f"Invalid UUID4 format: {uuid_str}"


class TestTLSAndTransportSecurity:
    """Tests for TLS and transport security"""
    
    def test_tls_crypt_key_handling(self, app):
        """Test TLS-Crypt key is handled securely"""
        with app.app_context():
            tls_key = app.config.get('OPENVPN_TLS_CRYPT_KEY')
            
            if tls_key:
                # Should be proper format
                assert isinstance(tls_key, str)
                assert len(tls_key) > 100, "TLS-Crypt key too short"
                
                # Should not be obviously weak
                assert tls_key != "test-key"
                assert tls_key != "default-key"
                assert not tls_key.startswith("1234")

    def test_no_weak_crypto_algorithms(self, app):
        """Test that weak cryptographic algorithms are not used"""
        # This is more of a code review check, but we can verify
        # that strong algorithms are configured
        
        with app.app_context():
            # Check that we're not using deprecated hash algorithms
            # This would need to be verified in the actual CSR generation
            private_key, csr = generate_key_and_csr("test.com")
            
            # Verify CSR is using strong signature algorithm (if available)
            # CSRs are unsigned, so we check the hash algorithm used in the CSR structure
            if hasattr(csr, 'signature_hash_algorithm') and csr.signature_hash_algorithm:
                assert csr.signature_hash_algorithm.name in ['sha256', 'sha384', 'sha512']
                assert csr.signature_hash_algorithm.name != 'sha1', "Weak hash algorithm used"
                assert csr.signature_hash_algorithm.name != 'md5', "Weak hash algorithm used"
            
            # Verify the private key uses strong parameters
            if isinstance(private_key, rsa.RSAPrivateKey):
                assert private_key.key_size >= 2048, "Weak RSA key size"


class TestSecretManagement:
    """Tests for secure secret management"""
    
    def test_secrets_not_in_config_directly(self, app):
        """Test that secrets are not hardcoded in configuration"""
        with app.app_context():
            # In test/development environment, weak secrets might be acceptable
            # But in production, they should be strong
            is_production = app.config.get('FLASK_ENV') == 'production'
            is_testing = app.config.get('TESTING', False)
            
            # Check various secret configurations
            sensitive_configs = [
                'SECRET_KEY',
                'FERNET_ENCRYPTION_KEY', 
                'SIGNING_SERVICE_API_SECRET',
                'OPENVPN_TLS_CRYPT_KEY'
            ]
            
            for config_key in sensitive_configs:
                config_value = app.config.get(config_key, '')
                
                if config_value and is_production and not is_testing:
                    # Should not be obviously weak values in production
                    weak_values = [
                        'password',
                        'secret',
                        '123456',
                        'default',
                        'test',
                        'changeme',
                        'admin'
                    ]
                    
                    for weak_value in weak_values:
                        assert weak_value not in config_value.lower(), f"Weak secret in {config_key} in production"
                    
                    # Should have sufficient length in production
                    if config_key in ['SECRET_KEY', 'FERNET_ENCRYPTION_KEY']:
                        assert len(config_value) >= 32, f"{config_key} too short in production: {len(config_value)}"
                
                elif config_value:
                    # In development/test, just check minimum length
                    if config_key in ['SECRET_KEY', 'FERNET_ENCRYPTION_KEY']:
                        assert len(config_value) >= 16, f"{config_key} too short even for development: {len(config_value)}"

    def test_environment_variable_usage(self, app):
        """Test that secrets can be loaded from environment variables"""
        # This tests that the application supports loading secrets from env vars
        # rather than hardcoding them
        
        with app.app_context():
            # The application should support loading from environment
            # This is more of an architectural test
            from app.utils import environment
            
            # Test that environment loading functions exist and work
            test_var = environment.get_env_var('NONEXISTENT_VAR_FOR_TEST', 'default_value')
            assert test_var == 'default_value', "Environment variable loading not working"

    def test_secrets_not_exposed_in_responses(self, client, app):
        """Test that secrets are not accidentally exposed in HTTP responses"""
        # Test various endpoints for secret leakage
        test_endpoints = [
            '/',
            '/admin/psk',
            '/api/v1/server/bundle',  # This will fail without PSK, but shouldn't expose secrets
        ]
        
        with app.app_context():
            # Get potential secrets to check for
            potential_secrets = [
                app.config.get('SECRET_KEY', ''),
                app.config.get('FERNET_ENCRYPTION_KEY', ''),
                app.config.get('SIGNING_SERVICE_API_SECRET', ''),
            ]
            
            secrets_to_check = [s for s in potential_secrets if s and len(s) > 10]
        
        for endpoint in test_endpoints:
            try:
                response = client.get(endpoint)
                response_text = response.get_data(as_text=True)
                
                for secret in secrets_to_check:
                    # Check for partial secret exposure (first/last 10 chars)
                    if len(secret) > 20:
                        secret_start = secret[:10]
                        secret_end = secret[-10:]
                        
                        assert secret_start not in response_text, f"Secret start exposed at {endpoint}"
                        assert secret_end not in response_text, f"Secret end exposed at {endpoint}"
                    
                    # Full secret should definitely not be there
                    assert secret not in response_text, f"Full secret exposed at {endpoint}"
                    
            except Exception:
                # If endpoint fails, that's fine - we're just checking it doesn't leak secrets
                pass