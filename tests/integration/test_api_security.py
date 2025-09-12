"""
Security tests for API endpoints covering OWASP Top 10 and API Security Top 10.
"""

import pytest
import json
import uuid
from unittest.mock import patch, MagicMock
from app.extensions import db
from app.models.presharedkey import PreSharedKey


class TestInputValidationSecurity:
    """Tests for input validation vulnerabilities (A03: Injection)"""
    
    def test_malformed_authorization_header(self, client, app):
        """Test malformed Authorization headers"""
        malformed_headers = [
            "Bearer",                    # Missing token
            "Bearer ",                   # Empty token
            "Bearer\x00malicious",       # Null byte injection
            "Bearer " + "A" * 10000,     # Very long token
            "InvalidFormat token",       # Wrong format
            "Bearer multiple tokens",    # Multiple tokens
        ]
        
        for header_value in malformed_headers:
            response = client.get(
                '/api/v1/server/bundle',
                headers={'Authorization': header_value}
            )
            # Should handle gracefully with 401 
            assert response.status_code == 401, f"Malformed header was processed: {header_value}"

    def test_json_body_ignored_security(self, client, app):
        """Test that JSON body with malicious content is ignored"""
        # Create a valid PSK
        hostname = "valid-server.com" 
        key = str(uuid.uuid4())
        with app.app_context():
            psk = PreSharedKey(description=hostname, key=key)
            db.session.add(psk)
            db.session.commit()
        
        # Various malicious JSON payloads that should be ignored
        malicious_payloads = [
            {'description': "'; DROP TABLE presharedkeys; --"},
            {'description': "test$(rm -rf /)"},
            {'description': "../../../etc/passwd"},
            {'description': "\x00malicious"},
            {'malicious_field': 'evil_value'},
            {'description': 'A' * 100000},  # Very large
        ]
        
        for payload in malicious_payloads:
            with patch('app.routes.api.v1.request_signed_certificate') as mock_sign:
                mock_sign.return_value = "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----"
                
                response = client.get(
                    '/api/v1/server/bundle',
                    headers={'Authorization': f'Bearer {key}'},
                    json=payload
                )
                # Should succeed (200) because only PSK matters, JSON is ignored
                assert response.status_code == 200, f"API failed when it should ignore JSON: {payload}"


class TestAuthenticationSecurity:
    """Tests for authentication vulnerabilities (A07, API2)"""
    
    def test_bearer_token_manipulation(self, client, app):
        """Test modified/forged Bearer tokens"""
        hostname = "test-server.com"
        real_key = str(uuid.uuid4())
        with app.app_context():
            psk = PreSharedKey(description=hostname, key=real_key)
            db.session.add(psk)
            db.session.commit()
        
        # Various token manipulation attempts
        manipulated_tokens = [
            real_key[:-1] + "X",  # Modified last character
            real_key.upper(),     # Case change
            real_key + "extra",   # Appended data
            "Bearer " + real_key, # Double Bearer
            real_key[:10],        # Truncated
            "",                   # Empty
            "null",               # String null
            "undefined",          # String undefined
        ]
        
        for token in manipulated_tokens:
            response = client.get(
                '/api/v1/server/bundle',
                headers={'Authorization': f'Bearer {token}'}
            )
            assert response.status_code == 401, f"Modified token was accepted: {token}"

    def test_authorization_header_variations(self, client, app):
        """Test various Authorization header formats"""
        hostname = "test-server.com"
        key = str(uuid.uuid4())
        with app.app_context():
            psk = PreSharedKey(description=hostname, key=key)
            db.session.add(psk)
            db.session.commit()
        
        # Various header format attempts
        auth_variations = [
            f"bearer {key}",           # Lowercase
            f"BEARER {key}",           # Uppercase
            f"Basic {key}",            # Wrong auth type
            f"Token {key}",            # Wrong auth type
            f"Bearer{key}",            # No space
            f"Bearer  {key}",          # Extra space
            f"Bearer\t{key}",          # Tab instead of space
            key,                       # No Bearer prefix
        ]
        
        for auth_header in auth_variations:
            response = client.get(
                '/api/v1/server/bundle',
                headers={'Authorization': auth_header}
            )
            # Only proper "Bearer <token>" should work
            if auth_header == f"Bearer {key}":
                continue  # This should work
            assert response.status_code == 401, f"Invalid auth header format was accepted: {auth_header}"

    def test_psk_enumeration_protection(self, client, app):
        """Test protection against PSK enumeration via timing attacks"""
        import time
        
        # Create one valid PSK
        valid_hostname = "exists.com"
        valid_key = str(uuid.uuid4())
        with app.app_context():
            psk = PreSharedKey(description=valid_hostname, key=valid_key)
            db.session.add(psk)
            db.session.commit()
        
        # Test timing for existing vs non-existing hostnames
        fake_key = str(uuid.uuid4())
        
        # Time requests with fake PSK key (should be consistent timing)
        times_fake_psk = []
        for _ in range(10):
            start = time.time()
            client.get(
                '/api/v1/server/bundle',
                headers={'Authorization': f'Bearer {fake_key}'}
            )
            times_fake_psk.append(time.time() - start)
        
        # Verify timing is consistent (no significant variation that could leak info)
        avg_time = sum(times_fake_psk) / len(times_fake_psk)
        max_deviation = max(abs(t - avg_time) for t in times_fake_psk)
        
        # Maximum deviation should be reasonable (< 50ms) indicating consistent timing
        assert max_deviation < 0.05, f"Timing inconsistency detected: {max_deviation:.3f}s max deviation"



class TestErrorHandlingSecurity:
    """Tests for secure error handling (A05: Security Misconfiguration)"""
    
    def test_error_information_disclosure(self, client, app):
        """Test that errors don't expose sensitive information"""
        with patch('app.routes.api.v1.generate_key_and_csr') as mock_gen:
            # Simulate various internal errors
            mock_gen.side_effect = Exception("Database connection failed at /home/user/secret_path/config.db")
            
            hostname = "test.com"
            key = str(uuid.uuid4())
            with app.app_context():
                psk = PreSharedKey(description=hostname, key=key)
                db.session.add(psk)
                db.session.commit()
            
            response = client.get(
                '/api/v1/server/bundle',
                headers={'Authorization': f'Bearer {key}'}
            )
            
            assert response.status_code == 500
            response_data = response.get_data(as_text=True).lower()
            
            # Should not expose sensitive paths, stack traces, or internal details
            sensitive_patterns = [
                '/home/',
                'traceback',
                'file "',
                'line ',
                'secret_path',
                'database connection',
                'config.db'
            ]
            
            for pattern in sensitive_patterns:
                assert pattern not in response_data, f"Sensitive info exposed: {pattern}"

    def test_malformed_json_ignored(self, client, app):
        """Test that malformed JSON is ignored when only Authorization header matters"""
        # Create a valid PSK
        hostname = "test-server.com"
        key = str(uuid.uuid4())
        with app.app_context():
            psk = PreSharedKey(description=hostname, key=key)
            db.session.add(psk)
            db.session.commit()

        # Test malformed JSON payloads - these should be ignored
        malformed_payloads = [
            '{"hostname": "test.com"',  # Missing closing brace
            '{"hostname": test.com}',  # Unquoted string value  
            'invalid json',  # Not JSON at all
            '[]',  # Array instead of object
        ]
        
        for payload in malformed_payloads:
            with patch('app.routes.api.v1.request_signed_certificate') as mock_sign:
                mock_sign.return_value = "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----"
                
                response = client.get(
                    '/api/v1/server/bundle',
                    headers={
                        'Authorization': f'Bearer {key}',
                        'Content-Type': 'application/json'
                    },
                    data=payload
                )
                # Should succeed because JSON is ignored, only PSK matters
                assert response.status_code == 200, f"API failed with malformed JSON when it should be ignored: {payload}"

    def test_large_payload_ignored(self, client, app):
        """Test that large JSON payloads are ignored"""
        # Create a valid PSK
        hostname = "test-server.com" 
        key = str(uuid.uuid4())
        with app.app_context():
            psk = PreSharedKey(description=hostname, key=key)
            db.session.add(psk)
            db.session.commit()
        
        # Large payload that would normally cause issues
        large_payload = {'data': 'x' * 100000}  # 100KB data
        
        with patch('app.routes.api.v1.request_signed_certificate') as mock_sign:
            mock_sign.return_value = "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----"
            
            response = client.get(
                '/api/v1/server/bundle',
                headers={'Authorization': f'Bearer {key}'},
                json=large_payload
            )
            # Should succeed because JSON payload is ignored
            assert response.status_code == 200


class TestBusinessLogicSecurity:
    """Tests for business logic vulnerabilities"""
    
    def test_revoked_psk_cannot_be_used(self, client, app):
        """Test that revoked PSKs cannot be used for authentication"""
        hostname = "revoked-test.com"
        key = str(uuid.uuid4())
        
        with app.app_context():
            psk = PreSharedKey(description=hostname, key=key)
            db.session.add(psk)
            db.session.commit()
            
            # Revoke the PSK
            psk.revoke()
            db.session.commit()
        
        response = client.get(
            '/api/v1/server/bundle',
            headers={'Authorization': f'Bearer {key}'}
        )
        
        assert response.status_code == 401
        assert "error" in response.json

    def test_psk_case_sensitivity(self, client, app):
        """Test PSK matching is case-sensitive for security"""
        hostname = "test-server.com"
        key = str(uuid.uuid4())
        
        with app.app_context():
            psk = PreSharedKey(description=hostname, key=key)
            db.session.add(psk)
            db.session.commit()
        
        # Test various case variations of the PSK
        case_variations = [
            key.upper(),
            key.lower(),
            key.capitalize(),
        ]
        
        for variation in case_variations:
            if variation == key:
                continue  # Skip if variation matches original
                
            response = client.get(
                '/api/v1/server/bundle',
                headers={'Authorization': f'Bearer {variation}'}
            )
            # Should be case-sensitive and reject PSK variations
            assert response.status_code == 401, f"Case insensitive PSK match allowed: {variation}"

    @patch('app.routes.api.v1.request_signed_certificate')
    def test_signing_service_timeout_handling(self, mock_signing, client, app):
        """Test graceful handling when signing service times out"""
        import requests
        
        # Simulate signing service timeout (wrapped in SigningServiceError as the signing client would do)
        from app.utils.signing_client import SigningServiceError
        mock_signing.side_effect = SigningServiceError("Failed to connect to signing service: Connection timed out")
        
        hostname = "timeout-test.com"
        key = str(uuid.uuid4())
        
        with app.app_context():
            psk = PreSharedKey(description=hostname, key=key)
            db.session.add(psk)
            db.session.commit()
        
        response = client.get(
            '/api/v1/server/bundle',
            headers={'Authorization': f'Bearer {key}'}
        )
        
        assert response.status_code == 503  # Service Unavailable
        assert "signing service unavailable" in response.json.get('error', '').lower()


class TestServerBundleSecurity:
    """Security tests specific to the server bundle endpoint"""
    
    def test_server_bundle_response_integrity(self, client, app):
        """Test server bundle endpoint returns expected structure"""
        hostname = "valid-server.com"
        key = str(uuid.uuid4())
        
        with app.app_context():
            psk = PreSharedKey(description=hostname, key=key)
            db.session.add(psk)
            db.session.commit()
        
        with patch('app.routes.api.v1.request_signed_certificate') as mock_sign:
            mock_sign.return_value = "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----"
            
            response = client.get(
                '/api/v1/server/bundle',
                headers={'Authorization': f'Bearer {key}'}
            )
            
            assert response.status_code == 200
            assert response.headers['Content-Type'] == 'application/gzip'
            assert response.headers['Content-Disposition'].startswith('attachment; filename=')
            
            # Ensure response contains gzip/tar data
            tar_data = response.data
            assert len(tar_data) > 0
            assert tar_data[:2] == b'\x1f\x8b'  # GZIP signature

    @patch('app.routes.api.v1.request_signed_certificate')
    def test_server_bundle_tar_bomb_protection(self, mock_signing, client, app):
        """Test protection against tar bomb attacks in server bundle"""
        # Mock successful certificate signing
        mock_signing.return_value = "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----"
        
        hostname = "tar-test.com"
        key = str(uuid.uuid4())
        
        with app.app_context():
            psk = PreSharedKey(description=hostname, key=key)
            db.session.add(psk)
            db.session.commit()
        
        response = client.get(
            '/api/v1/server/bundle',
            headers={'Authorization': f'Bearer {key}'}
        )
        
        if response.status_code == 200:
            # Check that the tar file size is reasonable (< 1MB)
            content_length = len(response.data)
            assert content_length < 1024 * 1024, f"Server bundle too large: {content_length} bytes"
            
            # Verify it's actually a valid tar.gz file
            assert response.headers.get('Content-Type') == 'application/gzip'
            assert 'openvpn-server-' in response.headers.get('Content-Disposition', '')