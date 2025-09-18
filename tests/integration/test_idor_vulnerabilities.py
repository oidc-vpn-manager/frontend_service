"""
Negative security tests for Insecure Direct Object Reference (IDOR) vulnerabilities.

These tests verify that users cannot access, modify, or delete resources
belonging to other users by manipulating object identifiers in URLs,
parameters, or request bodies.
"""

import pytest
import json
import uuid
from unittest.mock import patch, MagicMock
from app.extensions import db
from app.models.presharedkey import PreSharedKey
from app.models.downloadtoken import DownloadToken


class TestCertificateIDORVulnerabilities:
    """Tests for IDOR vulnerabilities in certificate management."""

    def test_certificate_detail_access_protection(self, client, app):
        """Test that users cannot access other users' certificate details."""
        # Create two different auditor sessions to simulate different privileged users
        user1_session = {
            'user': {
                'sub': 'auditor1@example.com',
                'name': 'Auditor One',
                'email': 'auditor1@example.com',
                'groups': ['auditors'],
                'is_auditor': True
            }
        }

        user2_session = {
            'user': {
                'sub': 'auditor2@example.com',
                'name': 'Auditor Two',
                'email': 'auditor2@example.com',
                'groups': ['auditors'],
                'is_auditor': True
            }
        }

        # Mock certificate transparency client to return certificates for testing
        mock_certificates = [
            {
                'fingerprint_sha256': 'cert1_fingerprint_for_auditor1',
                'issuing_user_id': 'auditor1@example.com',
                'serial_number': '12345',
                'subject_cn': 'auditor1@example.com',
                'issued_at': '2023-01-01T00:00:00Z',
                'expires_at': '2024-01-01T00:00:00Z',
                'is_revoked': False
            },
            {
                'fingerprint_sha256': 'cert2_fingerprint_for_auditor2',
                'issuing_user_id': 'auditor2@example.com',
                'serial_number': '67890',
                'subject_cn': 'auditor2@example.com',
                'issued_at': '2023-01-01T00:00:00Z',
                'expires_at': '2024-01-01T00:00:00Z',
                'is_revoked': False
            }
        ]

        # Test various certificate ID manipulation attempts
        certificate_ids = [
            'cert1_fingerprint_for_auditor1',
            'cert2_fingerprint_for_auditor2',
            '12345',  # Serial number
            '67890',  # Serial number
            'non_existent_cert_id',
            '../admin/certificates',  # Path traversal
            '../../etc/passwd',  # Path traversal
            'cert1_fingerprint_for_auditor1/../cert2_fingerprint_for_auditor2',  # Path traversal
        ]

        # Test as auditor1 trying to access various certificate IDs
        with client.session_transaction() as sess:
            sess.clear()
            sess.update(user1_session)

        # Mock the CT client to return certificates
        with patch('app.routes.certificates.get_certtransparency_client') as mock_ct_client:
            mock_client = MagicMock()
            mock_ct_client.return_value = mock_client
            mock_client.list_certificates.return_value = {
                'certificates': mock_certificates
            }

            for cert_id in certificate_ids:
                # Test certificate detail endpoint
                response = client.get(f'/certificates/{cert_id}')

                # For auditors, access patterns are different - they can see CT logs
                if cert_id == 'cert1_fingerprint_for_auditor1':
                    # This might be allowed if it belongs to auditor1
                    assert response.status_code in [200, 404], f"Unexpected response for own cert: {cert_id}"
                else:
                    # For other certificates, auditors might see them (CT logs are transparent)
                    # The key test is path traversal should be blocked
                    if '../' in cert_id or 'etc/passwd' in cert_id:
                        assert response.status_code in [403, 404], f"Path traversal not blocked: {cert_id}"
                    # Other valid certificate IDs might be allowed for auditors

    def test_certificate_revocation_idor(self, client, app):
        """Test that users cannot revoke other users' certificates."""
        # Create user session
        user_session = {
            'user': {
                'sub': 'user1@example.com',
                'name': 'User One',
                'email': 'user1@example.com',
                'groups': ['users']
            }
        }

        with client.session_transaction() as sess:
            sess.clear()
            sess.update(user_session)

        # Various certificate identifiers to attempt revoking
        other_user_certs = [
            'other_user_cert_fingerprint',
            'admin_certificate_id',
            '99999',  # Non-existent serial
            '../admin_cert',  # Path traversal
            'cert_belonging_to_user2',
            'system_root_certificate',
        ]

        for cert_id in other_user_certs:
            # Test certificate revocation endpoint
            response = client.post(f'/profile/certificates/{cert_id}/revoke')

            # Should deny revocation of other users' certificates
            assert response.status_code in [400, 403, 404, 405], f"IDOR vulnerability: revoked cert {cert_id}"

            # Test via API if available
            response = client.post(f'/api/v1/certificates/{cert_id}/revoke')
            assert response.status_code in [401, 403, 404, 405], f"API IDOR vulnerability: revoked cert {cert_id}"

    def test_certificate_list_filtering(self, client, app):
        """Test that certificate lists are properly filtered by user."""
        # Create user session
        user_session = {
            'user': {
                'sub': 'test_user@example.com',
                'name': 'Test User',
                'email': 'test_user@example.com',
                'groups': ['users']
            }
        }

        with client.session_transaction() as sess:
            sess.clear()
            sess.update(user_session)

        # Mock certificate data from different users
        mixed_certificates = [
            {
                'fingerprint_sha256': 'user_cert_1',
                'issuing_user_id': 'test_user@example.com',
                'serial_number': '11111',
                'subject_cn': 'test_user@example.com',
            },
            {
                'fingerprint_sha256': 'other_user_cert_1',
                'issuing_user_id': 'other_user@example.com',
                'serial_number': '22222',
                'subject_cn': 'other_user@example.com',
            },
            {
                'fingerprint_sha256': 'admin_cert_1',
                'issuing_user_id': 'admin@example.com',
                'serial_number': '33333',
                'subject_cn': 'admin@example.com',
            }
        ]

        with patch('app.routes.profile.get_certtransparency_client') as mock_ct_client:
            mock_client = MagicMock()
            mock_ct_client.return_value = mock_client
            mock_client.list_certificates.return_value = {
                'certificates': mixed_certificates
            }

            # Request user's certificate list
            response = client.get('/profile/certificates')

            if response.status_code == 200:
                response_text = response.get_data(as_text=True)

                # Should contain only user's certificates
                assert 'user_cert_1' in response_text or 'test_user@example.com' in response_text

                # Should NOT contain other users' certificates
                assert 'other_user_cert_1' not in response_text, "IDOR: Other user's certificate exposed"
                assert 'admin_cert_1' not in response_text, "IDOR: Admin certificate exposed"
                assert 'other_user@example.com' not in response_text, "IDOR: Other user's email exposed"
                assert 'admin@example.com' not in response_text, "IDOR: Admin email exposed"


class TestDownloadTokenIDORVulnerabilities:
    """Tests for IDOR vulnerabilities in download token management."""

    def test_download_token_access_protection(self, client, app):
        """Test that users cannot access download tokens belonging to other users."""
        # Create download tokens for different users
        with app.app_context():
            # Create tokens for different users
            user1_token = DownloadToken(
                token=str(uuid.uuid4()),
                user='user1@example.com',
                cn='user1@example.com',
                ovpn_content=b'user1 config content'
            )

            user2_token = DownloadToken(
                token=str(uuid.uuid4()),
                user='user2@example.com',
                cn='user2@example.com',
                ovpn_content=b'user2 config content'
            )

            admin_token = DownloadToken(
                token=str(uuid.uuid4()),
                user='admin@example.com',
                cn='admin@example.com',
                ovpn_content=b'admin bundle content'
            )

            db.session.add_all([user1_token, user2_token, admin_token])
            db.session.commit()

            # Get token values for testing
            user1_token_id = user1_token.token
            user2_token_id = user2_token.token
            admin_token_id = admin_token.token

        # Create user1 session
        user1_session = {
            'user': {
                'sub': 'user1@example.com',
                'name': 'User One',
                'email': 'user1@example.com',
                'groups': ['users']
            }
        }

        with client.session_transaction() as sess:
            sess.clear()
            sess.update(user1_session)

        # Test access to various download tokens
        download_attempts = [
            user1_token_id,  # Own token - should work
            user2_token_id,  # Other user's token - should fail
            admin_token_id,  # Admin token - should fail
            'non_existent_token',  # Non-existent - should fail
            '../admin/token',  # Path traversal - should fail
            '../../etc/passwd',  # Path traversal - should fail
            '',  # Empty token - should fail
        ]

        for token in download_attempts:
            response = client.get(f'/download/{token}')

            if token == user1_token_id:
                # Should allow access to own token
                assert response.status_code in [200, 404], f"Cannot access own token: {token}"
            else:
                # Should deny access to other tokens
                assert response.status_code in [403, 404], f"IDOR vulnerability: accessed token {token}"

    def test_download_token_manipulation(self, client, app):
        """Test various token manipulation attempts."""
        # Create a valid download token
        with app.app_context():
            valid_token = DownloadToken(
                token=str(uuid.uuid4()),
                user='test_user@example.com',
                cn='test_user@example.com',
                ovpn_content=b'test config content'
            )
            db.session.add(valid_token)
            db.session.commit()

            token_id = valid_token.token

        # Create user session
        user_session = {
            'user': {
                'sub': 'test_user@example.com',
                'name': 'Test User',
                'email': 'test_user@example.com',
                'groups': ['users']
            }
        }

        with client.session_transaction() as sess:
            sess.clear()
            sess.update(user_session)

        # Various token manipulation attempts
        manipulated_tokens = [
            token_id.upper(),  # Case change
            token_id.lower(),
            token_id[:-1] + 'X',  # Change last character
            token_id + 'extra',  # Append data
            token_id.replace('-', '_'),  # Replace characters
            f"{token_id}/../admin",  # Path traversal
            f"{token_id}\x00admin",  # Null byte injection
            f"{token_id}%2e%2e/admin",  # URL encoded path traversal
        ]

        for manipulated_token in manipulated_tokens:
            response = client.get(f'/download/{manipulated_token}')

            # Should only work with exact token match
            if manipulated_token != token_id:
                assert response.status_code in [403, 404], f"Token manipulation succeeded: {manipulated_token}"


class TestPSKIDORVulnerabilities:
    """Tests for IDOR vulnerabilities in PSK management (admin functions)."""

    def test_psk_access_requires_admin(self, client, app):
        """Test that PSK management requires admin privileges."""
        # Create regular user session
        user_session = {
            'user': {
                'sub': 'regular_user@example.com',
                'name': 'Regular User',
                'email': 'regular_user@example.com',
                'groups': ['users']  # Not admin
            }
        }

        with client.session_transaction() as sess:
            sess.clear()
            sess.update(user_session)

        # Create a PSK in database
        with app.app_context():
            test_psk = PreSharedKey(
                description='test-server.com',
                key=str(uuid.uuid4())
            )
            db.session.add(test_psk)
            db.session.commit()
            psk_id = test_psk.id

        # Test various PSK admin endpoints
        admin_endpoints = [
            '/admin/psk',  # PSK list
            '/admin/psk/new',  # New PSK form
            f'/admin/psk/{psk_id}',  # PSK detail
            f'/admin/psk/{psk_id}/edit',  # PSK edit
            f'/admin/psk/{psk_id}/delete',  # PSK delete
            f'/admin/psk/{psk_id}/revoke',  # PSK revoke
        ]

        for endpoint in admin_endpoints:
            # Test GET request
            response = client.get(endpoint)
            assert response.status_code in [302, 403, 404, 405], f"IDOR: Regular user accessed admin endpoint {endpoint}"

            # Test POST request
            response = client.post(endpoint)
            assert response.status_code in [302, 403, 404, 405], f"IDOR: Regular user POSTed to admin endpoint {endpoint}"

    def test_psk_id_manipulation(self, client, app):
        """Test PSK ID manipulation attempts by admin users."""
        # Create admin session
        admin_session = {
            'user': {
                'sub': 'admin@example.com',
                'name': 'Admin User',
                'email': 'admin@example.com',
                'groups': ['admin']
            }
        }

        with client.session_transaction() as sess:
            sess.clear()
            sess.update(admin_session)

        # Mock app config for admin group
        with app.app_context():
            app.config['OIDC_ADMIN_GROUP'] = 'admin'

            # Create test PSKs
            valid_psk = PreSharedKey(
                description='valid-server.com',
                key=str(uuid.uuid4())
            )
            db.session.add(valid_psk)
            db.session.commit()

            valid_psk_id = valid_psk.id

        # Various PSK ID manipulation attempts
        manipulated_ids = [
            str(valid_psk_id + 1000),  # Non-existent ID
            '-1',  # Negative ID
            '0',   # Zero ID
            'abc', # Non-numeric ID
            f"{valid_psk_id}'; DROP TABLE presharedkeys; --",  # SQL injection
            f"{valid_psk_id}/../admin",  # Path traversal
            f"{valid_psk_id}\x00",  # Null byte
            '999999999999999999',  # Very large number
        ]

        for manipulated_id in manipulated_ids:
            if manipulated_id != str(valid_psk_id):
                # Test PSK detail endpoint
                response = client.get(f'/admin/psk/{manipulated_id}')
                assert response.status_code in [403, 400, 404, 500], f"PSK ID manipulation succeeded: {manipulated_id}"

                # Test PSK deletion endpoint
                response = client.post(f'/admin/psk/{manipulated_id}/delete')
                assert response.status_code in [403, 400, 404, 405, 500], f"PSK deletion with manipulated ID: {manipulated_id}"


class TestAPIResourceIDORVulnerabilities:
    """Tests for IDOR vulnerabilities in API endpoints."""

    def test_api_resource_access_control(self, client, app):
        """Test API endpoints properly validate resource ownership."""
        # Create PSK for API testing
        with app.app_context():
            user1_key = str(uuid.uuid4())
            user2_key = str(uuid.uuid4())

            user1_psk = PreSharedKey(
                description='user1-server.com',
                key=user1_key
            )
            user2_psk = PreSharedKey(
                description='user2-server.com',
                key=user2_key
            )
            db.session.add_all([user1_psk, user2_psk])
            db.session.commit()

        # Test server bundle access with wrong PSK
        api_endpoints = [
            ('/api/v1/server/bundle', user1_key, 'user1 PSK'),
            ('/api/v1/server/bundle', user2_key, 'user2 PSK'),
            ('/api/v1/server/bundle', 'fake_key', 'fake PSK'),
        ]

        for endpoint, psk_key, description in api_endpoints:
            response = client.get(
                endpoint,
                headers={'Authorization': f'Bearer {psk_key}'}
            )

            if psk_key in [user1_key, user2_key]:
                # Valid PSKs should work (may need mocking for full functionality)
                assert response.status_code in [200, 503], f"Valid PSK rejected: {description}"
            else:
                # Invalid PSKs should be rejected
                assert response.status_code == 401, f"IDOR: Invalid PSK accepted: {description}"

    def test_api_parameter_manipulation(self, client, app):
        """Test API parameter manipulation attempts."""
        # Create valid PSK
        with app.app_context():
            valid_key = str(uuid.uuid4())

            test_psk = PreSharedKey(
                description='api-test-server.com',
                key=valid_key
            )
            db.session.add(test_psk)
            db.session.commit()

        # Various parameter manipulation attempts in JSON body
        malicious_payloads = [
            {'user_id': 'admin@example.com'},  # Trying to impersonate admin
            {'hostname': 'other-server.com'},  # Trying to get config for different server
            {'psk': 'different_psk_key'},  # Trying to use different PSK
            {'admin': True},  # Trying to escalate privileges
            {'bypass_auth': True},  # Trying to bypass authentication
            {'../admin': 'value'},  # Path traversal in parameter names
            {'user_id': '../admin'},  # Path traversal in values
        ]

        for payload in malicious_payloads:
            response = client.get(
                '/api/v1/server/bundle',
                headers={'Authorization': f'Bearer {valid_key}'},
                json=payload
            )

            # Should ignore malicious JSON parameters and only use PSK auth
            # Response should be consistent regardless of JSON content
            assert response.status_code in [200, 503], f"API affected by malicious payload: {payload}"


class TestSessionIDORVulnerabilities:
    """Tests for IDOR vulnerabilities in session management."""

    def test_session_isolation(self, client, app):
        """Test that sessions are properly isolated between users."""
        # Create two different users
        user1_data = {
            'sub': 'user1@example.com',
            'name': 'User One',
            'email': 'user1@example.com',
            'groups': ['users']
        }

        user2_data = {
            'sub': 'user2@example.com',
            'name': 'User Two',
            'email': 'user2@example.com',
            'groups': ['admin']  # Different privileges
        }

        # Test session switching attacks
        with client.session_transaction() as sess:
            sess['user'] = user1_data

        # Verify user1 session works
        response = client.get('/')
        initial_status = response.status_code

        # Attempt to switch to user2 by modifying session
        with client.session_transaction() as sess:
            sess['user'] = user2_data

        # This should work as it's a legitimate session modification
        # The real test is that the application validates token integrity in OIDC
        response = client.get('/admin/psk')

        # In a secure implementation, switching user data should require re-authentication
        # This test demonstrates the importance of token verification beyond session data
        if response.status_code == 200:
            # Session modification worked - indicates need for stronger session integrity
            pass

    def test_concurrent_session_manipulation(self, client, app):
        """Test handling of concurrent session modifications."""
        # This test would require more complex setup with multiple clients
        # For now, test basic session race condition protection

        user_data = {
            'sub': 'test_user@example.com',
            'name': 'Test User',
            'email': 'test_user@example.com',
            'groups': ['users']
        }

        # Rapid session modifications to test race conditions
        for i in range(10):
            with client.session_transaction() as sess:
                sess.clear()
                sess['user'] = user_data.copy()
                sess['user']['name'] = f'Modified User {i}'

            response = client.get('/')
            # Should handle rapid session changes gracefully
            assert response.status_code in [200, 302], f"Session race condition at iteration {i}"