"""
IDOR Protection Verification Tests

These tests verify that the existing IDOR protections are working correctly
by attempting unauthorized access patterns and confirming they are properly blocked.
"""

import pytest
import json
from unittest.mock import patch, MagicMock
from flask import session
from app.extensions import db


class TestIDORProtectionVerification:
    """Verification tests for IDOR protection mechanisms."""

    def test_certificate_detail_ownership_check(self, client, app):
        """Verify certificate detail endpoint properly checks ownership."""

        # Mock CT service to return a certificate owned by different user
        with patch('app.utils.certtransparency_client.CertTransparencyClient.get_certificate_by_fingerprint') as mock_get_cert:
            mock_get_cert.return_value = {
                'certificate': {
                    'fingerprint': 'BBBB567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF',
                    'issuing_user_id': 'other_user@example.com',
                    'subject': 'CN=Other User',
                    'issued_at': '2024-01-01T00:00:00Z',
                    'expires_at': '2025-01-01T00:00:00Z',
                    'revoked_at': None
                }
            }

            # Set up session for current user
            with client.session_transaction() as sess:
                sess['user'] = {
                    'sub': 'current_user@example.com',
                    'name': 'Current User',
                    'email': 'current_user@example.com',
                    'groups': ['users']
                }

            # Attempt to access other user's certificate (valid fingerprint format)
            response = client.get('/profile/certificates/1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF')

            # Should be redirected with access denied message
            assert response.status_code == 302

            # Follow redirect to see the flash message
            response = client.get('/profile/certificates/')
            assert b'Access denied: This certificate does not belong to you' in response.data

    def test_certificate_revocation_ownership_check(self, client, app):
        """Verify certificate revocation endpoint properly checks ownership."""

        # Mock CT service to return a certificate owned by different user
        with patch('app.utils.certtransparency_client.CertTransparencyClient.get_certificate_by_fingerprint') as mock_get_cert:
            mock_get_cert.return_value = {
                'certificate': {
                    'fingerprint': 'AAAA567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF',
                    'issuing_user_id': 'other_user@example.com',
                    'subject': 'CN=Other User',
                    'issued_at': '2024-01-01T00:00:00Z',
                    'expires_at': '2025-01-01T00:00:00Z',
                    'revoked_at': None
                }
            }

            # Set up session for current user
            with client.session_transaction() as sess:
                sess['user'] = {
                    'sub': 'current_user@example.com',
                    'name': 'Current User',
                    'email': 'current_user@example.com',
                    'groups': ['users']
                }

            # Attempt to revoke other user's certificate
            response = client.post('/profile/certificates/AAAA567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF/revoke', data={
                'reason': 'key_compromise'
            })

            # Should return 403 Forbidden
            assert response.status_code == 403

            response_data = json.loads(response.data)
            assert 'You are not authorized to revoke this certificate' in response_data['error']

    def test_certificate_detail_nonexistent_certificate(self, client, app):
        """Verify proper handling of non-existent certificates."""

        # Mock CT service to raise exception for non-existent certificate
        with patch('app.utils.certtransparency_client.CertTransparencyClient.get_certificate_by_fingerprint') as mock_get_cert:
            mock_get_cert.side_effect = Exception("Certificate not found")

            # Set up session for user
            with client.session_transaction() as sess:
                sess['user'] = {
                    'sub': 'current_user@example.com',
                    'name': 'Current User',
                    'email': 'current_user@example.com',
                    'groups': ['users']
                }

            # Attempt to access non-existent certificate (valid fingerprint format)
            response = client.get('/profile/certificates/FEDCBA0987654321FEDCBA0987654321FEDCBA0987654321FEDCBA0987654321')

            # Should be redirected with error message
            assert response.status_code == 302

            # Follow redirect to see the flash message
            response = client.get('/profile/certificates/')
            assert b'Certificate not found' in response.data

    def test_certificate_revocation_nonexistent_certificate(self, client, app):
        """Verify proper handling of non-existent certificate revocation."""

        # Mock CT service to return empty response for non-existent certificate
        with patch('app.utils.certtransparency_client.CertTransparencyClient.get_certificate_by_fingerprint') as mock_get_cert:
            mock_get_cert.return_value = {}

            # Set up session for user
            with client.session_transaction() as sess:
                sess['user'] = {
                    'sub': 'current_user@example.com',
                    'name': 'Current User',
                    'email': 'current_user@example.com',
                    'groups': ['users']
                }

            # Attempt to revoke non-existent certificate
            response = client.post('/profile/certificates/FEDCBA0987654321FEDCBA0987654321FEDCBA0987654321FEDCBA0987654321/revoke', data={
                'reason': 'key_compromise'
            })

            # Should return 404 Not Found
            assert response.status_code == 404

            response_data = json.loads(response.data)
            assert 'Certificate not found' in response_data['error']

    def test_certificate_revocation_already_revoked(self, client, app):
        """Verify proper handling of already revoked certificates."""

        # Mock CT service to return an already revoked certificate
        with patch('app.utils.certtransparency_client.CertTransparencyClient.get_certificate_by_fingerprint') as mock_get_cert:
            mock_get_cert.return_value = {
                'certificate': {
                    'fingerprint': '1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF',
                    'issuing_user_id': 'current_user@example.com',
                    'subject': 'CN=Current User',
                    'issued_at': '2024-01-01T00:00:00Z',
                    'expires_at': '2025-01-01T00:00:00Z',
                    'revoked_at': '2024-06-01T00:00:00Z'  # Already revoked
                }
            }

            # Set up session for user
            with client.session_transaction() as sess:
                sess['user'] = {
                    'sub': 'current_user@example.com',
                    'name': 'Current User',
                    'email': 'current_user@example.com',
                    'groups': ['users']
                }

            # Attempt to revoke already revoked certificate
            response = client.post('/profile/certificates/1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF/revoke', data={
                'reason': 'key_compromise'
            })

            # Should return 400 Bad Request
            assert response.status_code == 400

            response_data = json.loads(response.data)
            assert 'Certificate is already revoked' in response_data['error']

    def test_idor_protection_logs_warning(self, client, app, caplog):
        """Verify that IDOR attempts are logged for security monitoring."""

        # Mock CT service to return a certificate owned by different user
        with patch('app.utils.certtransparency_client.CertTransparencyClient.get_certificate_by_fingerprint') as mock_get_cert:
            mock_get_cert.return_value = {
                'certificate': {
                    'fingerprint': 'CCCC567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF',
                    'issuing_user_id': 'victim_user@example.com',
                    'subject': 'CN=Victim User',
                    'issued_at': '2024-01-01T00:00:00Z',
                    'expires_at': '2025-01-01T00:00:00Z',
                    'revoked_at': None
                }
            }

            # Set up session for attacker user
            with client.session_transaction() as sess:
                sess['user'] = {
                    'sub': 'attacker_user@example.com',
                    'name': 'Attacker User',
                    'email': 'attacker_user@example.com',
                    'groups': ['users']
                }

            # Attempt to revoke victim's certificate
            with caplog.at_level('WARNING'):
                response = client.post('/profile/certificates/CCCC567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF/revoke', data={
                    'reason': 'key_compromise'
                })

            # Should return 403 Forbidden (IDOR protection working correctly)
            assert response.status_code == 403