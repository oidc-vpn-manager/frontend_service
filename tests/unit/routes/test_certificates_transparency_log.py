"""
Unit tests for Certificate Transparency log viewing routes.

These tests cover the transparency log viewing functionality that allows
auditors and service administrators to view the full certificate transparency log.
"""

import json
import pytest
from unittest.mock import patch, MagicMock
from flask import Flask
from app import create_app
from app.extensions import db
from app.utils.certtransparency_client import CertTransparencyClientError


class TestCertificateTransparencyViewing:
    """Unit tests for certificate transparency log viewing."""

    # Remove custom app fixture and use the one from conftest.py

    @pytest.fixture
    def auditor_session(self):
        """Mock auditor user session."""
        return {
            'user': {
                'sub': 'auditor-user-123',
                'email': 'auditor@example.com',
                'name': 'Auditor User',
                'is_auditor': True,
                'is_system_admin': False,
                'is_admin': False
            }
        }

    @pytest.fixture
    def system_admin_session(self):
        """Mock system admin user session."""
        return {
            'user': {
                'sub': 'sysadmin-user-123',
                'email': 'sysadmin@example.com',
                'name': 'System Admin User',
                'is_auditor': False,
                'is_system_admin': True,
                'is_admin': False
            }
        }

    @pytest.fixture
    def admin_session(self):
        """Mock admin user session."""
        return {
            'user': {
                'sub': 'admin-user-123',
                'email': 'admin@example.com',
                'name': 'Admin User',
                'is_auditor': False,
                'is_system_admin': False,
                'is_admin': True
            }
        }

    @pytest.fixture
    def regular_user_session(self):
        """Mock regular user session without special privileges."""
        return {
            'user': {
                'sub': 'regular-user-123',
                'email': 'user@example.com',
                'name': 'Regular User',
                'is_auditor': False,
                'is_system_admin': False,
                'is_admin': False
            }
        }

    @pytest.fixture
    def mock_certificates(self):
        """Mock certificate data."""
        return [
            {
                'fingerprint_sha256': 'abcd1234' * 8,
                'serial_number': '12345',
                'certificate_type': 'client',
                'subject': {'common_name': 'user@example.com', 'email_address': 'user@example.com'},
                'issuer': {'common_name': 'OpenVPN CA'},
                'not_before': '2025-01-01T10:00:00Z',
                'not_after': '2026-01-01T10:00:00Z',
                'revoked_at': None,
                'revocation': None,
                'logged_at': '2025-01-01T10:00:00Z',
                'issuing_user_id': 'user-123',
                'issuer_info': {
                    'request_source': '192.168.1.100',
                    'user_agent': 'Mozilla/5.0',
                    'issued_by': 'signing-service'
                }
            }
        ]

    @patch('app.routes.certificates.get_certtransparency_client')
    def test_transparency_log_auditor_access(self, mock_ct_client, app, auditor_session, mock_certificates):
        """Test that auditors can access the transparency log."""
        mock_ct_instance = MagicMock()
        mock_ct_client.return_value = mock_ct_instance
        mock_ct_instance.list_certificates.return_value = {
            'certificates': mock_certificates,
            'pagination': {'page': 1, 'pages': 1, 'total': 1},
            'filters': {}
        }
        mock_ct_instance.get_statistics.return_value = {}

        with app.test_client() as client:
            with client.session_transaction() as sess:
                sess.update(auditor_session)

            response = client.get('/certificates/')
            
            assert response.status_code == 200
            assert b'Certificate Transparency Log' in response.data
            assert b'Audit view of all certificates' in response.data
            assert b'user@example.com' in response.data

    @patch('app.routes.certificates.get_certtransparency_client')
    def test_transparency_log_system_admin_access(self, mock_ct_client, app, system_admin_session, mock_certificates):
        """Test that system admins can access the transparency log."""
        mock_ct_instance = MagicMock()
        mock_ct_client.return_value = mock_ct_instance
        mock_ct_instance.list_certificates.return_value = {
            'certificates': mock_certificates,
            'pagination': {'page': 1, 'pages': 1, 'total': 1},
            'filters': {}
        }
        mock_ct_instance.get_statistics.return_value = {}

        with app.test_client() as client:
            with client.session_transaction() as sess:
                sess.update(system_admin_session)

            response = client.get('/certificates/')
            
            assert response.status_code == 200
            assert b'Certificate Transparency Log' in response.data
            assert b'System Administrator view' in response.data

    @patch('app.routes.certificates.get_certtransparency_client')
    def test_transparency_log_admin_access(self, mock_ct_client, app, admin_session, mock_certificates):
        """Test that admins can access the transparency log."""
        mock_ct_instance = MagicMock()
        mock_ct_client.return_value = mock_ct_instance
        mock_ct_instance.list_certificates.return_value = {
            'certificates': mock_certificates,
            'pagination': {'page': 1, 'pages': 1, 'total': 1},
            'filters': {}
        }
        mock_ct_instance.get_statistics.return_value = {}

        with app.test_client() as client:
            with client.session_transaction() as sess:
                sess.update(admin_session)

            response = client.get('/certificates/')
            
            assert response.status_code == 200
            assert b'Certificate Transparency Log' in response.data

    def test_transparency_log_regular_user_denied(self, app, regular_user_session):
        """Test that regular users are denied access to the transparency log."""
        with app.test_client() as client:
            with client.session_transaction() as sess:
                sess.update(regular_user_session)

            response = client.get('/certificates/')
            
            assert response.status_code == 403

    def test_transparency_log_unauthenticated_denied(self, app):
        """Test that unauthenticated users are redirected to login."""
        with app.test_client() as client:
            response = client.get('/certificates/')
            
            assert response.status_code == 302  # Redirect to login

    @patch('app.routes.certificates.get_certtransparency_client')
    def test_transparency_log_filtering(self, mock_ct_client, app, auditor_session):
        """Test that filtering parameters are properly passed to CT client."""
        mock_ct_instance = MagicMock()
        mock_ct_client.return_value = mock_ct_instance
        mock_ct_instance.list_certificates.return_value = {
            'certificates': [],
            'pagination': {},
            'filters': {}
        }
        mock_ct_instance.get_statistics.return_value = {}

        with app.test_client() as client:
            with client.session_transaction() as sess:
                sess.update(auditor_session)

            response = client.get('/certificates/?type=client&subject=user@example.com&include_revoked=false')
            
            assert response.status_code == 200
            mock_ct_instance.list_certificates.assert_called_once()
            call_args = mock_ct_instance.list_certificates.call_args
            assert call_args[1]['type'] == 'client'
            assert call_args[1]['subject'] == 'user@example.com'
            assert call_args[1]['include_revoked'] == 'false'

    @patch('app.routes.certificates.get_certtransparency_client')
    def test_transparency_log_auditor_uncollapsed_filter(self, mock_ct_client, app, auditor_session):
        """Test that auditors can use the show_uncollapsed filter."""
        mock_ct_instance = MagicMock()
        mock_ct_client.return_value = mock_ct_instance
        mock_ct_instance.list_certificates.return_value = {
            'certificates': [],
            'pagination': {},
            'filters': {}
        }
        mock_ct_instance.get_statistics.return_value = {}

        with app.test_client() as client:
            with client.session_transaction() as sess:
                sess.update(auditor_session)

            response = client.get('/certificates/?show_uncollapsed=true')
            
            assert response.status_code == 200
            mock_ct_instance.list_certificates.assert_called_once()
            call_args = mock_ct_instance.list_certificates.call_args
            assert call_args[1]['show_uncollapsed'] == 'true'

    @patch('app.routes.certificates.get_certtransparency_client')
    def test_transparency_log_non_auditor_no_uncollapsed_filter(self, mock_ct_client, app, system_admin_session):
        """Test that non-auditors cannot use the show_uncollapsed filter."""
        mock_ct_instance = MagicMock()
        mock_ct_client.return_value = mock_ct_instance
        mock_ct_instance.list_certificates.return_value = {
            'certificates': [],
            'pagination': {},
            'filters': {}
        }
        mock_ct_instance.get_statistics.return_value = {}

        with app.test_client() as client:
            with client.session_transaction() as sess:
                sess.update(system_admin_session)

            response = client.get('/certificates/?show_uncollapsed=true')
            
            assert response.status_code == 200
            mock_ct_instance.list_certificates.assert_called_once()
            call_args = mock_ct_instance.list_certificates.call_args
            assert 'show_uncollapsed' not in call_args[1]

    @patch('app.routes.certificates.get_certtransparency_client')
    def test_transparency_log_ct_service_error(self, mock_ct_client, app, auditor_session):
        """Test handling of Certificate Transparency service errors."""
        mock_ct_instance = MagicMock()
        mock_ct_client.return_value = mock_ct_instance
        mock_ct_instance.list_certificates.side_effect = CertTransparencyClientError("Service unavailable")
        mock_ct_instance.get_statistics.return_value = {}

        with app.test_client() as client:
            with client.session_transaction() as sess:
                sess.update(auditor_session)

            response = client.get('/certificates/')
            
            assert response.status_code == 200  # Should render with error message
            assert b'Unable to fetch certificates' in response.data

    @patch('app.routes.certificates.get_certtransparency_client')
    def test_certificate_detail_auditor_access(self, mock_ct_client, app, auditor_session):
        """Test that auditors can access certificate detail pages."""
        mock_ct_instance = MagicMock()
        mock_ct_client.return_value = mock_ct_instance
        mock_ct_instance.get_certificate_by_fingerprint.return_value = {
            'certificate': {
                'fingerprint_sha256': 'abcd1234' * 8,
                'subject': {'common_name': 'user@example.com'},
                'certificate_type': 'client'
            }
        }

        with app.test_client() as client:
            with client.session_transaction() as sess:
                sess.update(auditor_session)

            response = client.get('/certificates/abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234')
            
            assert response.status_code == 200
            assert b'Certificate Details' in response.data
            assert b'user@example.com' in response.data

    def test_certificate_detail_regular_user_denied(self, app, regular_user_session):
        """Test that regular users are denied access to certificate details."""
        with app.test_client() as client:
            with client.session_transaction() as sess:
                sess.update(regular_user_session)

            response = client.get('/certificates/abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234')
            
            assert response.status_code == 403

    @patch('app.routes.certificates.get_certtransparency_client')
    def test_certificate_detail_not_found(self, mock_ct_client, app, auditor_session):
        """Test handling of certificate not found in detail view."""
        mock_ct_instance = MagicMock()
        mock_ct_client.return_value = mock_ct_instance
        mock_ct_instance.get_certificate_by_fingerprint.return_value = {'certificate': None}

        with app.test_client() as client:
            with client.session_transaction() as sess:
                sess.update(auditor_session)

            response = client.get('/certificates/nonexistent1234567890abcdef1234567890abcdef1234567890abcdef1234567890')
            
            assert response.status_code == 404

    @patch('app.routes.certificates.get_certtransparency_client')
    def test_transparency_log_pagination(self, mock_ct_client, app, auditor_session):
        """Test pagination parameters are handled correctly."""
        mock_ct_instance = MagicMock()
        mock_ct_client.return_value = mock_ct_instance
        mock_ct_instance.list_certificates.return_value = {
            'certificates': [],
            'pagination': {'page': 2, 'pages': 5, 'total': 100, 'has_prev': True, 'has_next': True, 'prev_num': 1, 'next_num': 3},
            'filters': {}
        }
        mock_ct_instance.get_statistics.return_value = {}

        with app.test_client() as client:
            with client.session_transaction() as sess:
                sess.update(auditor_session)

            response = client.get('/certificates/?page=2&limit=20')
            
            assert response.status_code == 200
            assert b'Page 2 of 5' in response.data
            mock_ct_instance.list_certificates.assert_called_once()
            call_args = mock_ct_instance.list_certificates.call_args
            assert call_args[1]['page'] == 2
            assert call_args[1]['limit'] == 20

    @patch('app.routes.certificates.get_certtransparency_client')
    def test_transparency_log_role_based_columns(self, mock_ct_client, app, auditor_session, mock_certificates):
        """Test that role-specific columns are shown correctly."""
        mock_ct_instance = MagicMock()
        mock_ct_client.return_value = mock_ct_instance
        mock_ct_instance.list_certificates.return_value = {
            'certificates': mock_certificates,
            'pagination': {},
            'filters': {}
        }
        mock_ct_instance.get_statistics.return_value = {}

        with app.test_client() as client:
            with client.session_transaction() as sess:
                sess.update(auditor_session)

            response = client.get('/certificates/')
            
            assert response.status_code == 200
            # Auditors should see request info column
            assert b'Request Info' in response.data
            assert b'IP: 192.168.1.100' in response.data
            # But not user ID column (that's for system admins)
            assert b'User ID' not in response.data

    @patch('app.routes.certificates.get_certtransparency_client')
    def test_transparency_log_with_filter_parameters_coverage(self, mock_ct_client, app, auditor_session, mock_certificates):
        """Test transparency log with specific filter parameters to hit missing coverage lines."""
        mock_ct_instance = MagicMock()
        mock_ct_client.return_value = mock_ct_instance
        mock_ct_instance.list_certificates.return_value = {
            'certificates': mock_certificates,
            'pagination': {'page': 1, 'pages': 1, 'total': 1},
            'filters': {}
        }
        mock_ct_instance.get_statistics.return_value = {}

        with app.test_client() as client:
            with client.session_transaction() as sess:
                sess.update(auditor_session)

            # Test with filters to hit lines 37, 39, 41, 52, 54
            response = client.get('/certificates/?issuer=example-ca&from_date=2025-01-01&to_date=2025-12-31&sort=issued_at&order=desc')
            
            assert response.status_code == 200
            # Verify the filter parameters were passed correctly
            call_args = mock_ct_instance.list_certificates.call_args
            assert 'issuer' in call_args[1]
            assert 'from_date' in call_args[1] 
            assert 'to_date' in call_args[1]
            assert 'sort' in call_args[1]
            assert 'order' in call_args[1]

    @patch('app.routes.certificates.get_certtransparency_client')
    def test_transparency_log_stats_exception_coverage(self, mock_ct_client, app, auditor_session, mock_certificates):
        """Test statistics exception handling to hit lines 69-71."""
        mock_ct_instance = MagicMock()
        mock_ct_client.return_value = mock_ct_instance
        mock_ct_instance.list_certificates.return_value = {
            'certificates': mock_certificates,
            'pagination': {'page': 1, 'pages': 1, 'total': 1},
            'filters': {}
        }
        # Make get_statistics raise an exception to hit the exception handling
        mock_ct_instance.get_statistics.side_effect = CertTransparencyClientError("Stats unavailable")

        with app.test_client() as client:
            with client.session_transaction() as sess:
                sess.update(auditor_session)

            response = client.get('/certificates/')
            
            assert response.status_code == 200
            # Should still render the page successfully with empty stats
            assert b'Certificate Transparency Log' in response.data

    @patch('app.routes.certificates.get_certtransparency_client')
    def test_certificate_detail_exception_coverage(self, mock_ct_client, app, auditor_session):
        """Test certificate detail exception handling to hit lines 122-124."""
        mock_ct_instance = MagicMock()
        mock_ct_client.return_value = mock_ct_instance
        # Make the method raise an exception to hit exception handling
        mock_ct_instance.get_certificate_by_fingerprint.side_effect = CertTransparencyClientError("Service error")

        with app.test_client() as client:
            with client.session_transaction() as sess:
                sess.update(auditor_session)

            response = client.get('/certificates/1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF')
            
            assert response.status_code == 500
            # Should render error page (exact content may vary based on template)

    @patch('app.routes.certificates.get_certtransparency_client')
    def test_transparency_log_invalid_page_parameter_valueerror(self, mock_ct_client, app, auditor_session):
        """Test transparency log with invalid page parameter causing ValueError - lines 33-34."""
        mock_ct_instance = MagicMock()
        mock_ct_client.return_value = mock_ct_instance
        mock_ct_instance.list_certificates.return_value = {
            'certificates': [],
            'pagination': {'page': 1, 'pages': 0, 'total': 0},
            'filters': {}
        }
        mock_ct_instance.get_statistics.return_value = {}

        with app.test_client() as client:
            with client.session_transaction() as sess:
                sess.update(auditor_session)

            # Test with invalid page parameter that causes ValueError when converted to int
            response = client.get('/certificates/?page=invalid_number')

            assert response.status_code == 200
            # Should default to page 1 due to exception handling
            call_args = mock_ct_instance.list_certificates.call_args
            assert call_args[1]['page'] == 1  # Should default to 1 despite invalid input

    @patch('app.routes.certificates.get_certtransparency_client')
    def test_transparency_log_invalid_limit_parameter_typeerror(self, mock_ct_client, app, auditor_session):
        """Test transparency log with invalid limit parameter causing TypeError - lines 38-39."""
        mock_ct_instance = MagicMock()
        mock_ct_client.return_value = mock_ct_instance
        mock_ct_instance.list_certificates.return_value = {
            'certificates': [],
            'pagination': {'page': 1, 'pages': 0, 'total': 0},
            'filters': {}
        }
        mock_ct_instance.get_statistics.return_value = {}

        with app.test_client() as client:
            with client.session_transaction() as sess:
                sess.update(auditor_session)

            # Test with limit parameter that causes TypeError when converted to int
            response = client.get('/certificates/?limit=not_a_number')

            assert response.status_code == 200
            # Should default to limit 50 due to exception handling
            call_args = mock_ct_instance.list_certificates.call_args
            assert call_args[1]['limit'] == 50  # Should default to 50 despite invalid input

    @patch('app.routes.certificates.get_certtransparency_client')
    def test_certificate_detail_certificate_not_found_with_logging(self, mock_ct_client, app, auditor_session):
        """Test certificate detail when certificate is not found with warning logging - lines 128-129."""
        mock_ct_instance = MagicMock()
        mock_ct_client.return_value = mock_ct_instance
        # Mock response where certificate is None (not just missing key)
        mock_ct_instance.get_certificate_by_fingerprint.return_value = {'certificate': None}

        # Mock the Flask app logger to capture the warning call
        with patch.object(app.logger, 'warning') as mock_warning:
            with app.test_client() as client:
                with client.session_transaction() as sess:
                    sess.update(auditor_session)

                # Use a valid SHA256 fingerprint format (64 hex characters, all hex digits)
                valid_fingerprint = 'AAAAAAAA1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF12345678'
                response = client.get(f'/certificates/{valid_fingerprint}')

                # Should return 404 status and custom 404 template
                assert response.status_code == 404

                # Should have called warning with the specific message (line 128)
                mock_warning.assert_called_once_with(f'Certificate not found: {valid_fingerprint}')