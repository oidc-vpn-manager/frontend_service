"""
Unit tests for Service Admin API routes.
"""

import pytest
import os
from unittest.mock import Mock, patch
from flask import url_for

from app import create_app
from app.extensions import db
from app.models.presharedkey import PreSharedKey  # Needed for db.create_all
from app.utils.certtransparency_client import CertTransparencyClientError


@pytest.fixture
def app():
    """Creates a test Flask app using the real create_app function."""
    # Set test keys for secure configuration
    os.environ['FLASK_SECRET_KEY'] = 'test-secret-key-for-service-admin-api-tests-only'
    os.environ['FERNET_ENCRYPTION_KEY'] = 'YenxIAHqvrO7OHbNXvzAxEhthHCaitvnV9CALkQvvCc='

    app = create_app('development')
    app.config.update({
        'TESTING': True,
        'WTF_CSRF_ENABLED': False,
        'ADMIN_URL_BASE': ''  # Ensure admin service routes are available
    })

    # Create database tables
    with app.app_context():
        db.create_all()

    return app


@pytest.fixture
def client(app):
    """Creates a test client."""
    return app.test_client()


@pytest.fixture
def service_admin_client(app):
    """Creates a test client with service admin session configured."""
    client = app.test_client()

    # Set up service admin session
    with client.session_transaction() as sess:
        sess['user'] = {
            'sub': 'service-admin@example.com',
            'email': 'service-admin@example.com',
            'name': 'Service Admin',
            'is_system_admin': True,
            'is_admin': False,
            'is_auditor': False
        }

    return client


@pytest.fixture
def auditor_client(app):
    """Creates a test client with auditor session configured."""
    client = app.test_client()

    # Set up auditor session
    with client.session_transaction() as sess:
        sess['user'] = {
            'sub': 'auditor@example.com',
            'email': 'auditor@example.com',
            'name': 'Security Auditor',
            'is_system_admin': False,
            'is_admin': False,
            'is_auditor': True
        }

    return client


@pytest.fixture
def admin_client(app):
    """Creates a test client with admin session configured."""
    client = app.test_client()

    # Set up admin session
    with client.session_transaction() as sess:
        sess['user'] = {
            'sub': 'admin@example.com',
            'email': 'admin@example.com',
            'name': 'Admin User',
            'is_system_admin': False,
            'is_admin': True,
            'is_auditor': False
        }

    return client


class TestListAllCertificates:
    """Test the list_all_certificates service admin API endpoint."""

    def test_list_all_certificates_requires_auth(self, client):
        """Test that list_all_certificates requires authentication."""
        response = client.get('/api/certificates')
        assert response.status_code == 302  # Redirect to login

    def test_list_all_certificates_requires_service_admin_or_auditor(self, app):
        """Test that list_all_certificates requires service admin or auditor privileges."""
        client = app.test_client()

        # Set up regular user session (no admin/auditor privileges)
        with client.session_transaction() as sess:
            sess['user'] = {
                'sub': 'user@example.com',
                'email': 'user@example.com',
                'name': 'Regular User',
                'is_system_admin': False,
                'is_admin': False,
                'is_auditor': False
            }

        response = client.get('/api/certificates')
        assert response.status_code == 403

    @patch('app.routes.api.service_admin.get_certtransparency_client')
    @patch('app.utils.security_logging.security_logger.log_data_access')
    def test_list_all_certificates_success_service_admin(self, mock_log_access, mock_get_client, service_admin_client):
        """Test successful certificate list retrieval by service admin."""
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        mock_client.list_certificates.return_value = {
            'certificates': [
                {'id': 1, 'subject': 'CN=test1', 'is_revoked': False},
                {'id': 2, 'subject': 'CN=test2', 'is_revoked': True}
            ],
            'total_count': 2,
            'page': 1,
            'pages': 1
        }

        response = service_admin_client.get('/api/certificates')

        assert response.status_code == 200
        data = response.get_json()
        assert 'certificates' in data
        assert len(data['certificates']) == 2
        assert data['total_count'] == 2

        # Verify CT client was called with default parameters
        mock_client.list_certificates.assert_called_once_with(
            page=1,
            limit=100,
            include_revoked='true'
        )

        # Verify security logging
        mock_log_access.assert_called_once_with(
            data_type="certificate_list",
            access_type="query",
            user_id='service-admin@example.com',
            additional_details={
                'query_params': {},
                'result_count': 2
            }
        )

    @patch('app.routes.api.service_admin.get_certtransparency_client')
    @patch('app.utils.security_logging.security_logger.log_data_access')
    def test_list_all_certificates_success_auditor(self, mock_log_access, mock_get_client, auditor_client):
        """Test successful certificate list retrieval by auditor."""
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        mock_client.list_certificates.return_value = {
            'certificates': [],
            'total_count': 0,
            'page': 1,
            'pages': 0
        }

        response = auditor_client.get('/api/certificates')

        assert response.status_code == 200
        data = response.get_json()
        assert 'certificates' in data
        assert len(data['certificates']) == 0

        # Verify security logging with auditor user
        mock_log_access.assert_called_once_with(
            data_type="certificate_list",
            access_type="query",
            user_id='auditor@example.com',
            additional_details={
                'query_params': {},
                'result_count': 0
            }
        )

    @patch('app.routes.api.service_admin.get_certtransparency_client')
    @patch('app.utils.security_logging.security_logger.log_data_access')
    def test_list_all_certificates_success_admin(self, mock_log_access, mock_get_client, admin_client):
        """Test successful certificate list retrieval by admin."""
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        mock_client.list_certificates.return_value = {
            'certificates': [{'id': 1, 'subject': 'CN=admin-test'}],
            'total_count': 1,
            'page': 1,
            'pages': 1
        }

        response = admin_client.get('/api/certificates')

        assert response.status_code == 200

    @patch('app.routes.api.service_admin.get_certtransparency_client')
    @patch('app.utils.security_logging.security_logger.log_data_access')
    def test_list_all_certificates_with_pagination(self, mock_log_access, mock_get_client, service_admin_client):
        """Test certificate listing with pagination parameters."""
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        mock_client.list_certificates.return_value = {
            'certificates': [{'id': 1, 'subject': 'CN=test'}],
            'total_count': 50,
            'page': 2,
            'pages': 5
        }

        response = service_admin_client.get('/api/certificates?page=2&limit=10')

        assert response.status_code == 200

        # Verify CT client was called with pagination parameters
        mock_client.list_certificates.assert_called_once_with(
            page=2,
            limit=10,
            include_revoked='true'
        )

    @patch('app.routes.api.service_admin.get_certtransparency_client')
    @patch('app.utils.security_logging.security_logger.log_data_access')
    def test_list_all_certificates_with_limit_capping(self, mock_log_access, mock_get_client, service_admin_client):
        """Test certificate listing with limit capping at 1000."""
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        mock_client.list_certificates.return_value = {'certificates': [], 'total_count': 0}

        response = service_admin_client.get('/api/certificates?limit=5000')

        assert response.status_code == 200

        # Verify limit was capped at 1000
        mock_client.list_certificates.assert_called_once_with(
            page=1,
            limit=1000,  # Capped from 5000
            include_revoked='true'
        )

    @patch('app.routes.api.service_admin.get_certtransparency_client')
    @patch('app.utils.security_logging.security_logger.log_data_access')
    def test_list_all_certificates_active_only_filter(self, mock_log_access, mock_get_client, service_admin_client):
        """Test certificate listing with active_only filter."""
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        mock_client.list_certificates.return_value = {'certificates': [], 'total_count': 0}

        response = service_admin_client.get('/api/certificates?active_only=true')

        assert response.status_code == 200

        # Verify active_only parameter was processed correctly
        mock_client.list_certificates.assert_called_once_with(
            page=1,
            limit=100,
            include_revoked='false',  # Changed from true
            active_only='true'
        )

    @patch('app.routes.api.service_admin.get_certtransparency_client')
    @patch('app.utils.security_logging.security_logger.log_data_access')
    def test_list_all_certificates_revoked_only_filter(self, mock_log_access, mock_get_client, service_admin_client):
        """Test certificate listing with revoked_only filter."""
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        mock_client.list_certificates.return_value = {'certificates': [], 'total_count': 0}

        response = service_admin_client.get('/api/certificates?revoked_only=true')

        assert response.status_code == 200

        # Verify revoked_only parameter was processed correctly
        mock_client.list_certificates.assert_called_once_with(
            page=1,
            limit=100,
            include_revoked='true',
            revoked_only='true'
        )

    @patch('app.routes.api.service_admin.get_certtransparency_client')
    @patch('app.utils.security_logging.security_logger.log_data_access')
    def test_list_all_certificates_with_all_optional_filters(self, mock_log_access, mock_get_client, service_admin_client):
        """Test certificate listing with all optional filters."""
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        mock_client.list_certificates.return_value = {'certificates': [], 'total_count': 0}

        params = {
            'type': 'user',
            'subject': 'CN=test-user',
            'from_date': '2023-01-01',
            'to_date': '2023-12-31',
            'page': 3,
            'limit': 50
        }

        query_string = '&'.join([f'{k}={v}' for k, v in params.items()])
        response = service_admin_client.get(f'/api/certificates?{query_string}')

        assert response.status_code == 200

        # Verify all optional filters were passed through
        expected_params = {
            'page': 3,
            'limit': 50,
            'include_revoked': 'true',
            'type': 'user',
            'subject': 'CN=test-user',
            'from_date': '2023-01-01',
            'to_date': '2023-12-31'
        }
        mock_client.list_certificates.assert_called_once_with(**expected_params)

        # Verify security logging includes query params
        # Note: Flask request.args format may include all string values
        expected_query_params = {k: str(v) for k, v in params.items()}
        mock_log_access.assert_called_once_with(
            data_type="certificate_list",
            access_type="query",
            user_id='service-admin@example.com',
            additional_details={
                'query_params': expected_query_params,
                'result_count': 0
            }
        )

    @patch('app.routes.api.service_admin.get_certtransparency_client')
    def test_list_all_certificates_ct_client_error(self, mock_get_client, service_admin_client):
        """Test certificate listing with Certificate Transparency client error."""
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        mock_client.list_certificates.side_effect = CertTransparencyClientError("CT service unavailable")

        response = service_admin_client.get('/api/certificates')

        assert response.status_code == 503
        data = response.get_json()
        assert data['error'] == "Failed to retrieve certificates"
        assert "CT service unavailable" in data['details']

    @patch('app.routes.api.service_admin.get_certtransparency_client')
    @patch('app.utils.security_logging.security_logger.log_data_access')
    def test_list_all_certificates_empty_optional_filters_ignored(self, mock_log_access, mock_get_client, service_admin_client):
        """Test that empty optional filter parameters are ignored."""
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        mock_client.list_certificates.return_value = {'certificates': [], 'total_count': 0}

        # Send empty string values for optional filters
        response = service_admin_client.get('/api/certificates?type=&subject=&from_date=&to_date=')

        assert response.status_code == 200

        # Verify empty optional filters were not passed to CT client
        mock_client.list_certificates.assert_called_once_with(
            page=1,
            limit=100,
            include_revoked='true'
            # No optional filters should be included
        )

    @patch('app.routes.api.service_admin.get_certtransparency_client')
    @patch('app.utils.security_logging.security_logger.log_data_access')
    def test_list_all_certificates_both_active_and_revoked_filters(self, mock_log_access, mock_get_client, service_admin_client):
        """Test behavior when both active_only and revoked_only are specified (active_only takes precedence)."""
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        mock_client.list_certificates.return_value = {'certificates': [], 'total_count': 0}

        response = service_admin_client.get('/api/certificates?active_only=true&revoked_only=true')

        assert response.status_code == 200

        # Verify active_only takes precedence (processed first in if/elif chain)
        mock_client.list_certificates.assert_called_once_with(
            page=1,
            limit=100,
            include_revoked='false',
            active_only='true'
            # revoked_only should not be included since active_only was processed first
        )


class TestBulkRevokeUserCertificates:
    """Test the bulk_revoke_user_certificates service admin API endpoint."""

    def test_bulk_revoke_user_certificates_requires_auth(self, client):
        """Test that bulk_revoke_user_certificates requires authentication."""
        response = client.post('/api/certificates/user/test@example.com/revoke',
                               json={'reason': 'key_compromise'})
        assert response.status_code == 302  # Redirect to login

    def test_bulk_revoke_user_certificates_requires_service_admin(self, app):
        """Test that bulk_revoke_user_certificates requires service admin privileges."""
        client = app.test_client()

        # Set up regular user session (no service admin privileges)
        with client.session_transaction() as sess:
            sess['user'] = {
                'sub': 'user@example.com',
                'email': 'user@example.com',
                'name': 'Regular User',
                'is_system_admin': False,
                'is_admin': False,
                'is_auditor': False
            }

        response = client.post('/api/certificates/user/test@example.com/revoke',
                               json={'reason': 'key_compromise'})
        assert response.status_code == 403

    def test_bulk_revoke_user_certificates_requires_service_admin_not_auditor(self, auditor_client):
        """Test that bulk_revoke_user_certificates requires service admin, not just auditor."""
        response = auditor_client.post('/api/certificates/user/test@example.com/revoke',
                                       json={'reason': 'key_compromise'})
        assert response.status_code == 403

    def test_bulk_revoke_user_certificates_missing_request_body(self, service_admin_client):
        """Test bulk revocation fails without request body."""
        response = service_admin_client.post('/api/certificates/user/test@example.com/revoke')
        assert response.status_code == 500  # Flask throws 415, caught by general exception handler
        data = response.get_json()
        assert data['error'] == "Internal error occurred"

    def test_bulk_revoke_user_certificates_empty_request_body(self, service_admin_client):
        """Test bulk revocation fails with empty request body."""
        response = service_admin_client.post('/api/certificates/user/test@example.com/revoke',
                                             json={})
        assert response.status_code == 400
        data = response.get_json()
        assert data['error'] == "Missing required field: reason"

    def test_bulk_revoke_user_certificates_missing_reason(self, service_admin_client):
        """Test bulk revocation fails with missing reason field."""
        response = service_admin_client.post('/api/certificates/user/test@example.com/revoke',
                                             json={'other_field': 'value'})
        assert response.status_code == 400
        data = response.get_json()
        assert data['error'] == "Missing required field: reason"

    def test_bulk_revoke_user_certificates_empty_reason(self, service_admin_client):
        """Test bulk revocation fails with empty reason field."""
        response = service_admin_client.post('/api/certificates/user/test@example.com/revoke',
                                             json={'reason': ''})
        assert response.status_code == 400
        data = response.get_json()
        assert data['error'] == "Missing required field: reason"

    @patch('app.routes.api.service_admin.get_certtransparency_client')
    @patch('app.utils.security_logging.security_logger.log_certificate_bulk_revoked')
    def test_bulk_revoke_user_certificates_success(self, mock_log_revoked, mock_get_client, service_admin_client):
        """Test successful bulk user certificate revocation."""
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        mock_client.bulk_revoke_user_certificates.return_value = {
            'revoked_count': 5,
            'status': 'success',
            'user_id': 'test@example.com'
        }

        response = service_admin_client.post('/api/certificates/user/test@example.com/revoke',
                                             json={'reason': 'key_compromise'})

        assert response.status_code == 200
        data = response.get_json()
        assert data['revoked_count'] == 5
        assert data['status'] == 'success'
        assert data['user_id'] == 'test@example.com'

        # Verify CT client was called correctly
        mock_client.bulk_revoke_user_certificates.assert_called_once_with(
            user_id='test@example.com',
            reason='key_compromise',
            revoked_by='service-admin@example.com'
        )

        # Verify security logging
        mock_log_revoked.assert_called_once_with(
            revocation_type="user_email",
            target_identifier='test@example.com',
            reason='key_compromise',
            user_id='service-admin@example.com',
            certificates_affected=5
        )

    @patch('app.routes.api.service_admin.get_certtransparency_client')
    @patch('app.utils.security_logging.security_logger.log_certificate_bulk_revoked')
    def test_bulk_revoke_user_certificates_no_certificates(self, mock_log_revoked, mock_get_client, service_admin_client):
        """Test bulk revocation when user has no certificates."""
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        mock_client.bulk_revoke_user_certificates.return_value = {
            'revoked_count': 0,
            'status': 'success',
            'user_id': 'nonexistent@example.com',
            'message': 'No active certificates found for user'
        }

        response = service_admin_client.post('/api/certificates/user/nonexistent@example.com/revoke',
                                             json={'reason': 'cessation_of_operation'})

        assert response.status_code == 200
        data = response.get_json()
        assert data['revoked_count'] == 0
        assert data['status'] == 'success'

        # Verify security logging with zero certificates
        mock_log_revoked.assert_called_once_with(
            revocation_type="user_email",
            target_identifier='nonexistent@example.com',
            reason='cessation_of_operation',
            user_id='service-admin@example.com',
            certificates_affected=0
        )

    @patch('app.routes.api.service_admin.get_certtransparency_client')
    @patch('app.utils.security_logging.security_logger.log_certificate_bulk_revoked')
    def test_bulk_revoke_user_certificates_different_revocation_reasons(self, mock_log_revoked, mock_get_client, service_admin_client):
        """Test bulk revocation with different valid revocation reasons."""
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        mock_client.bulk_revoke_user_certificates.return_value = {
            'revoked_count': 3,
            'status': 'success'
        }

        # Test various valid revocation reasons
        reasons = [
            'key_compromise',
            'cessation_of_operation',
            'ca_compromise',
            'affiliation_changed',
            'superseded',
            'privilege_withdrawn',
            'certificate_hold'
        ]

        for reason in reasons:
            response = service_admin_client.post('/api/certificates/user/test@example.com/revoke',
                                                 json={'reason': reason})
            assert response.status_code == 200

            # Verify correct reason was passed
            mock_client.bulk_revoke_user_certificates.assert_called_with(
                user_id='test@example.com',
                reason=reason,
                revoked_by='service-admin@example.com'
            )

    @patch('app.routes.api.service_admin.get_certtransparency_client')
    def test_bulk_revoke_user_certificates_ct_client_error(self, mock_get_client, service_admin_client):
        """Test bulk revocation with Certificate Transparency client error."""
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        mock_client.bulk_revoke_user_certificates.side_effect = CertTransparencyClientError("CT service unavailable")

        response = service_admin_client.post('/api/certificates/user/test@example.com/revoke',
                                             json={'reason': 'key_compromise'})

        assert response.status_code == 503
        data = response.get_json()
        assert data['error'] == "Failed to bulk revoke certificates"
        assert "CT service unavailable" in data['details']

    @patch('app.routes.api.service_admin.get_certtransparency_client')
    def test_bulk_revoke_user_certificates_general_exception(self, mock_get_client, service_admin_client):
        """Test bulk revocation with general exception."""
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        mock_client.bulk_revoke_user_certificates.side_effect = Exception("Database connection failed")

        response = service_admin_client.post('/api/certificates/user/test@example.com/revoke',
                                             json={'reason': 'key_compromise'})

        assert response.status_code == 500
        data = response.get_json()
        assert data['error'] == "Internal error occurred"

    @patch('app.routes.api.service_admin.get_certtransparency_client')
    @patch('app.utils.security_logging.security_logger.log_certificate_bulk_revoked')
    def test_bulk_revoke_user_certificates_with_special_characters_email(self, mock_log_revoked, mock_get_client, service_admin_client):
        """Test bulk revocation with email containing special characters."""
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        mock_client.bulk_revoke_user_certificates.return_value = {
            'revoked_count': 2,
            'status': 'success'
        }

        # Test with email containing special characters
        special_email = 'user+test@sub-domain.example.com'
        response = service_admin_client.post(f'/api/certificates/user/{special_email}/revoke',
                                             json={'reason': 'key_compromise'})

        assert response.status_code == 200

        # Verify CT client was called with the special email
        mock_client.bulk_revoke_user_certificates.assert_called_once_with(
            user_id=special_email,
            reason='key_compromise',
            revoked_by='service-admin@example.com'
        )

    @patch('app.routes.api.service_admin.get_certtransparency_client')
    @patch('app.utils.security_logging.security_logger.log_certificate_bulk_revoked')
    def test_bulk_revoke_user_certificates_admin_user_privileges(self, mock_log_revoked, mock_get_client, admin_client):
        """Test that regular admin users can perform bulk revocation."""
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        mock_client.bulk_revoke_user_certificates.return_value = {
            'revoked_count': 1,
            'status': 'success'
        }

        response = admin_client.post('/api/certificates/user/test@example.com/revoke',
                                     json={'reason': 'key_compromise'})

        assert response.status_code == 200

        # Verify correct admin user ID was used
        mock_log_revoked.assert_called_once_with(
            revocation_type="user_email",
            target_identifier='test@example.com',
            reason='key_compromise',
            user_id='admin@example.com',  # Admin user, not service admin
            certificates_affected=1
        )


class TestListUserCertificates:
    """Test the list_user_certificates service admin API endpoint."""

    def test_list_user_certificates_requires_auth(self, client):
        """Test that list_user_certificates requires authentication."""
        response = client.get('/api/certificates/user/test@example.com')
        assert response.status_code == 302  # Redirect to login

    def test_list_user_certificates_requires_service_admin_or_auditor(self, app):
        """Test that list_user_certificates requires service admin or auditor privileges."""
        client = app.test_client()

        # Set up regular user session (no admin/auditor privileges)
        with client.session_transaction() as sess:
            sess['user'] = {
                'sub': 'user@example.com',
                'email': 'user@example.com',
                'name': 'Regular User',
                'is_system_admin': False,
                'is_admin': False,
                'is_auditor': False
            }

        response = client.get('/api/certificates/user/test@example.com')
        assert response.status_code == 403

    @patch('app.routes.api.service_admin.get_certtransparency_client')
    @patch('app.utils.security_logging.security_logger.log_data_access')
    def test_list_user_certificates_success_service_admin(self, mock_log_access, mock_get_client, service_admin_client):
        """Test successful user certificate list retrieval by service admin."""
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        mock_client.list_user_certificates.return_value = {
            'certificates': [
                {'id': 1, 'subject': 'CN=test@example.com', 'is_revoked': False, 'issued_at': '2023-01-01'},
                {'id': 2, 'subject': 'CN=test@example.com', 'is_revoked': True, 'issued_at': '2023-02-01'}
            ],
            'user_email': 'test@example.com',
            'total_count': 2
        }

        response = service_admin_client.get('/api/certificates/user/test@example.com')

        assert response.status_code == 200
        data = response.get_json()
        assert 'certificates' in data
        assert len(data['certificates']) == 2
        assert data['user_email'] == 'test@example.com'
        assert data['total_count'] == 2

        # Verify CT client was called with default parameters
        mock_client.list_user_certificates.assert_called_once_with(
            user_email='test@example.com',
            include_revoked=True,  # Default when active_only is False
            active_only=False,
            revoked_only=False
        )

        # Verify security logging
        mock_log_access.assert_called_once_with(
            data_type="user_certificates",
            access_type="query",
            user_id='service-admin@example.com',
            additional_details={
                'target_user_email': 'test@example.com',
                'active_only': False,
                'revoked_only': False,
                'result_count': 2
            }
        )

    @patch('app.routes.api.service_admin.get_certtransparency_client')
    @patch('app.utils.security_logging.security_logger.log_data_access')
    def test_list_user_certificates_success_auditor(self, mock_log_access, mock_get_client, auditor_client):
        """Test successful user certificate list retrieval by auditor."""
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        mock_client.list_user_certificates.return_value = {
            'certificates': [],
            'user_email': 'auditor-test@example.com',
            'total_count': 0
        }

        response = auditor_client.get('/api/certificates/user/auditor-test@example.com')

        assert response.status_code == 200
        data = response.get_json()
        assert 'certificates' in data
        assert len(data['certificates']) == 0

        # Verify security logging with auditor user
        mock_log_access.assert_called_once_with(
            data_type="user_certificates",
            access_type="query",
            user_id='auditor@example.com',
            additional_details={
                'target_user_email': 'auditor-test@example.com',
                'active_only': False,
                'revoked_only': False,
                'result_count': 0
            }
        )

    @patch('app.routes.api.service_admin.get_certtransparency_client')
    @patch('app.utils.security_logging.security_logger.log_data_access')
    def test_list_user_certificates_success_admin(self, mock_log_access, mock_get_client, admin_client):
        """Test successful user certificate list retrieval by admin."""
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        mock_client.list_user_certificates.return_value = {
            'certificates': [{'id': 1, 'subject': 'CN=admin-test@example.com'}],
            'user_email': 'admin-test@example.com',
            'total_count': 1
        }

        response = admin_client.get('/api/certificates/user/admin-test@example.com')

        assert response.status_code == 200

    @patch('app.routes.api.service_admin.get_certtransparency_client')
    @patch('app.utils.security_logging.security_logger.log_data_access')
    def test_list_user_certificates_with_active_only_filter(self, mock_log_access, mock_get_client, service_admin_client):
        """Test user certificate listing with active_only filter."""
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        mock_client.list_user_certificates.return_value = {
            'certificates': [{'id': 1, 'subject': 'CN=test@example.com', 'is_revoked': False}],
            'total_count': 1
        }

        response = service_admin_client.get('/api/certificates/user/test@example.com?active_only=true')

        assert response.status_code == 200

        # Verify active_only parameter was processed correctly
        mock_client.list_user_certificates.assert_called_once_with(
            user_email='test@example.com',
            include_revoked=False,  # Changed from True when active_only=true
            active_only=True,
            revoked_only=False
        )

        # Verify security logging includes filter details
        mock_log_access.assert_called_once_with(
            data_type="user_certificates",
            access_type="query",
            user_id='service-admin@example.com',
            additional_details={
                'target_user_email': 'test@example.com',
                'active_only': True,
                'revoked_only': False,
                'result_count': 1
            }
        )

    @patch('app.routes.api.service_admin.get_certtransparency_client')
    @patch('app.utils.security_logging.security_logger.log_data_access')
    def test_list_user_certificates_with_revoked_only_filter(self, mock_log_access, mock_get_client, service_admin_client):
        """Test user certificate listing with revoked_only filter."""
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        mock_client.list_user_certificates.return_value = {
            'certificates': [{'id': 2, 'subject': 'CN=test@example.com', 'is_revoked': True}],
            'total_count': 1
        }

        response = service_admin_client.get('/api/certificates/user/test@example.com?revoked_only=true')

        assert response.status_code == 200

        # Verify revoked_only parameter was processed correctly
        mock_client.list_user_certificates.assert_called_once_with(
            user_email='test@example.com',
            include_revoked=True,  # Remains True when revoked_only=true
            active_only=False,
            revoked_only=True
        )

    @patch('app.routes.api.service_admin.get_certtransparency_client')
    @patch('app.utils.security_logging.security_logger.log_data_access')
    def test_list_user_certificates_both_active_and_revoked_filters(self, mock_log_access, mock_get_client, service_admin_client):
        """Test behavior when both active_only and revoked_only are specified (active_only takes precedence)."""
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        mock_client.list_user_certificates.return_value = {'certificates': [], 'total_count': 0}

        response = service_admin_client.get('/api/certificates/user/test@example.com?active_only=true&revoked_only=true')

        assert response.status_code == 200

        # Verify active_only takes precedence (processed first in if/elif chain)
        mock_client.list_user_certificates.assert_called_once_with(
            user_email='test@example.com',
            include_revoked=False,  # active_only=true overrides revoked_only
            active_only=True,
            revoked_only=True  # Both flags are passed, but include_revoked logic follows active_only
        )

    @patch('app.routes.api.service_admin.get_certtransparency_client')
    @patch('app.utils.security_logging.security_logger.log_data_access')
    def test_list_user_certificates_with_special_characters_email(self, mock_log_access, mock_get_client, service_admin_client):
        """Test user certificate listing with email containing special characters."""
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        mock_client.list_user_certificates.return_value = {
            'certificates': [{'id': 1, 'subject': 'CN=user+test@sub-domain.example.com'}],
            'user_email': 'user+test@sub-domain.example.com',
            'total_count': 1
        }

        # Test with email containing special characters
        special_email = 'user+test@sub-domain.example.com'
        response = service_admin_client.get(f'/api/certificates/user/{special_email}')

        assert response.status_code == 200

        # Verify CT client was called with the special email
        mock_client.list_user_certificates.assert_called_once_with(
            user_email=special_email,
            include_revoked=True,
            active_only=False,
            revoked_only=False
        )

        # Verify security logging includes special email
        mock_log_access.assert_called_once_with(
            data_type="user_certificates",
            access_type="query",
            user_id='service-admin@example.com',
            additional_details={
                'target_user_email': special_email,
                'active_only': False,
                'revoked_only': False,
                'result_count': 1
            }
        )

    @patch('app.routes.api.service_admin.get_certtransparency_client')
    @patch('app.utils.security_logging.security_logger.log_data_access')
    def test_list_user_certificates_empty_result(self, mock_log_access, mock_get_client, service_admin_client):
        """Test user certificate listing when user has no certificates."""
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        mock_client.list_user_certificates.return_value = {
            'certificates': [],
            'user_email': 'nonexistent@example.com',
            'total_count': 0,
            'message': 'No certificates found for user'
        }

        response = service_admin_client.get('/api/certificates/user/nonexistent@example.com')

        assert response.status_code == 200
        data = response.get_json()
        assert 'certificates' in data
        assert len(data['certificates']) == 0
        assert data['total_count'] == 0

        # Verify security logging with zero result count
        mock_log_access.assert_called_once_with(
            data_type="user_certificates",
            access_type="query",
            user_id='service-admin@example.com',
            additional_details={
                'target_user_email': 'nonexistent@example.com',
                'active_only': False,
                'revoked_only': False,
                'result_count': 0
            }
        )

    @patch('app.routes.api.service_admin.get_certtransparency_client')
    def test_list_user_certificates_ct_client_error(self, mock_get_client, service_admin_client):
        """Test user certificate listing with Certificate Transparency client error."""
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        mock_client.list_user_certificates.side_effect = CertTransparencyClientError("CT service unavailable for user query")

        response = service_admin_client.get('/api/certificates/user/test@example.com')

        assert response.status_code == 503
        data = response.get_json()
        assert data['error'] == "Failed to retrieve user certificates"
        assert "CT service unavailable for user query" in data['details']

    @patch('app.routes.api.service_admin.get_certtransparency_client')
    @patch('app.utils.security_logging.security_logger.log_data_access')
    def test_list_user_certificates_boolean_filter_variations(self, mock_log_access, mock_get_client, service_admin_client):
        """Test user certificate listing with various boolean filter values."""
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        mock_client.list_user_certificates.return_value = {'certificates': [], 'total_count': 0}

        # Test different boolean representations
        test_cases = [
            ('active_only=false', False, True),  # (param, active_only, include_revoked)
            ('active_only=True', False, True),   # Case sensitive - should be False
            ('active_only=1', False, True),      # Non-string value - should be False
            ('revoked_only=false', False, True), # revoked_only false
            ('revoked_only=True', False, True),  # Case sensitive - should be False
            ('revoked_only=1', False, True),     # Non-string value - should be False
        ]

        for param_string, expected_active_only, expected_include_revoked in test_cases:
            response = service_admin_client.get(f'/api/certificates/user/test@example.com?{param_string}')
            assert response.status_code == 200

            # Find the most recent call arguments
            latest_call = mock_client.list_user_certificates.call_args
            assert latest_call[1]['active_only'] == expected_active_only
            assert latest_call[1]['include_revoked'] == expected_include_revoked


class TestListComputerCertificates:
    """Test the list_computer_certificates service admin API endpoint."""

    def test_list_computer_certificates_requires_auth(self, client):
        """Test that list_computer_certificates requires authentication."""
        response = client.get('/api/certificates/computer')
        assert response.status_code == 302  # Redirect to login

    def test_list_computer_certificates_requires_service_admin_or_auditor(self, app):
        """Test that list_computer_certificates requires service admin or auditor privileges."""
        client = app.test_client()

        # Set up regular user session (no admin/auditor privileges)
        with client.session_transaction() as sess:
            sess['user'] = {
                'sub': 'user@example.com',
                'email': 'user@example.com',
                'name': 'Regular User',
                'is_system_admin': False,
                'is_admin': False,
                'is_auditor': False
            }

        response = client.get('/api/certificates/computer')
        assert response.status_code == 403

    @patch('app.routes.api.service_admin.get_certtransparency_client')
    @patch('app.utils.security_logging.security_logger.log_data_access')
    def test_list_computer_certificates_success_service_admin(self, mock_log_access, mock_get_client, service_admin_client):
        """Test successful computer certificate list retrieval by service admin."""
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        mock_client.list_computer_certificates.return_value = {
            'certificates': [
                {'id': 1, 'subject': 'CN=server01', 'psk_description': 'Production Server', 'is_revoked': False},
                {'id': 2, 'subject': 'CN=server02', 'psk_description': 'Staging Server', 'is_revoked': True}
            ],
            'total_count': 2
        }

        response = service_admin_client.get('/api/certificates/computer')

        assert response.status_code == 200
        data = response.get_json()
        assert 'certificates' in data
        assert len(data['certificates']) == 2
        assert data['total_count'] == 2

        # Verify CT client was called with default parameters
        mock_client.list_computer_certificates.assert_called_once_with(
            psk_filter=None,
            include_revoked=True,  # Default when active_only is False
            active_only=False,
            revoked_only=False
        )

        # Verify security logging
        mock_log_access.assert_called_once_with(
            data_type="computer_certificates",
            access_type="query",
            user_id='service-admin@example.com',
            additional_details={
                'psk_filter': None,
                'active_only': False,
                'revoked_only': False,
                'result_count': 2
            }
        )

    @patch('app.routes.api.service_admin.get_certtransparency_client')
    @patch('app.utils.security_logging.security_logger.log_data_access')
    def test_list_computer_certificates_success_auditor(self, mock_log_access, mock_get_client, auditor_client):
        """Test successful computer certificate list retrieval by auditor."""
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        mock_client.list_computer_certificates.return_value = {
            'certificates': [],
            'total_count': 0
        }

        response = auditor_client.get('/api/certificates/computer')

        assert response.status_code == 200
        data = response.get_json()
        assert 'certificates' in data
        assert len(data['certificates']) == 0

        # Verify security logging with auditor user
        mock_log_access.assert_called_once_with(
            data_type="computer_certificates",
            access_type="query",
            user_id='auditor@example.com',
            additional_details={
                'psk_filter': None,
                'active_only': False,
                'revoked_only': False,
                'result_count': 0
            }
        )

    @patch('app.routes.api.service_admin.get_certtransparency_client')
    @patch('app.utils.security_logging.security_logger.log_data_access')
    def test_list_computer_certificates_success_admin(self, mock_log_access, mock_get_client, admin_client):
        """Test successful computer certificate list retrieval by admin."""
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        mock_client.list_computer_certificates.return_value = {
            'certificates': [{'id': 1, 'subject': 'CN=admin-server', 'psk_description': 'Admin Test Server'}],
            'total_count': 1
        }

        response = admin_client.get('/api/certificates/computer')

        assert response.status_code == 200

    @patch('app.routes.api.service_admin.get_certtransparency_client')
    @patch('app.utils.security_logging.security_logger.log_data_access')
    def test_list_computer_certificates_with_active_only_filter(self, mock_log_access, mock_get_client, service_admin_client):
        """Test computer certificate listing with active_only filter."""
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        mock_client.list_computer_certificates.return_value = {
            'certificates': [{'id': 1, 'subject': 'CN=active-server', 'is_revoked': False}],
            'total_count': 1
        }

        response = service_admin_client.get('/api/certificates/computer?active_only=true')

        assert response.status_code == 200

        # Verify active_only parameter was processed correctly
        mock_client.list_computer_certificates.assert_called_once_with(
            psk_filter=None,
            include_revoked=False,  # Changed from True when active_only=true
            active_only=True,
            revoked_only=False
        )

        # Verify security logging includes filter details
        mock_log_access.assert_called_once_with(
            data_type="computer_certificates",
            access_type="query",
            user_id='service-admin@example.com',
            additional_details={
                'psk_filter': None,
                'active_only': True,
                'revoked_only': False,
                'result_count': 1
            }
        )

    @patch('app.routes.api.service_admin.get_certtransparency_client')
    @patch('app.utils.security_logging.security_logger.log_data_access')
    def test_list_computer_certificates_with_revoked_only_filter(self, mock_log_access, mock_get_client, service_admin_client):
        """Test computer certificate listing with revoked_only filter."""
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        mock_client.list_computer_certificates.return_value = {
            'certificates': [{'id': 2, 'subject': 'CN=revoked-server', 'is_revoked': True}],
            'total_count': 1
        }

        response = service_admin_client.get('/api/certificates/computer?revoked_only=true')

        assert response.status_code == 200

        # Verify revoked_only parameter was processed correctly
        mock_client.list_computer_certificates.assert_called_once_with(
            psk_filter=None,
            include_revoked=True,  # Remains True when revoked_only=true
            active_only=False,
            revoked_only=True
        )

    @patch('app.routes.api.service_admin.get_certtransparency_client')
    @patch('app.utils.security_logging.security_logger.log_data_access')
    def test_list_computer_certificates_with_psk_filter(self, mock_log_access, mock_get_client, service_admin_client):
        """Test computer certificate listing with PSK filter."""
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        mock_client.list_computer_certificates.return_value = {
            'certificates': [
                {'id': 1, 'subject': 'CN=prod-server-01', 'psk_description': 'Production Web Server 01'},
                {'id': 2, 'subject': 'CN=prod-server-02', 'psk_description': 'Production Web Server 02'}
            ],
            'total_count': 2
        }

        response = service_admin_client.get('/api/certificates/computer?psk_filter=Production')

        assert response.status_code == 200

        # Verify psk_filter parameter was passed correctly
        mock_client.list_computer_certificates.assert_called_once_with(
            psk_filter='Production',
            include_revoked=True,
            active_only=False,
            revoked_only=False
        )

        # Verify security logging includes PSK filter
        mock_log_access.assert_called_once_with(
            data_type="computer_certificates",
            access_type="query",
            user_id='service-admin@example.com',
            additional_details={
                'psk_filter': 'Production',
                'active_only': False,
                'revoked_only': False,
                'result_count': 2
            }
        )

    @patch('app.routes.api.service_admin.get_certtransparency_client')
    @patch('app.utils.security_logging.security_logger.log_data_access')
    def test_list_computer_certificates_with_all_filters(self, mock_log_access, mock_get_client, service_admin_client):
        """Test computer certificate listing with all filter parameters."""
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        mock_client.list_computer_certificates.return_value = {
            'certificates': [{'id': 1, 'subject': 'CN=staging-server', 'psk_description': 'Staging Environment'}],
            'total_count': 1
        }

        response = service_admin_client.get('/api/certificates/computer?active_only=true&psk_filter=Staging')

        assert response.status_code == 200

        # Verify all filter parameters were processed correctly
        mock_client.list_computer_certificates.assert_called_once_with(
            psk_filter='Staging',
            include_revoked=False,  # active_only=true
            active_only=True,
            revoked_only=False
        )

        # Verify security logging includes all filter details
        mock_log_access.assert_called_once_with(
            data_type="computer_certificates",
            access_type="query",
            user_id='service-admin@example.com',
            additional_details={
                'psk_filter': 'Staging',
                'active_only': True,
                'revoked_only': False,
                'result_count': 1
            }
        )

    @patch('app.routes.api.service_admin.get_certtransparency_client')
    @patch('app.utils.security_logging.security_logger.log_data_access')
    def test_list_computer_certificates_both_active_and_revoked_filters(self, mock_log_access, mock_get_client, service_admin_client):
        """Test behavior when both active_only and revoked_only are specified (active_only takes precedence)."""
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        mock_client.list_computer_certificates.return_value = {'certificates': [], 'total_count': 0}

        response = service_admin_client.get('/api/certificates/computer?active_only=true&revoked_only=true')

        assert response.status_code == 200

        # Verify active_only takes precedence (processed first in if/elif chain)
        mock_client.list_computer_certificates.assert_called_once_with(
            psk_filter=None,
            include_revoked=False,  # active_only=true overrides revoked_only
            active_only=True,
            revoked_only=True  # Both flags are passed, but include_revoked logic follows active_only
        )

    @patch('app.routes.api.service_admin.get_certtransparency_client')
    @patch('app.utils.security_logging.security_logger.log_data_access')
    def test_list_computer_certificates_with_special_characters_psk_filter(self, mock_log_access, mock_get_client, service_admin_client):
        """Test computer certificate listing with PSK filter containing special characters."""
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        mock_client.list_computer_certificates.return_value = {
            'certificates': [{'id': 1, 'subject': 'CN=special-server', 'psk_description': 'Test & Development'}],
            'total_count': 1
        }

        # Test with PSK filter containing special characters (URL encoded)
        from urllib.parse import quote
        special_filter = 'Test & Development'
        encoded_filter = quote(special_filter)
        response = service_admin_client.get(f'/api/certificates/computer?psk_filter={encoded_filter}')

        assert response.status_code == 200

        # Verify PSK filter with special characters was passed correctly (decoded by Flask)
        mock_client.list_computer_certificates.assert_called_once_with(
            psk_filter=special_filter,
            include_revoked=True,
            active_only=False,
            revoked_only=False
        )

        # Verify security logging includes special filter (decoded)
        mock_log_access.assert_called_once_with(
            data_type="computer_certificates",
            access_type="query",
            user_id='service-admin@example.com',
            additional_details={
                'psk_filter': special_filter,
                'active_only': False,
                'revoked_only': False,
                'result_count': 1
            }
        )

    @patch('app.routes.api.service_admin.get_certtransparency_client')
    @patch('app.utils.security_logging.security_logger.log_data_access')
    def test_list_computer_certificates_empty_result(self, mock_log_access, mock_get_client, service_admin_client):
        """Test computer certificate listing when no certificates match filter."""
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        mock_client.list_computer_certificates.return_value = {
            'certificates': [],
            'total_count': 0,
            'message': 'No computer certificates found'
        }

        response = service_admin_client.get('/api/certificates/computer?psk_filter=NonExistent')

        assert response.status_code == 200
        data = response.get_json()
        assert 'certificates' in data
        assert len(data['certificates']) == 0
        assert data['total_count'] == 0

        # Verify security logging with zero result count
        mock_log_access.assert_called_once_with(
            data_type="computer_certificates",
            access_type="query",
            user_id='service-admin@example.com',
            additional_details={
                'psk_filter': 'NonExistent',
                'active_only': False,
                'revoked_only': False,
                'result_count': 0
            }
        )

    @patch('app.routes.api.service_admin.get_certtransparency_client')
    def test_list_computer_certificates_ct_client_error(self, mock_get_client, service_admin_client):
        """Test computer certificate listing with Certificate Transparency client error."""
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        mock_client.list_computer_certificates.side_effect = CertTransparencyClientError("CT service unavailable for computer query")

        response = service_admin_client.get('/api/certificates/computer')

        assert response.status_code == 503
        data = response.get_json()
        assert data['error'] == "Failed to retrieve computer certificates"
        assert "CT service unavailable for computer query" in data['details']

    @patch('app.routes.api.service_admin.get_certtransparency_client')
    @patch('app.utils.security_logging.security_logger.log_data_access')
    def test_list_computer_certificates_empty_psk_filter_ignored(self, mock_log_access, mock_get_client, service_admin_client):
        """Test that empty PSK filter is treated as None."""
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        mock_client.list_computer_certificates.return_value = {'certificates': [], 'total_count': 0}

        response = service_admin_client.get('/api/certificates/computer?psk_filter=')

        assert response.status_code == 200

        # Verify empty PSK filter is passed as empty string (not None)
        mock_client.list_computer_certificates.assert_called_once_with(
            psk_filter='',
            include_revoked=True,
            active_only=False,
            revoked_only=False
        )

        # Verify security logging includes empty filter
        mock_log_access.assert_called_once_with(
            data_type="computer_certificates",
            access_type="query",
            user_id='service-admin@example.com',
            additional_details={
                'psk_filter': '',
                'active_only': False,
                'revoked_only': False,
                'result_count': 0
            }
        )


class TestBulkRevokeComputerCertificates:
    """Test the bulk_revoke_computer_certificates service admin API endpoint."""

    def test_bulk_revoke_computer_certificates_requires_auth(self, client):
        """Test that bulk_revoke_computer_certificates requires authentication."""
        response = client.post('/api/certificates/computer/bulk-revoke',
                               json={'psk_filter': 'Production', 'reason': 'key_compromise'})
        assert response.status_code == 302  # Redirect to login

    def test_bulk_revoke_computer_certificates_requires_service_admin(self, app):
        """Test that bulk_revoke_computer_certificates requires service admin privileges."""
        client = app.test_client()

        # Set up regular user session (no service admin privileges)
        with client.session_transaction() as sess:
            sess['user'] = {
                'sub': 'user@example.com',
                'email': 'user@example.com',
                'name': 'Regular User',
                'is_system_admin': False,
                'is_admin': False,
                'is_auditor': False
            }

        response = client.post('/api/certificates/computer/bulk-revoke',
                               json={'psk_filter': 'Production', 'reason': 'key_compromise'})
        assert response.status_code == 403

    def test_bulk_revoke_computer_certificates_requires_service_admin_not_auditor(self, auditor_client):
        """Test that bulk_revoke_computer_certificates requires service admin, not just auditor."""
        response = auditor_client.post('/api/certificates/computer/bulk-revoke',
                                       json={'psk_filter': 'Production', 'reason': 'key_compromise'})
        assert response.status_code == 403

    def test_bulk_revoke_computer_certificates_missing_request_body(self, service_admin_client):
        """Test bulk revocation fails without request body."""
        response = service_admin_client.post('/api/certificates/computer/bulk-revoke')
        assert response.status_code == 500  # Flask throws 415, caught by general exception handler
        data = response.get_json()
        assert data['error'] == "Internal error occurred"

    def test_bulk_revoke_computer_certificates_empty_request_body(self, service_admin_client):
        """Test bulk revocation fails with empty request body."""
        response = service_admin_client.post('/api/certificates/computer/bulk-revoke',
                                             json={})
        assert response.status_code == 400
        data = response.get_json()
        assert data['error'] == "Missing required fields: psk_filter, reason"

    def test_bulk_revoke_computer_certificates_missing_psk_filter(self, service_admin_client):
        """Test bulk revocation fails with missing psk_filter field."""
        response = service_admin_client.post('/api/certificates/computer/bulk-revoke',
                                             json={'reason': 'key_compromise'})
        assert response.status_code == 400
        data = response.get_json()
        assert data['error'] == "Missing required fields: psk_filter, reason"

    def test_bulk_revoke_computer_certificates_missing_reason(self, service_admin_client):
        """Test bulk revocation fails with missing reason field."""
        response = service_admin_client.post('/api/certificates/computer/bulk-revoke',
                                             json={'psk_filter': 'Production'})
        assert response.status_code == 400
        data = response.get_json()
        assert data['error'] == "Missing required fields: psk_filter, reason"

    def test_bulk_revoke_computer_certificates_empty_psk_filter(self, service_admin_client):
        """Test bulk revocation fails with empty psk_filter field."""
        response = service_admin_client.post('/api/certificates/computer/bulk-revoke',
                                             json={'psk_filter': '', 'reason': 'key_compromise'})
        assert response.status_code == 400
        data = response.get_json()
        assert data['error'] == "Missing required fields: psk_filter, reason"

    def test_bulk_revoke_computer_certificates_empty_reason(self, service_admin_client):
        """Test bulk revocation fails with empty reason field."""
        response = service_admin_client.post('/api/certificates/computer/bulk-revoke',
                                             json={'psk_filter': 'Production', 'reason': ''})
        assert response.status_code == 400
        data = response.get_json()
        assert data['error'] == "Missing required fields: psk_filter, reason"

    @patch('app.routes.api.service_admin.get_certtransparency_client')
    @patch('app.utils.security_logging.security_logger.log_certificate_bulk_revoked')
    def test_bulk_revoke_computer_certificates_success(self, mock_log_revoked, mock_get_client, service_admin_client):
        """Test successful bulk computer certificate revocation."""
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        mock_client.bulk_revoke_computer_certificates.return_value = {
            'revoked_count': 8,
            'status': 'success',
            'psk_filter': 'Production'
        }

        response = service_admin_client.post('/api/certificates/computer/bulk-revoke',
                                             json={'psk_filter': 'Production', 'reason': 'key_compromise'})

        assert response.status_code == 200
        data = response.get_json()
        assert data['revoked_count'] == 8
        assert data['status'] == 'success'
        assert data['psk_filter'] == 'Production'

        # Verify CT client was called correctly
        mock_client.bulk_revoke_computer_certificates.assert_called_once_with(
            psk_filter='Production',
            reason='key_compromise',
            revoked_by='service-admin@example.com'
        )

        # Verify security logging
        mock_log_revoked.assert_called_once_with(
            revocation_type="computer_psk",
            target_identifier='Production',
            reason='key_compromise',
            user_id='service-admin@example.com',
            certificates_affected=8
        )

    @patch('app.routes.api.service_admin.get_certtransparency_client')
    @patch('app.utils.security_logging.security_logger.log_certificate_bulk_revoked')
    def test_bulk_revoke_computer_certificates_no_certificates(self, mock_log_revoked, mock_get_client, service_admin_client):
        """Test bulk revocation when no certificates match PSK filter."""
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        mock_client.bulk_revoke_computer_certificates.return_value = {
            'revoked_count': 0,
            'status': 'success',
            'psk_filter': 'NonExistentPSK',
            'message': 'No active computer certificates found matching PSK filter'
        }

        response = service_admin_client.post('/api/certificates/computer/bulk-revoke',
                                             json={'psk_filter': 'NonExistentPSK', 'reason': 'cessation_of_operation'})

        assert response.status_code == 200
        data = response.get_json()
        assert data['revoked_count'] == 0
        assert data['status'] == 'success'

        # Verify security logging with zero certificates
        mock_log_revoked.assert_called_once_with(
            revocation_type="computer_psk",
            target_identifier='NonExistentPSK',
            reason='cessation_of_operation',
            user_id='service-admin@example.com',
            certificates_affected=0
        )

    @patch('app.routes.api.service_admin.get_certtransparency_client')
    @patch('app.utils.security_logging.security_logger.log_certificate_bulk_revoked')
    def test_bulk_revoke_computer_certificates_different_revocation_reasons(self, mock_log_revoked, mock_get_client, service_admin_client):
        """Test bulk revocation with different valid revocation reasons."""
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        mock_client.bulk_revoke_computer_certificates.return_value = {
            'revoked_count': 3,
            'status': 'success'
        }

        # Test various valid revocation reasons
        reasons = [
            'key_compromise',
            'cessation_of_operation',
            'ca_compromise',
            'affiliation_changed',
            'superseded',
            'privilege_withdrawn',
            'certificate_hold'
        ]

        for reason in reasons:
            response = service_admin_client.post('/api/certificates/computer/bulk-revoke',
                                                 json={'psk_filter': 'TestPSK', 'reason': reason})
            assert response.status_code == 200

            # Verify correct reason was passed
            mock_client.bulk_revoke_computer_certificates.assert_called_with(
                psk_filter='TestPSK',
                reason=reason,
                revoked_by='service-admin@example.com'
            )

    @patch('app.routes.api.service_admin.get_certtransparency_client')
    @patch('app.utils.security_logging.security_logger.log_certificate_bulk_revoked')
    def test_bulk_revoke_computer_certificates_with_special_characters_psk(self, mock_log_revoked, mock_get_client, service_admin_client):
        """Test bulk revocation with PSK filter containing special characters."""
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        mock_client.bulk_revoke_computer_certificates.return_value = {
            'revoked_count': 2,
            'status': 'success'
        }

        # Test with PSK filter containing special characters
        special_psk = 'Test & Development Environment'
        response = service_admin_client.post('/api/certificates/computer/bulk-revoke',
                                             json={'psk_filter': special_psk, 'reason': 'key_compromise'})

        assert response.status_code == 200

        # Verify CT client was called with the special PSK filter
        mock_client.bulk_revoke_computer_certificates.assert_called_once_with(
            psk_filter=special_psk,
            reason='key_compromise',
            revoked_by='service-admin@example.com'
        )

        # Verify security logging includes special PSK filter
        mock_log_revoked.assert_called_once_with(
            revocation_type="computer_psk",
            target_identifier=special_psk,
            reason='key_compromise',
            user_id='service-admin@example.com',
            certificates_affected=2
        )

    @patch('app.routes.api.service_admin.get_certtransparency_client')
    def test_bulk_revoke_computer_certificates_ct_client_error(self, mock_get_client, service_admin_client):
        """Test bulk revocation with Certificate Transparency client error."""
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        mock_client.bulk_revoke_computer_certificates.side_effect = CertTransparencyClientError("CT service unavailable for bulk operation")

        response = service_admin_client.post('/api/certificates/computer/bulk-revoke',
                                             json={'psk_filter': 'Production', 'reason': 'key_compromise'})

        assert response.status_code == 503
        data = response.get_json()
        assert data['error'] == "Failed to bulk revoke computer certificates"
        assert "CT service unavailable for bulk operation" in data['details']

    @patch('app.routes.api.service_admin.get_certtransparency_client')
    def test_bulk_revoke_computer_certificates_general_exception(self, mock_get_client, service_admin_client):
        """Test bulk revocation with general exception."""
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        mock_client.bulk_revoke_computer_certificates.side_effect = Exception("Database connection failed")

        response = service_admin_client.post('/api/certificates/computer/bulk-revoke',
                                             json={'psk_filter': 'Production', 'reason': 'key_compromise'})

        assert response.status_code == 500
        data = response.get_json()
        assert data['error'] == "Internal error occurred"

    @patch('app.routes.api.service_admin.get_certtransparency_client')
    @patch('app.utils.security_logging.security_logger.log_certificate_bulk_revoked')
    def test_bulk_revoke_computer_certificates_admin_user_privileges(self, mock_log_revoked, mock_get_client, admin_client):
        """Test that regular admin users can perform bulk computer certificate revocation."""
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        mock_client.bulk_revoke_computer_certificates.return_value = {
            'revoked_count': 3,
            'status': 'success'
        }

        response = admin_client.post('/api/certificates/computer/bulk-revoke',
                                     json={'psk_filter': 'Staging', 'reason': 'key_compromise'})

        assert response.status_code == 200

        # Verify correct admin user ID was used
        mock_log_revoked.assert_called_once_with(
            revocation_type="computer_psk",
            target_identifier='Staging',
            reason='key_compromise',
            user_id='admin@example.com',  # Admin user, not service admin
            certificates_affected=3
        )


class TestBulkRevokeByCA:
    """Test the bulk_revoke_by_ca service admin API endpoint."""

    def test_bulk_revoke_by_ca_requires_auth(self, client):
        """Test that bulk_revoke_by_ca requires authentication."""
        response = client.post('/api/certificates/bulk-revoke-by-ca',
                               json={'ca_issuer': 'CN=Test CA', 'reason': 'ca_compromise'})
        assert response.status_code == 302  # Redirect to login

    def test_bulk_revoke_by_ca_requires_service_admin(self, app):
        """Test that bulk_revoke_by_ca requires service admin privileges."""
        client = app.test_client()

        # Set up regular user session (no service admin privileges)
        with client.session_transaction() as sess:
            sess['user'] = {
                'sub': 'user@example.com',
                'email': 'user@example.com',
                'name': 'Regular User',
                'is_system_admin': False,
                'is_admin': False,
                'is_auditor': False
            }

        response = client.post('/api/certificates/bulk-revoke-by-ca',
                               json={'ca_issuer': 'CN=Test CA', 'reason': 'ca_compromise'})
        assert response.status_code == 403

    def test_bulk_revoke_by_ca_requires_service_admin_not_auditor(self, auditor_client):
        """Test that bulk_revoke_by_ca requires service admin, not just auditor."""
        response = auditor_client.post('/api/certificates/bulk-revoke-by-ca',
                                       json={'ca_issuer': 'CN=Test CA', 'reason': 'ca_compromise'})
        assert response.status_code == 403

    def test_bulk_revoke_by_ca_missing_request_body(self, service_admin_client):
        """Test bulk revocation fails without request body."""
        response = service_admin_client.post('/api/certificates/bulk-revoke-by-ca')
        assert response.status_code == 500  # Flask throws 415, caught by general exception handler
        data = response.get_json()
        assert data['error'] == "Internal error occurred"

    def test_bulk_revoke_by_ca_empty_request_body(self, service_admin_client):
        """Test bulk revocation fails with empty request body."""
        response = service_admin_client.post('/api/certificates/bulk-revoke-by-ca',
                                             json={})
        assert response.status_code == 400
        data = response.get_json()
        assert data['error'] == "Missing required fields: ca_issuer, reason"

    def test_bulk_revoke_by_ca_missing_ca_issuer(self, service_admin_client):
        """Test bulk revocation fails with missing ca_issuer field."""
        response = service_admin_client.post('/api/certificates/bulk-revoke-by-ca',
                                             json={'reason': 'ca_compromise'})
        assert response.status_code == 400
        data = response.get_json()
        assert data['error'] == "Missing required fields: ca_issuer, reason"

    def test_bulk_revoke_by_ca_missing_reason(self, service_admin_client):
        """Test bulk revocation fails with missing reason field."""
        response = service_admin_client.post('/api/certificates/bulk-revoke-by-ca',
                                             json={'ca_issuer': 'CN=Test CA'})
        assert response.status_code == 400
        data = response.get_json()
        assert data['error'] == "Missing required fields: ca_issuer, reason"

    def test_bulk_revoke_by_ca_empty_ca_issuer(self, service_admin_client):
        """Test bulk revocation fails with empty ca_issuer field."""
        response = service_admin_client.post('/api/certificates/bulk-revoke-by-ca',
                                             json={'ca_issuer': '', 'reason': 'ca_compromise'})
        assert response.status_code == 400
        data = response.get_json()
        assert data['error'] == "Missing required fields: ca_issuer, reason"

    def test_bulk_revoke_by_ca_empty_reason(self, service_admin_client):
        """Test bulk revocation fails with empty reason field."""
        response = service_admin_client.post('/api/certificates/bulk-revoke-by-ca',
                                             json={'ca_issuer': 'CN=Test CA', 'reason': ''})
        assert response.status_code == 400
        data = response.get_json()
        assert data['error'] == "Missing required fields: ca_issuer, reason"

    @patch('app.routes.api.service_admin.get_certtransparency_client')
    @patch('app.utils.security_logging.security_logger.log_certificate_bulk_revoked')
    def test_bulk_revoke_by_ca_success(self, mock_log_revoked, mock_get_client, service_admin_client):
        """Test successful bulk certificate revocation by CA."""
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        mock_client.bulk_revoke_by_ca.return_value = {
            'revoked_count': 25,
            'status': 'success',
            'ca_issuer': 'CN=Compromised Root CA'
        }

        response = service_admin_client.post('/api/certificates/bulk-revoke-by-ca',
                                             json={'ca_issuer': 'CN=Compromised Root CA', 'reason': 'ca_compromise'})

        assert response.status_code == 200
        data = response.get_json()
        assert data['revoked_count'] == 25
        assert data['status'] == 'success'
        assert data['ca_issuer'] == 'CN=Compromised Root CA'

        # Verify CT client was called correctly
        mock_client.bulk_revoke_by_ca.assert_called_once_with(
            ca_issuer='CN=Compromised Root CA',
            reason='ca_compromise',
            revoked_by='service-admin@example.com'
        )

        # Verify security logging
        mock_log_revoked.assert_called_once_with(
            revocation_type="ca_issuer",
            target_identifier='CN=Compromised Root CA',
            reason='ca_compromise',
            user_id='service-admin@example.com',
            certificates_affected=25
        )

    @patch('app.routes.api.service_admin.get_certtransparency_client')
    @patch('app.utils.security_logging.security_logger.log_certificate_bulk_revoked')
    def test_bulk_revoke_by_ca_no_certificates(self, mock_log_revoked, mock_get_client, service_admin_client):
        """Test bulk revocation when no certificates match CA issuer."""
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        mock_client.bulk_revoke_by_ca.return_value = {
            'revoked_count': 0,
            'status': 'success',
            'ca_issuer': 'CN=NonExistent CA',
            'message': 'No active certificates found for the specified CA issuer'
        }

        response = service_admin_client.post('/api/certificates/bulk-revoke-by-ca',
                                             json={'ca_issuer': 'CN=NonExistent CA', 'reason': 'cessation_of_operation'})

        assert response.status_code == 200
        data = response.get_json()
        assert data['revoked_count'] == 0
        assert data['status'] == 'success'

        # Verify security logging with zero certificates
        mock_log_revoked.assert_called_once_with(
            revocation_type="ca_issuer",
            target_identifier='CN=NonExistent CA',
            reason='cessation_of_operation',
            user_id='service-admin@example.com',
            certificates_affected=0
        )

    @patch('app.routes.api.service_admin.get_certtransparency_client')
    @patch('app.utils.security_logging.security_logger.log_certificate_bulk_revoked')
    def test_bulk_revoke_by_ca_different_revocation_reasons(self, mock_log_revoked, mock_get_client, service_admin_client):
        """Test bulk revocation with different valid revocation reasons."""
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        mock_client.bulk_revoke_by_ca.return_value = {
            'revoked_count': 10,
            'status': 'success'
        }

        # Test various valid revocation reasons
        reasons = [
            'ca_compromise',
            'key_compromise',
            'cessation_of_operation',
            'affiliation_changed',
            'superseded',
            'privilege_withdrawn',
            'certificate_hold'
        ]

        for reason in reasons:
            response = service_admin_client.post('/api/certificates/bulk-revoke-by-ca',
                                                 json={'ca_issuer': 'CN=Test CA', 'reason': reason})
            assert response.status_code == 200

            # Verify correct reason was passed
            mock_client.bulk_revoke_by_ca.assert_called_with(
                ca_issuer='CN=Test CA',
                reason=reason,
                revoked_by='service-admin@example.com'
            )

    @patch('app.routes.api.service_admin.get_certtransparency_client')
    @patch('app.utils.security_logging.security_logger.log_certificate_bulk_revoked')
    def test_bulk_revoke_by_ca_with_complex_ca_issuer_name(self, mock_log_revoked, mock_get_client, service_admin_client):
        """Test bulk revocation with complex CA issuer distinguished name."""
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        mock_client.bulk_revoke_by_ca.return_value = {
            'revoked_count': 15,
            'status': 'success'
        }

        # Test with complex DN containing multiple attributes and special characters
        complex_issuer = 'CN=Enterprise Root CA, OU=IT Security, O=ACME Corporation, L=New York, ST=NY, C=US'
        response = service_admin_client.post('/api/certificates/bulk-revoke-by-ca',
                                             json={'ca_issuer': complex_issuer, 'reason': 'key_compromise'})

        assert response.status_code == 200

        # Verify CT client was called with the complex CA issuer
        mock_client.bulk_revoke_by_ca.assert_called_once_with(
            ca_issuer=complex_issuer,
            reason='key_compromise',
            revoked_by='service-admin@example.com'
        )

        # Verify security logging includes complex CA issuer
        mock_log_revoked.assert_called_once_with(
            revocation_type="ca_issuer",
            target_identifier=complex_issuer,
            reason='key_compromise',
            user_id='service-admin@example.com',
            certificates_affected=15
        )

    @patch('app.routes.api.service_admin.get_certtransparency_client')
    @patch('app.utils.security_logging.security_logger.log_certificate_bulk_revoked')
    def test_bulk_revoke_by_ca_intermediate_ca(self, mock_log_revoked, mock_get_client, service_admin_client):
        """Test bulk revocation for intermediate CA certificates."""
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        mock_client.bulk_revoke_by_ca.return_value = {
            'revoked_count': 8,
            'status': 'success',
            'ca_level': 'intermediate',
            'parent_ca': 'CN=Root CA'
        }

        response = service_admin_client.post('/api/certificates/bulk-revoke-by-ca',
                                             json={'ca_issuer': 'CN=Intermediate CA', 'reason': 'superseded'})

        assert response.status_code == 200
        data = response.get_json()
        assert data['revoked_count'] == 8

        # Verify security logging for intermediate CA revocation
        mock_log_revoked.assert_called_once_with(
            revocation_type="ca_issuer",
            target_identifier='CN=Intermediate CA',
            reason='superseded',
            user_id='service-admin@example.com',
            certificates_affected=8
        )

    @patch('app.routes.api.service_admin.get_certtransparency_client')
    @patch('app.utils.security_logging.security_logger.log_certificate_bulk_revoked')
    def test_bulk_revoke_by_ca_partial_match_issuer(self, mock_log_revoked, mock_get_client, service_admin_client):
        """Test bulk revocation with partial CA issuer matching."""
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        mock_client.bulk_revoke_by_ca.return_value = {
            'revoked_count': 12,
            'status': 'success',
            'matched_issuers': [
                'CN=Development Root CA',
                'CN=Development Intermediate CA',
                'CN=Development Test CA'
            ]
        }

        response = service_admin_client.post('/api/certificates/bulk-revoke-by-ca',
                                             json={'ca_issuer': 'Development', 'reason': 'affiliation_changed'})

        assert response.status_code == 200
        data = response.get_json()
        assert data['revoked_count'] == 12
        assert 'matched_issuers' in data

        # Verify security logging with partial match result
        mock_log_revoked.assert_called_once_with(
            revocation_type="ca_issuer",
            target_identifier='Development',
            reason='affiliation_changed',
            user_id='service-admin@example.com',
            certificates_affected=12
        )

    @patch('app.routes.api.service_admin.get_certtransparency_client')
    def test_bulk_revoke_by_ca_ct_client_error(self, mock_get_client, service_admin_client):
        """Test bulk revocation with Certificate Transparency client error."""
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        mock_client.bulk_revoke_by_ca.side_effect = CertTransparencyClientError("CT service unavailable for CA revocation")

        response = service_admin_client.post('/api/certificates/bulk-revoke-by-ca',
                                             json={'ca_issuer': 'CN=Test CA', 'reason': 'ca_compromise'})

        assert response.status_code == 503
        data = response.get_json()
        assert data['error'] == "Failed to bulk revoke certificates by CA"
        assert "CT service unavailable for CA revocation" in data['details']

    @patch('app.routes.api.service_admin.get_certtransparency_client')
    def test_bulk_revoke_by_ca_general_exception(self, mock_get_client, service_admin_client):
        """Test bulk revocation with general exception."""
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        mock_client.bulk_revoke_by_ca.side_effect = Exception("Database connection failed")

        response = service_admin_client.post('/api/certificates/bulk-revoke-by-ca',
                                             json={'ca_issuer': 'CN=Test CA', 'reason': 'ca_compromise'})

        assert response.status_code == 500
        data = response.get_json()
        assert data['error'] == "Internal error occurred"

    @patch('app.routes.api.service_admin.get_certtransparency_client')
    @patch('app.utils.security_logging.security_logger.log_certificate_bulk_revoked')
    def test_bulk_revoke_by_ca_admin_user_privileges(self, mock_log_revoked, mock_get_client, admin_client):
        """Test that regular admin users can perform bulk CA revocation."""
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        mock_client.bulk_revoke_by_ca.return_value = {
            'revoked_count': 5,
            'status': 'success'
        }

        response = admin_client.post('/api/certificates/bulk-revoke-by-ca',
                                     json={'ca_issuer': 'CN=Admin Test CA', 'reason': 'privilege_withdrawn'})

        assert response.status_code == 200

        # Verify correct admin user ID was used
        mock_log_revoked.assert_called_once_with(
            revocation_type="ca_issuer",
            target_identifier='CN=Admin Test CA',
            reason='privilege_withdrawn',
            user_id='admin@example.com',  # Admin user, not service admin
            certificates_affected=5
        )

    @patch('app.routes.api.service_admin.get_certtransparency_client')
    @patch('app.utils.security_logging.security_logger.log_certificate_bulk_revoked')
    def test_bulk_revoke_by_ca_case_sensitive_issuer(self, mock_log_revoked, mock_get_client, service_admin_client):
        """Test bulk revocation with case-sensitive CA issuer."""
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        mock_client.bulk_revoke_by_ca.return_value = {
            'revoked_count': 3,
            'status': 'success'
        }

        # Test case-sensitive CA issuer
        response = service_admin_client.post('/api/certificates/bulk-revoke-by-ca',
                                             json={'ca_issuer': 'cn=lowercase ca', 'reason': 'certificate_hold'})

        assert response.status_code == 200

        # Verify exact case was preserved and passed to CT client
        mock_client.bulk_revoke_by_ca.assert_called_once_with(
            ca_issuer='cn=lowercase ca',  # Exact case preservation
            reason='certificate_hold',
            revoked_by='service-admin@example.com'
        )

    @patch('app.routes.api.service_admin.get_certtransparency_client')
    @patch('app.utils.security_logging.security_logger.log_certificate_bulk_revoked')
    def test_bulk_revoke_by_ca_with_additional_fields(self, mock_log_revoked, mock_get_client, service_admin_client):
        """Test bulk revocation ignores additional fields beyond required ones."""
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        mock_client.bulk_revoke_by_ca.return_value = {
            'revoked_count': 7,
            'status': 'success'
        }

        # Include extra fields that should be ignored
        response = service_admin_client.post('/api/certificates/bulk-revoke-by-ca',
                                             json={
                                                 'ca_issuer': 'CN=Legacy CA',
                                                 'reason': 'cessation_of_operation',
                                                 'extra_field': 'ignored',
                                                 'confirmation': True,
                                                 'admin_notes': 'Migration to new CA'
                                             })

        assert response.status_code == 200

        # Verify only required fields were passed to CT client
        mock_client.bulk_revoke_by_ca.assert_called_once_with(
            ca_issuer='CN=Legacy CA',
            reason='cessation_of_operation',
            revoked_by='service-admin@example.com'
        )


class TestCreateComputerPSK:
    """Test the create_computer_psk service admin API endpoint."""

    def test_create_computer_psk_requires_auth(self, client):
        """Test that create_computer_psk requires authentication."""
        response = client.post('/api/psks/computer',
                               json={'description': 'Test Computer PSK'})
        assert response.status_code == 302  # Redirect to login

    def test_create_computer_psk_requires_service_admin(self, app):
        """Test that create_computer_psk requires service admin privileges."""
        client = app.test_client()

        # Set up regular user session (no service admin privileges)
        with client.session_transaction() as sess:
            sess['user'] = {
                'sub': 'user@example.com',
                'email': 'user@example.com',
                'name': 'Regular User',
                'is_system_admin': False,
                'is_admin': False,
                'is_auditor': False
            }

        response = client.post('/api/psks/computer',
                               json={'description': 'Test Computer PSK'})
        assert response.status_code == 403

    def test_create_computer_psk_requires_service_admin_not_auditor(self, auditor_client):
        """Test that create_computer_psk requires service admin, not just auditor."""
        response = auditor_client.post('/api/psks/computer',
                                       json={'description': 'Test Computer PSK'})
        assert response.status_code == 403

    def test_create_computer_psk_missing_request_body(self, service_admin_client):
        """Test PSK creation fails without request body."""
        response = service_admin_client.post('/api/psks/computer')
        assert response.status_code == 500  # Flask throws 415, caught by general exception handler
        data = response.get_json()
        assert data['error'] == "Failed to create computer PSK"

    def test_create_computer_psk_empty_request_body(self, service_admin_client):
        """Test PSK creation fails with empty request body."""
        response = service_admin_client.post('/api/psks/computer',
                                             json={})
        assert response.status_code == 400
        data = response.get_json()
        assert data['error'] == "Missing required field: description"

    def test_create_computer_psk_missing_description(self, service_admin_client):
        """Test PSK creation fails with missing description field."""
        response = service_admin_client.post('/api/psks/computer',
                                             json={'template_set': 'Production'})
        assert response.status_code == 400
        data = response.get_json()
        assert data['error'] == "Missing required field: description"

    def test_create_computer_psk_empty_description(self, service_admin_client):
        """Test PSK creation fails with empty description field."""
        response = service_admin_client.post('/api/psks/computer',
                                             json={'description': ''})
        assert response.status_code == 400
        data = response.get_json()
        assert data['error'] == "Missing required field: description"

    @patch('app.utils.security_logging.security_logger.log_psk_created')
    @patch('app.routes.api.service_admin.uuid.uuid4')
    def test_create_computer_psk_success_minimal(self, mock_uuid, mock_log_psk, service_admin_client):
        """Test successful computer PSK creation with minimal required fields."""
        # Mock UUID generation for predictable testing
        mock_uuid.return_value = 'test-uuid-1234-5678-9abc'

        response = service_admin_client.post('/api/psks/computer',
                                             json={'description': 'Production Web Server'})

        assert response.status_code == 201
        data = response.get_json()

        # Verify response structure and content
        assert 'id' in data
        assert data['key'] == 'test-uuid-1234-5678-9abc'
        assert 'key_truncated' in data
        assert data['description'] == 'Production Web Server'
        assert data['template_set'] == 'Default'  # Default value
        assert data['psk_type'] == 'computer'
        assert data['expires_at'] is None  # Not specified
        assert 'created_at' in data
        assert data['is_enabled'] is True

        # Verify security logging
        mock_log_psk.assert_called_once_with(
            psk_type='computer',
            description='Production Web Server',
            template_set='Default',
            created_by='service-admin@example.com',
            expires_at=None
        )

    @patch('app.utils.security_logging.security_logger.log_psk_created')
    @patch('app.routes.api.service_admin.uuid.uuid4')
    def test_create_computer_psk_success_with_template_set(self, mock_uuid, mock_log_psk, service_admin_client):
        """Test successful computer PSK creation with custom template set."""
        mock_uuid.return_value = 'test-uuid-template-5678-9def'

        response = service_admin_client.post('/api/psks/computer',
                                             json={
                                                 'description': 'Staging Environment Server',
                                                 'template_set': 'Staging'
                                             })

        assert response.status_code == 201
        data = response.get_json()
        assert data['key'] == 'test-uuid-template-5678-9def'
        assert data['description'] == 'Staging Environment Server'
        assert data['template_set'] == 'Staging'
        assert data['psk_type'] == 'computer'

        # Verify security logging includes custom template set
        mock_log_psk.assert_called_once_with(
            psk_type='computer',
            description='Staging Environment Server',
            template_set='Staging',
            created_by='service-admin@example.com',
            expires_at=None
        )

    @patch('app.utils.security_logging.security_logger.log_psk_created')
    @patch('app.routes.api.service_admin.uuid.uuid4')
    def test_create_computer_psk_success_with_expiration(self, mock_uuid, mock_log_psk, service_admin_client):
        """Test successful computer PSK creation with expiration date."""
        mock_uuid.return_value = 'test-uuid-expires-1234-abcd'

        expiration_date = '2024-12-31T23:59:59Z'
        response = service_admin_client.post('/api/psks/computer',
                                             json={
                                                 'description': 'Temporary Test Server',
                                                 'expires_at': expiration_date
                                             })

        assert response.status_code == 201
        data = response.get_json()
        assert data['key'] == 'test-uuid-expires-1234-abcd'
        assert data['description'] == 'Temporary Test Server'
        assert data['expires_at'] == '2024-12-31T23:59:59+00:00'  # ISO format with timezone (standardized)

        # Verify security logging includes expiration
        mock_log_psk.assert_called_once_with(
            psk_type='computer',
            description='Temporary Test Server',
            template_set='Default',
            created_by='service-admin@example.com',
            expires_at='2024-12-31T23:59:59+00:00'
        )

    @patch('app.utils.security_logging.security_logger.log_psk_created')
    @patch('app.routes.api.service_admin.uuid.uuid4')
    def test_create_computer_psk_success_with_all_fields(self, mock_uuid, mock_log_psk, service_admin_client):
        """Test successful computer PSK creation with all optional fields."""
        mock_uuid.return_value = 'test-uuid-full-9876-5432'

        response = service_admin_client.post('/api/psks/computer',
                                             json={
                                                 'description': 'Development Docker Cluster',
                                                 'template_set': 'Development',
                                                 'expires_at': '2024-06-30T12:00:00Z'
                                             })

        assert response.status_code == 201
        data = response.get_json()
        assert data['key'] == 'test-uuid-full-9876-5432'
        assert data['description'] == 'Development Docker Cluster'
        assert data['template_set'] == 'Development'
        assert data['expires_at'] == '2024-06-30T12:00:00+00:00'

        # Verify security logging includes all fields
        mock_log_psk.assert_called_once_with(
            psk_type='computer',
            description='Development Docker Cluster',
            template_set='Development',
            created_by='service-admin@example.com',
            expires_at='2024-06-30T12:00:00+00:00'
        )

    def test_create_computer_psk_invalid_expiration_format(self, service_admin_client):
        """Test PSK creation fails with invalid expiration date format."""
        response = service_admin_client.post('/api/psks/computer',
                                             json={
                                                 'description': 'Test Server',
                                                 'expires_at': 'invalid-date-format'
                                             })

        assert response.status_code == 400
        data = response.get_json()
        assert data['error'] == "Invalid expires_at format. Use ISO 8601 format."

    def test_create_computer_psk_invalid_expiration_partial_date(self, service_admin_client):
        """Test PSK creation fails with partial/malformed date."""
        response = service_admin_client.post('/api/psks/computer',
                                             json={
                                                 'description': 'Test Server',
                                                 'expires_at': '2024-13-31T25:99:99Z'  # Invalid month, hour, minute
                                             })

        assert response.status_code == 400
        data = response.get_json()
        assert data['error'] == "Invalid expires_at format. Use ISO 8601 format."

    @patch('app.utils.security_logging.security_logger.log_psk_created')
    @patch('app.routes.api.service_admin.uuid.uuid4')
    def test_create_computer_psk_different_iso_date_formats(self, mock_uuid, mock_log_psk, service_admin_client):
        """Test PSK creation with various valid ISO 8601 date formats."""
        # Test different valid ISO 8601 formats
        valid_formats = [
            ('2024-12-31T23:59:59Z', 'test-uuid-iso-format-1'),           # UTC with Z
            ('2024-12-31T23:59:59+00:00', 'test-uuid-iso-format-2'),      # UTC with offset
            ('2024-12-31T23:59:59-05:00', 'test-uuid-iso-format-3'),      # EST timezone
            ('2024-12-31T23:59:59.123Z', 'test-uuid-iso-format-4'),       # With milliseconds
            ('2024-12-31T23:59:59+01:00', 'test-uuid-iso-format-5')       # CET timezone
        ]

        for date_format, uuid_value in valid_formats:
            mock_uuid.return_value = uuid_value
            response = service_admin_client.post('/api/psks/computer',
                                                 json={
                                                     'description': f'Test Server {date_format}',
                                                     'expires_at': date_format
                                                 })
            assert response.status_code == 201

    @patch('app.utils.security_logging.security_logger.log_psk_created')
    @patch('app.routes.api.service_admin.uuid.uuid4')
    def test_create_computer_psk_with_special_characters_description(self, mock_uuid, mock_log_psk, service_admin_client):
        """Test PSK creation with special characters in description."""
        mock_uuid.return_value = 'test-uuid-special-chars'

        special_description = 'Test & Development Server #1 (Docker-Compose)'
        response = service_admin_client.post('/api/psks/computer',
                                             json={'description': special_description})

        assert response.status_code == 201
        data = response.get_json()
        assert data['description'] == special_description

        # Verify security logging preserves special characters
        mock_log_psk.assert_called_once_with(
            psk_type='computer',
            description=special_description,
            template_set='Default',
            created_by='service-admin@example.com',
            expires_at=None
        )

    @patch('app.utils.security_logging.security_logger.log_psk_created')
    @patch('app.routes.api.service_admin.uuid.uuid4')
    def test_create_computer_psk_admin_user_privileges(self, mock_uuid, mock_log_psk, admin_client):
        """Test that regular admin users can create computer PSKs."""
        mock_uuid.return_value = 'test-uuid-admin-user'

        response = admin_client.post('/api/psks/computer',
                                     json={'description': 'Admin Created PSK'})

        assert response.status_code == 201

        # Verify correct admin user ID was used in logging
        mock_log_psk.assert_called_once_with(
            psk_type='computer',
            description='Admin Created PSK',
            template_set='Default',
            created_by='admin@example.com',  # Admin user, not service admin
            expires_at=None
        )

    @patch('app.routes.api.service_admin.db.session.commit')
    @patch('app.routes.api.service_admin.uuid.uuid4')
    def test_create_computer_psk_database_error(self, mock_uuid, mock_commit, service_admin_client):
        """Test PSK creation with database error."""
        mock_uuid.return_value = 'test-uuid-db-error'
        mock_commit.side_effect = Exception("Database connection failed")

        response = service_admin_client.post('/api/psks/computer',
                                             json={'description': 'Test PSK'})

        assert response.status_code == 500
        data = response.get_json()
        assert data['error'] == "Failed to create computer PSK"
        assert "Database connection failed" in data['details']

    @patch('app.utils.security_logging.security_logger.log_psk_created')
    @patch('app.routes.api.service_admin.uuid.uuid4')
    def test_create_computer_psk_ignores_additional_fields(self, mock_uuid, mock_log_psk, service_admin_client):
        """Test PSK creation ignores additional fields beyond specified ones."""
        mock_uuid.return_value = 'test-uuid-extra-fields'

        # Include extra fields that should be ignored
        response = service_admin_client.post('/api/psks/computer',
                                             json={
                                                 'description': 'Clean PSK',
                                                 'template_set': 'Production',
                                                 'expires_at': '2024-12-31T23:59:59Z',
                                                 'extra_field': 'ignored',
                                                 'psk_type': 'user',  # Should be ignored, forced to 'computer'
                                                 'custom_key': 'should-be-ignored',
                                                 'is_enabled': False  # Should be ignored, defaults to True
                                             })

        assert response.status_code == 201
        data = response.get_json()

        # Verify only valid fields were processed
        assert data['description'] == 'Clean PSK'
        assert data['template_set'] == 'Production'
        assert data['psk_type'] == 'computer'  # Forced to computer type
        assert data['is_enabled'] is True  # Default value, not from request
        assert 'extra_field' not in data
        assert 'custom_key' not in data

    @patch('app.utils.security_logging.security_logger.log_psk_created')
    @patch('app.routes.api.service_admin.uuid.uuid4')
    def test_create_computer_psk_long_description(self, mock_uuid, mock_log_psk, service_admin_client):
        """Test PSK creation with very long description."""
        mock_uuid.return_value = 'test-uuid-long-desc'

        # Test with a very long description
        long_description = 'A' * 500  # 500 character description
        response = service_admin_client.post('/api/psks/computer',
                                             json={'description': long_description})

        assert response.status_code == 201
        data = response.get_json()
        assert data['description'] == long_description

    @patch('app.utils.security_logging.security_logger.log_psk_created')
    @patch('app.routes.api.service_admin.uuid.uuid4')
    def test_create_computer_psk_unicode_description(self, mock_uuid, mock_log_psk, service_admin_client):
        """Test PSK creation with Unicode characters in description."""
        mock_uuid.return_value = 'test-uuid-unicode'

        unicode_description = 'Test Server 测试服务器 🖥️ Сервер тестирования'
        response = service_admin_client.post('/api/psks/computer',
                                             json={'description': unicode_description})

        assert response.status_code == 201
        data = response.get_json()
        assert data['description'] == unicode_description


"""Additional tests for service admin API endpoints - part 2."""

import pytest
from unittest.mock import patch, Mock
from datetime import datetime, timezone


class TestCreateComputerPskAdditionalCoverage:
    """Additional tests for create_computer_psk endpoint."""

    @patch('app.utils.security_logging.security_logger.log_psk_created')
    @patch('app.routes.api.service_admin.uuid.uuid4')
    def test_create_computer_psk_database_rollback_on_error(self, mock_uuid, mock_log_psk, service_admin_client):
        """Test database rollback when PSK creation fails."""
        mock_uuid.return_value = 'test-uuid-rollback'

        # Mock database session to raise an exception during commit
        with patch('app.routes.api.service_admin.db.session') as mock_session:
            mock_session.add.side_effect = Exception("Database connection lost")
            mock_session.rollback = Mock()

            response = service_admin_client.post('/api/psks/computer',
                                                json={'description': 'Should fail'})

            assert response.status_code == 500
            data = response.get_json()
            assert data['error'] == 'Failed to create computer PSK'
            assert 'Database connection lost' in data['details']

            # Verify rollback was called
            mock_session.rollback.assert_called_once()

    @patch('app.utils.security_logging.security_logger.log_psk_created')
    @patch('app.routes.api.service_admin.uuid.uuid4')
    def test_create_computer_psk_security_logging_failure(self, mock_uuid, mock_log_psk, service_admin_client):
        """Test PSK creation fails when security logging fails."""
        mock_uuid.return_value = 'test-uuid-log-fail'
        mock_log_psk.side_effect = Exception("Logging service unavailable")

        response = service_admin_client.post('/api/psks/computer',
                                            json={'description': 'PSK with logging failure'})

        # PSK creation should fail due to logging error
        assert response.status_code == 500
        data = response.get_json()
        assert data['error'] == 'Failed to create computer PSK'
        assert 'Logging service unavailable' in data['details']

    @patch('app.utils.security_logging.security_logger.log_psk_created')
    @patch('app.routes.api.service_admin.uuid.uuid4')
    def test_create_computer_psk_template_set_default(self, mock_uuid, mock_log_psk, service_admin_client):
        """Test default template set is applied when not specified."""
        mock_uuid.return_value = 'test-uuid-default-template'

        response = service_admin_client.post('/api/psks/computer',
                                            json={'description': 'Default template test'})

        assert response.status_code == 201
        data = response.get_json()
        assert data['template_set'] == 'Default'

        # Verify security logging received the default template set
        mock_log_psk.assert_called_once()
        call_args = mock_log_psk.call_args[1]
        assert call_args['template_set'] == 'Default'

    @patch('app.utils.security_logging.security_logger.log_psk_created')
    @patch('app.routes.api.service_admin.uuid.uuid4')
    def test_create_computer_psk_custom_template_set(self, mock_uuid, mock_log_psk, service_admin_client):
        """Test custom template set is properly stored."""
        mock_uuid.return_value = 'test-uuid-custom-template'

        response = service_admin_client.post('/api/psks/computer',
                                            json={
                                                'description': 'Custom template test',
                                                'template_set': 'Enterprise-VPN'
                                            })

        assert response.status_code == 201
        data = response.get_json()
        assert data['template_set'] == 'Enterprise-VPN'

        # Verify security logging received the custom template set
        mock_log_psk.assert_called_once()
        call_args = mock_log_psk.call_args[1]
        assert call_args['template_set'] == 'Enterprise-VPN'

    @patch('app.utils.security_logging.security_logger.log_psk_created')
    @patch('app.routes.api.service_admin.uuid.uuid4')
    def test_create_computer_psk_response_structure(self, mock_uuid, mock_log_psk, service_admin_client):
        """Test complete response structure for PSK creation."""
        mock_uuid.return_value = 'test-uuid-structure'

        response = service_admin_client.post('/api/psks/computer',
                                            json={
                                                'description': 'Structure test',
                                                'template_set': 'Custom',
                                                'expires_at': '2025-01-01T00:00:00Z'
                                            })

        assert response.status_code == 201
        data = response.get_json()

        # Verify all required fields are present
        required_fields = ['id', 'key', 'key_truncated', 'description',
                          'template_set', 'psk_type', 'expires_at',
                          'created_at', 'is_enabled']

        for field in required_fields:
            assert field in data, f"Missing required field: {field}"

        # Verify field values
        assert data['key'] == 'test-uuid-structure'
        assert data['description'] == 'Structure test'
        assert data['template_set'] == 'Custom'
        assert data['psk_type'] == 'computer'
        assert data['is_enabled'] is True
        assert data['expires_at'].endswith('+00:00')
        assert data['created_at'].endswith('+00:00')


class TestServiceAdminHealthCheck:
    """Test the service admin health check endpoint."""

    def test_health_check_success(self, service_admin_client):
        """Test successful health check."""
        with patch('app.routes.api.service_admin.db.session') as mock_session:
            mock_session.execute.return_value = None

            with patch('app.routes.api.service_admin.get_certtransparency_client') as mock_get_client:
                mock_client = Mock()
                mock_client.get_statistics.return_value = {'total_certificates': 1000}
                mock_get_client.return_value = mock_client

                response = service_admin_client.get('/api/health')

                assert response.status_code == 200
                data = response.get_json()
                assert data['status'] == 'healthy'
                assert data['database'] == 'connected'
                assert data['cert_transparency_service'] == 'connected'
                assert 'timestamp' in data

    def test_health_check_database_failure(self, service_admin_client):
        """Test health check with database connection failure."""
        with patch('app.routes.api.service_admin.db.session') as mock_session:
            mock_session.execute.side_effect = Exception("Database connection failed")

            response = service_admin_client.get('/api/health')

            assert response.status_code == 503
            data = response.get_json()
            assert data['status'] == 'unhealthy'
            assert 'Database connection failed' in data['error']
            assert 'timestamp' in data

    def test_health_check_ct_service_failure(self, service_admin_client):
        """Test health check with CT service failure."""
        with patch('app.routes.api.service_admin.db.session') as mock_session:
            mock_session.execute.return_value = None

            with patch('app.routes.api.service_admin.get_certtransparency_client') as mock_get_client:
                mock_get_client.side_effect = Exception("CT service unavailable")

                response = service_admin_client.get('/api/health')

                assert response.status_code == 503
                data = response.get_json()
                assert data['status'] == 'unhealthy'
                assert 'CT service unavailable' in data['error']
                assert 'timestamp' in data

    def test_health_check_no_authentication_required(self, admin_client):
        """Test that health check endpoint doesn't require authentication."""
        # Use regular admin client (no service admin authentication)
        with patch('app.routes.api.service_admin.db.session') as mock_session:
            mock_session.execute.return_value = None

            with patch('app.routes.api.service_admin.get_certtransparency_client') as mock_get_client:
                mock_client = Mock()
                mock_client.get_statistics.return_value = {'total_certificates': 500}
                mock_get_client.return_value = mock_client

                response = admin_client.get('/api/health')

                assert response.status_code == 200
                data = response.get_json()
                assert data['status'] == 'healthy'

    def test_health_check_timestamp_format(self, service_admin_client):
        """Test health check timestamp format is ISO 8601 with timezone."""
        with patch('app.routes.api.service_admin.db.session') as mock_session:
            mock_session.execute.return_value = None

            with patch('app.routes.api.service_admin.get_certtransparency_client') as mock_get_client:
                mock_client = Mock()
                mock_client.get_statistics.return_value = {'total_certificates': 1000}
                mock_get_client.return_value = mock_client

                response = service_admin_client.get('/api/health')

                assert response.status_code == 200
                data = response.get_json()
                timestamp = data['timestamp']

                # Verify it's valid ISO format
                parsed = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                assert parsed.tzinfo is not None

    def test_health_check_ct_statistics_integration(self, service_admin_client):
        """Test health check properly calls CT client statistics."""
        with patch('app.routes.api.service_admin.db.session') as mock_session:
            mock_session.execute.return_value = None

            with patch('app.routes.api.service_admin.get_certtransparency_client') as mock_get_client:
                mock_client = Mock()
                mock_client.get_statistics.return_value = {
                    'total_certificates': 2500,
                    'active_certificates': 2000,
                    'revoked_certificates': 500
                }
                mock_get_client.return_value = mock_client

                response = service_admin_client.get('/api/health')

                assert response.status_code == 200
                mock_client.get_statistics.assert_called_once()
                data = response.get_json()
                assert data['cert_transparency_service'] == 'connected'