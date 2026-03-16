"""
Tests for VULN-08: CSRF Token Exposed in HTML Comments.

Three templates contain debug HTML comments that print the live CSRF token
on every page load. Any XSS payload can extract the token and forge
authenticated requests.

Fix: remove the debug comment lines from the templates.
"""
import os
import pytest
from unittest.mock import Mock, patch

from app import create_app
from app.extensions import db
from app.models.presharedkey import PreSharedKey


FINGERPRINT = 'ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234'


@pytest.fixture
def app():
    """Test Flask app via create_app."""
    os.environ['FLASK_SECRET_KEY'] = 'test-secret-key-vuln08-only'
    os.environ['FERNET_ENCRYPTION_KEY'] = 'YenxIAHqvrO7OHbNXvzAxEhthHCaitvnV9CALkQvvCc='
    app = create_app('development')
    app.config.update({
        'TESTING': True,
        'OIDC_ADMIN_GROUP': 'vpn-admins',
        'WTF_CSRF_ENABLED': False,
    })
    with app.app_context():
        db.create_all()
    return app


@pytest.fixture
def admin_client(app):
    """Test client with admin session."""
    client = app.test_client()
    with client.session_transaction() as sess:
        sess['user'] = {
            'sub': 'admin@example.com',
            'groups': ['vpn-admins'],
            'name': 'Admin User',
            'email': 'admin@example.com',
        }
    return client


@pytest.fixture
def user_client(app):
    """Test client with regular user session."""
    client = app.test_client()
    with client.session_transaction() as sess:
        sess['user'] = {
            'sub': 'user@example.com',
            'groups': [],
            'name': 'Regular User',
            'email': 'user@example.com',
        }
    return client


class TestVuln08CsrfTokenNotInHtmlComments:
    """VULN-08: Debug CSRF token HTML comments must be absent from rendered pages.

    Verifies that none of the three affected templates expose the live CSRF
    token value in an HTML comment. Such comments allow any XSS payload to
    trivially extract the token and forge authenticated form submissions.
    """

    @patch('app.routes.admin.get_certtransparency_client')
    def test_admin_certificate_detail_no_csrf_debug_comment(self, mock_get_client, admin_client):
        """admin/certificate_detail.html must not contain CSRF debug comments.

        Covers both the admin-revocation form comment and the bulk-revocation
        form comment that were both in this template.
        """
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        mock_client.get_certificate_by_fingerprint.return_value = {
            'certificate': {
                'subject': {'common_name': 'test@example.com'},
                'issuer': {'common_name': 'Test CA'},
                'certificate_type': 'client',
                'serial_number': '123456789',
                'issued_at': '2025-01-01T00:00:00Z',
                'validity': {
                    'not_before': '2025-01-01T00:00:00Z',
                    'not_after': '2026-01-01T00:00:00Z',
                },
                'fingerprint_sha256': FINGERPRINT,
                'revoked_at': None,
            }
        }

        response = admin_client.get(f'/admin/certificates/{FINGERPRINT}')

        assert response.status_code == 200
        assert b'Debug: CSRF token' not in response.data
        assert b'Debug: Bulk CSRF token' not in response.data

    @patch('app.routes.profile.get_certtransparency_client')
    def test_profile_certificate_detail_no_csrf_debug_comment(self, mock_get_client, user_client):
        """profile/certificate_detail.html must not contain a CSRF debug comment."""
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        mock_client.get_certificate_by_fingerprint.return_value = {
            'certificate': {
                'issuing_user_id': 'user@example.com',
                'subject': {'common_name': 'user@example.com'},
                'issuer': {'common_name': 'Test CA'},
                'certificate_type': 'client',
                'serial_number': '987654321',
                'issued_at': '2025-01-01T00:00:00Z',
                'validity': {
                    'not_before': '2025-01-01T00:00:00Z',
                    'not_after': '2026-01-01T00:00:00Z',
                },
                'fingerprint_sha256': FINGERPRINT,
                'revoked_at': None,
            }
        }

        response = user_client.get(f'/profile/certificates/{FINGERPRINT}')

        assert response.status_code == 200
        assert b'Debug: User CSRF token' not in response.data

    @patch('app.routes.profile.get_certtransparency_client')
    def test_profile_certificates_no_csrf_debug_comment(self, mock_get_client, user_client):
        """profile/certificates.html must not contain a CSRF debug comment."""
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        mock_client.list_certificates.return_value = {
            'certificates': [],
            'pagination': {'page': 1, 'pages': 0, 'total': 0},
        }

        response = user_client.get('/profile/certificates')

        assert response.status_code == 200
        assert b'Debug: User CSRF token' not in response.data
