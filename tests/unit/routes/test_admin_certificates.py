"""
Unit tests for Certificate Transparency admin routes.
"""

import pytest
import os
from unittest.mock import Mock, patch
from flask import url_for

from app import create_app
from app.utils.certtransparency_client import CertTransparencyClientError


@pytest.fixture
def app():
    """Creates a test Flask app using the real create_app function."""
    # Set test keys for secure configuration
    os.environ['FLASK_SECRET_KEY'] = 'test-secret-key-for-admin-cert-tests-only'
    os.environ['FERNET_ENCRYPTION_KEY'] = 'YenxIAHqvrO7OHbNXvzAxEhthHCaitvnV9CALkQvvCc='
    
    app = create_app('development')
    app.config.update({
        'TESTING': True,
        'OIDC_ADMIN_GROUP': 'vpn-admins',
        'WTF_CSRF_ENABLED': False
    })
    
    return app


@pytest.fixture
def client(app):
    """Creates a test client."""
    return app.test_client()


@pytest.fixture
def admin_client(app):
    """Creates a test client with admin session configured."""
    client = app.test_client()
    
    # Set up admin session
    with client.session_transaction() as sess:
        sess['user'] = {'groups': ['vpn-admins']}
    
    return client


class TestCertificateTransparencyRoutes:
    """Test certificate transparency admin routes."""

    def test_list_certificates_requires_admin(self, client):
        """Test that certificates list requires admin access."""
        # Without admin session, should be redirected or get 403
        response = client.get('/admin/certificates')
        assert response.status_code in [302, 403]

    @patch('app.routes.admin.get_certtransparency_client')
    def test_list_certificates_success(self, mock_get_client, admin_client):
        """Test successful certificate listing."""
        # Mock the Certificate Transparency client
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        
        mock_certificates_response = {
            'certificates': [
                {
                    'subject': {
                        'common_name': 'test@example.com'
                    },
                    'certificate_type': 'client',
                    'serial_number': '123456789',
                    'issued_at': '2025-01-01T00:00:00Z',
                    'validity': {
                        'not_after': '2026-01-01T00:00:00Z'
                    },
                    'fingerprint_sha256': 'abc123',
                    'revoked_at': None
                }
            ],
            'pagination': {
                'page': 1,
                'pages': 1,
                'per_page': 50,
                'total': 1,
                'has_next': False,
                'has_prev': False
            },
            'filters': {}
        }
        
        mock_stats_response = {
            'total_certificates': 1,
            'by_type': {'client': 1, 'server': 0, 'intermediate': 0},
            'by_status': {'active': 1, 'revoked': 0}
        }
        
        mock_client.list_certificates.return_value = mock_certificates_response
        mock_client.get_statistics.return_value = mock_stats_response
        
        response = admin_client.get('/admin/certificates')
        
        assert response.status_code == 200
        assert b'Administrate Issued Certificates' in response.data
        assert b'test@example.com' in response.data
        mock_client.list_certificates.assert_called_once()
        mock_client.get_statistics.assert_called_once()

    @patch('app.routes.admin.get_certtransparency_client')
    def test_list_certificates_with_filters(self, mock_get_client, admin_client):
        """Test certificate listing with filters."""
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        
        mock_client.list_certificates.return_value = {
            'certificates': [],
            'pagination': {'page': 1, 'pages': 0, 'total': 0},
            'filters': {'type': 'client', 'subject': 'test'}
        }
        mock_client.get_statistics.return_value = {}
        
        response = admin_client.get('/admin/certificates?type=client&subject=test&page=2')
        
        assert response.status_code == 200
        mock_client.list_certificates.assert_called_once_with(
            page=2, 
            limit=50, 
            type='client', 
            subject='test'
        )

    @patch('app.routes.admin.get_certtransparency_client')
    def test_list_certificates_client_error(self, mock_get_client, admin_client):
        """Test certificate listing when client fails."""
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        
        mock_client.list_certificates.side_effect = CertTransparencyClientError("Service unavailable")
        
        response = admin_client.get('/admin/certificates')
        
        assert response.status_code == 200
        assert b'Unable to fetch certificates' in response.data

    def test_certificate_detail_requires_admin(self, client):
        """Test that certificate detail requires admin access."""
        response = client.get('/admin/certificates/abc123')
        assert response.status_code in [302, 403]

    @patch('app.routes.admin.get_certtransparency_client')
    def test_certificate_detail_success(self, mock_get_client, admin_client):
        """Test successful certificate detail view."""
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        
        mock_certificate_response = {
            'certificate': {
                'subject': {
                    'common_name': 'test@example.com'
                },
                'issuer': {
                    'common_name': 'Test CA'
                },
                'certificate_type': 'client',
                'serial_number': '123456789',
                'issued_at': '2025-01-01T00:00:00Z',
                'validity': {
                    'not_before': '2025-01-01T00:00:00Z',
                    'not_after': '2026-01-01T00:00:00Z'
                },
                'fingerprint_sha256': 'abc123',
                'certificate_pem': '-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----',
                'revoked_at': None
            }
        }
        
        mock_client.get_certificate_by_fingerprint.return_value = mock_certificate_response
        
        response = admin_client.get('/admin/certificates/abc123')
        
        assert response.status_code == 200
        assert b'Certificate Details' in response.data
        assert b'test@example.com' in response.data
        assert b'-----BEGIN CERTIFICATE-----' in response.data
        mock_client.get_certificate_by_fingerprint.assert_called_once_with('abc123', include_pem=True)

    @patch('app.routes.admin.get_certtransparency_client')
    def test_certificate_detail_not_found(self, mock_get_client, admin_client):
        """Test certificate detail when certificate not found."""
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        
        mock_client.get_certificate_by_fingerprint.return_value = {'certificate': None}
        
        response = admin_client.get('/admin/certificates/nonexistent')
        
        assert response.status_code == 404

    @patch('app.routes.admin.get_certtransparency_client')
    def test_certificate_detail_client_error(self, mock_get_client, admin_client):
        """Test certificate detail when client fails."""
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        
        mock_client.get_certificate_by_fingerprint.side_effect = CertTransparencyClientError("Service unavailable")
        
        response = admin_client.get('/admin/certificates/abc123')
        
        assert response.status_code == 302  # Redirect back to list
        
    @patch('app.routes.admin.get_certtransparency_client')
    def test_list_certificates_pagination_params(self, mock_get_client, admin_client):
        """Test that pagination parameters are handled correctly."""
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        
        mock_client.list_certificates.return_value = {
            'certificates': [],
            'pagination': {'page': 2, 'pages': 5, 'total': 200},
            'filters': {}
        }
        mock_client.get_statistics.return_value = {}
        
        # Test with custom limit that should be capped at 100
        response = admin_client.get('/admin/certificates?limit=200&page=2')
        
        assert response.status_code == 200
        mock_client.list_certificates.assert_called_once_with(
            page=2, 
            limit=100  # Should be capped at 100
        )

    @patch('app.routes.admin.get_certtransparency_client')
    def test_list_certificates_filter_revoked(self, mock_get_client, admin_client):
        """Test filtering out revoked certificates."""
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        
        mock_client.list_certificates.return_value = {
            'certificates': [],
            'pagination': {'page': 1, 'pages': 0, 'total': 0},
            'filters': {'include_revoked': 'false'}
        }
        mock_client.get_statistics.return_value = {}
        
        response = admin_client.get('/admin/certificates?include_revoked=false')
        
        assert response.status_code == 200
        mock_client.list_certificates.assert_called_once_with(
            page=1, 
            limit=50, 
            include_revoked='false'
        )

    @patch('app.routes.admin.get_certtransparency_client')
    def test_list_certificates_date_filters(self, mock_get_client, admin_client):
        """Test date range filtering."""
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        
        mock_client.list_certificates.return_value = {
            'certificates': [],
            'pagination': {'page': 1, 'pages': 0, 'total': 0},
            'filters': {'from_date': '2025-01-01', 'to_date': '2025-12-31'}
        }
        mock_client.get_statistics.return_value = {}
        
        response = admin_client.get('/admin/certificates?from_date=2025-01-01&to_date=2025-12-31')
        
        assert response.status_code == 200
        mock_client.list_certificates.assert_called_once_with(
            page=1, 
            limit=50, 
            from_date='2025-01-01',
            to_date='2025-12-31'
        )

    @patch('app.routes.admin.get_certtransparency_client')
    def test_list_certificates_stats_failure_handled(self, mock_get_client, admin_client):
        """Test that statistics failure doesn't break the page."""
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        
        mock_client.list_certificates.return_value = {
            'certificates': [],
            'pagination': {'page': 1, 'pages': 0, 'total': 0},
            'filters': {}
        }
        # Stats call fails but shouldn't break the page
        mock_client.get_statistics.side_effect = CertTransparencyClientError("Stats unavailable")
        
        response = admin_client.get('/admin/certificates')
        
        assert response.status_code == 200
        # Should still show the page but without stats
        assert b'Administrate Issued Certificates' in response.data

    @patch('app.routes.admin.get_certtransparency_client')
    def test_list_certificates_with_issuer_filter(self, mock_get_client, admin_client):
        """Test certificate listing with issuer filter to cover line 69."""
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        
        mock_client.list_certificates.return_value = {
            'certificates': [],
            'pagination': {'page': 1, 'pages': 0, 'total': 0},
            'filters': {'issuer': 'Test CA'}
        }
        mock_client.get_statistics.return_value = {}
        
        response = admin_client.get('/admin/certificates?issuer=Test%20CA')
        
        assert response.status_code == 200
        mock_client.list_certificates.assert_called_once_with(
            page=1, 
            limit=50, 
            issuer='Test CA'
        )

    @patch('app.routes.admin.get_certtransparency_client')
    def test_list_certificates_with_sort_and_order(self, mock_get_client, admin_client):
        """Test certificate listing with sort and order filters to cover lines 79 and 81."""
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        
        mock_client.list_certificates.return_value = {
            'certificates': [],
            'pagination': {'page': 1, 'pages': 0, 'total': 0},
            'filters': {'sort': 'issued_at', 'order': 'desc'}
        }
        mock_client.get_statistics.return_value = {}
        
        response = admin_client.get('/admin/certificates?sort=issued_at&order=desc')
        
        assert response.status_code == 200
        mock_client.list_certificates.assert_called_once_with(
            page=1, 
            limit=50, 
            sort='issued_at',
            order='desc'
        )