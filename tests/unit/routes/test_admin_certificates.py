"""
Unit tests for Certificate Transparency admin routes.
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
    os.environ['FLASK_SECRET_KEY'] = 'test-secret-key-for-admin-cert-tests-only'
    os.environ['FERNET_ENCRYPTION_KEY'] = 'YenxIAHqvrO7OHbNXvzAxEhthHCaitvnV9CALkQvvCc='
    
    app = create_app('development')
    app.config.update({
        'TESTING': True,
        'OIDC_ADMIN_GROUP': 'vpn-admins',
        'WTF_CSRF_ENABLED': False
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
def admin_client(app):
    """Creates a test client with admin session configured."""
    client = app.test_client()
    
    # Set up admin session
    with client.session_transaction() as sess:
        sess['user'] = {
            'sub': 'admin@example.com',
            'groups': ['vpn-admins'],
            'name': 'Admin User',
            'email': 'admin@example.com'
        }
    
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
                    'fingerprint_sha256': '1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF',
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
        response = client.get('/admin/certificates/1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF')
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
                'fingerprint_sha256': '1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF',
                'certificate_pem': '-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----',
                'revoked_at': None
            }
        }
        
        mock_client.get_certificate_by_fingerprint.return_value = mock_certificate_response
        
        response = admin_client.get('/admin/certificates/1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF')
        
        assert response.status_code == 200
        assert b'Certificate Details' in response.data
        assert b'test@example.com' in response.data
        assert b'-----BEGIN CERTIFICATE-----' in response.data
        mock_client.get_certificate_by_fingerprint.assert_called_once_with('1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF', include_pem=True)

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
        
        response = admin_client.get('/admin/certificates/1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF')
        
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


class TestBulkRevokeByCa:
    """Test bulk certificate revocation by CA issuer."""

    @patch('app.routes.admin.get_certtransparency_client')
    def test_bulk_revoke_by_ca_get_renders_form(self, mock_get_client, admin_client):
        """Test GET request renders the bulk revocation form."""
        response = admin_client.get('/admin/bulk-revoke-by-ca')
        assert response.status_code == 200

    @patch('app.routes.admin.get_certtransparency_client')
    @patch('app.utils.security_logging.security_logger.log_certificate_bulk_revoked')
    def test_bulk_revoke_by_ca_post_success(self, mock_log_bulk, mock_get_client, admin_client):
        """Test successful bulk revocation by CA."""
        # Mock CT client
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        mock_client.bulk_revoke_by_ca.return_value = {'revoked_count': 5}

        response = admin_client.post('/admin/bulk-revoke-by-ca', data={
            'ca_issuer': 'CN=Test CA',
            'reason': 'key_compromise',
            'comment': 'Security incident'
        })

        assert response.status_code == 302  # Redirect to certificates list
        mock_client.bulk_revoke_by_ca.assert_called_once_with(
            ca_issuer='CN=Test CA',
            reason='key_compromise',
            revoked_by='admin@example.com'
        )
        mock_log_bulk.assert_called_once()

    @patch('app.routes.admin.get_certtransparency_client')
    def test_bulk_revoke_by_ca_missing_ca_issuer(self, mock_get_client, admin_client):
        """Test bulk revocation with missing CA issuer."""
        response = admin_client.post('/admin/bulk-revoke-by-ca', data={
            'ca_issuer': '',
            'reason': 'key_compromise'
        })

        assert response.status_code == 200
        assert b'CA Issuer is required' in response.data

    @patch('app.routes.admin.get_certtransparency_client')
    def test_bulk_revoke_by_ca_missing_reason(self, mock_get_client, admin_client):
        """Test bulk revocation with missing reason."""
        response = admin_client.post('/admin/bulk-revoke-by-ca', data={
            'ca_issuer': 'CN=Test CA',
            'reason': ''
        })

        assert response.status_code == 200
        assert b'Revocation reason is required' in response.data

    @patch('app.routes.admin.get_certtransparency_client')
    def test_bulk_revoke_by_ca_invalid_reason(self, mock_get_client, admin_client):
        """Test bulk revocation with invalid reason."""
        response = admin_client.post('/admin/bulk-revoke-by-ca', data={
            'ca_issuer': 'CN=Test CA',
            'reason': 'invalid_reason'
        })

        assert response.status_code == 200
        assert b'Invalid revocation reason' in response.data

    @patch('app.routes.admin.get_certtransparency_client')
    def test_bulk_revoke_by_ca_ct_client_error(self, mock_get_client, admin_client):
        """Test bulk revocation with Certificate Transparency client error."""
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        mock_client.bulk_revoke_by_ca.side_effect = CertTransparencyClientError("CT service error")

        response = admin_client.post('/admin/bulk-revoke-by-ca', data={
            'ca_issuer': 'CN=Test CA',
            'reason': 'key_compromise'
        })

        assert response.status_code == 200
        assert b'Certificate Transparency service unavailable' in response.data

    @patch('app.routes.admin.get_certtransparency_client')
    def test_bulk_revoke_by_ca_unexpected_error(self, mock_get_client, admin_client):
        """Test bulk revocation with unexpected error."""
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        mock_client.bulk_revoke_by_ca.side_effect = Exception("Unexpected error")

        response = admin_client.post('/admin/bulk-revoke-by-ca', data={
            'ca_issuer': 'CN=Test CA',
            'reason': 'key_compromise'
        })

        assert response.status_code == 200
        assert b'Internal server error during bulk CA revocation' in response.data

    def test_bulk_revoke_by_ca_requires_admin(self, client):
        """Test that bulk revocation requires admin permissions."""
        response = client.get('/admin/bulk-revoke-by-ca')
        assert response.status_code == 302  # Redirect to login

    @patch('app.routes.admin.get_certtransparency_client')
    @patch('app.utils.security_logging.security_logger.log_certificate_bulk_revoked')
    def test_bulk_revoke_by_ca_all_valid_reasons(self, mock_log_bulk, mock_get_client, admin_client):
        """Test bulk revocation with all valid reasons."""
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        mock_client.bulk_revoke_by_ca.return_value = {'revoked_count': 1}

        valid_reasons = [
            'key_compromise', 'ca_compromise', 'affiliation_changed',
            'superseded', 'cessation_of_operation', 'certificate_hold',
            'remove_from_crl', 'privilege_withdrawn', 'aa_compromise',
            'admin_revocation', 'admin_bulk_revocation'
        ]

        for reason in valid_reasons:
            response = admin_client.post('/admin/bulk-revoke-by-ca', data={
                'ca_issuer': 'CN=Test CA',
                'reason': reason
            })

            assert response.status_code == 302  # Redirect to certificates list
            mock_client.bulk_revoke_by_ca.assert_called_with(
                ca_issuer='CN=Test CA',
                reason=reason,
                revoked_by='admin@example.com'
            )


class TestBulkRevokeComputerCertificates:
    """Test bulk computer certificate revocation by PSK criteria."""

    def test_bulk_revoke_computer_certificates_get(self, admin_client, app):
        """Test GET request to bulk computer certificate revocation page."""
        with app.app_context():
            # Create some test computer PSKs
            from app.models.presharedkey import PreSharedKey
            from app.extensions import db

            psk1 = PreSharedKey(description="computer1.vpn.com", psk_type="computer", key="test-key-1")
            psk1.is_enabled = True  # Set directly to bypass mass assignment protection
            psk2 = PreSharedKey(description="computer2.vpn.com", psk_type="computer", key="test-key-2")
            psk2.is_enabled = True  # Set directly to bypass mass assignment protection
            psk3 = PreSharedKey(description="user.vpn.com", psk_type="user", key="test-key-3")  # Should not appear
            psk3.is_enabled = True  # Set directly to bypass mass assignment protection
            psk4 = PreSharedKey(description="disabled.vpn.com", psk_type="computer", key="test-key-4")  # Should not appear
            psk4.is_enabled = False  # Set directly to bypass mass assignment protection

            db.session.add_all([psk1, psk2, psk3, psk4])
            db.session.commit()

        response = admin_client.get('/admin/computer-certificates/bulk-revoke')

        assert response.status_code == 200
        assert b'Bulk Revoke Computer Certificates' in response.data or b'computer1.vpn.com' in response.data
        assert b'computer2.vpn.com' in response.data
        # User PSK and disabled PSK should not appear
        assert b'user.vpn.com' not in response.data
        assert b'disabled.vpn.com' not in response.data

    @patch('app.routes.admin.get_certtransparency_client')
    @patch('app.utils.security_logging.security_logger.log_certificate_bulk_revoked')
    def test_bulk_revoke_computer_certificates_post_success(self, mock_log_bulk, mock_get_client, admin_client):
        """Test successful computer certificate bulk revocation."""
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        mock_client.bulk_revoke_computer_certificates.return_value = {'revoked_count': 5}

        response = admin_client.post('/admin/computer-certificates/bulk-revoke', data={
            'psk_filter': 'computer-lab-*',
            'reason': 'admin_bulk_revocation',
            'comment': 'End of semester cleanup'
        })

        assert response.status_code == 302  # Redirect to certificates list
        mock_client.bulk_revoke_computer_certificates.assert_called_once_with(
            psk_filter='computer-lab-*',
            reason='admin_bulk_revocation',
            revoked_by='admin@example.com'
        )
        mock_log_bulk.assert_called_once_with(
            revocation_type="computer_psk",
            target_identifier='computer-lab-*',
            reason='admin_bulk_revocation',
            user_id='admin@example.com',
            certificates_affected=5
        )

    @patch('app.routes.admin.get_certtransparency_client')
    def test_bulk_revoke_computer_certificates_missing_psk_filter(self, mock_get_client, admin_client, app):
        """Test bulk revocation with missing PSK filter."""
        with app.app_context():
            # Create test PSK for template rendering
            from app.models.presharedkey import PreSharedKey
            from app.extensions import db

            psk = PreSharedKey(description="test.vpn.com", psk_type="computer", is_enabled=True, key="test-key-unique-1")
            db.session.add(psk)
            db.session.commit()

        response = admin_client.post('/admin/computer-certificates/bulk-revoke', data={
            'reason': 'admin_bulk_revocation'
        })

        assert response.status_code == 200
        assert b'PSK filter is required' in response.data

    @patch('app.routes.admin.get_certtransparency_client')
    def test_bulk_revoke_computer_certificates_empty_psk_filter(self, mock_get_client, admin_client, app):
        """Test bulk revocation with empty PSK filter."""
        with app.app_context():
            # Create test PSK for template rendering
            from app.models.presharedkey import PreSharedKey
            from app.extensions import db

            psk = PreSharedKey(description="test.vpn.com", psk_type="computer", is_enabled=True, key="test-key-unique-2")
            db.session.add(psk)
            db.session.commit()

        response = admin_client.post('/admin/computer-certificates/bulk-revoke', data={
            'psk_filter': '   ',  # Whitespace only
            'reason': 'admin_bulk_revocation'
        })

        assert response.status_code == 200
        assert b'PSK filter is required' in response.data

    @patch('app.routes.admin.get_certtransparency_client')
    def test_bulk_revoke_computer_certificates_missing_reason(self, mock_get_client, admin_client, app):
        """Test bulk revocation with missing reason."""
        with app.app_context():
            # Create test PSK for template rendering
            from app.models.presharedkey import PreSharedKey
            from app.extensions import db

            psk = PreSharedKey(description="test.vpn.com", psk_type="computer", is_enabled=True, key="test-key-unique-3")
            db.session.add(psk)
            db.session.commit()

        response = admin_client.post('/admin/computer-certificates/bulk-revoke', data={
            'psk_filter': 'computer-*'
        })

        assert response.status_code == 200
        assert b'Revocation reason is required' in response.data

    @patch('app.routes.admin.get_certtransparency_client')
    def test_bulk_revoke_computer_certificates_empty_reason(self, mock_get_client, admin_client, app):
        """Test bulk revocation with empty reason."""
        with app.app_context():
            # Create test PSK for template rendering
            from app.models.presharedkey import PreSharedKey
            from app.extensions import db

            psk = PreSharedKey(description="test.vpn.com", psk_type="computer", is_enabled=True, key="test-key-unique-4")
            db.session.add(psk)
            db.session.commit()

        response = admin_client.post('/admin/computer-certificates/bulk-revoke', data={
            'psk_filter': 'computer-*',
            'reason': '   '  # Whitespace only
        })

        assert response.status_code == 200
        assert b'Revocation reason is required' in response.data

    @patch('app.routes.admin.get_certtransparency_client')
    def test_bulk_revoke_computer_certificates_invalid_reason(self, mock_get_client, admin_client, app):
        """Test bulk revocation with invalid reason."""
        with app.app_context():
            # Create test PSK for template rendering
            from app.models.presharedkey import PreSharedKey
            from app.extensions import db

            psk = PreSharedKey(description="test.vpn.com", psk_type="computer", is_enabled=True, key="test-key-unique-5")
            db.session.add(psk)
            db.session.commit()

        response = admin_client.post('/admin/computer-certificates/bulk-revoke', data={
            'psk_filter': 'computer-*',
            'reason': 'invalid_reason'
        })

        assert response.status_code == 200
        assert b'Invalid revocation reason' in response.data

    @patch('app.routes.admin.get_certtransparency_client')
    def test_bulk_revoke_computer_certificates_ct_client_error(self, mock_get_client, admin_client, app):
        """Test bulk revocation with Certificate Transparency client error."""
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        mock_client.bulk_revoke_computer_certificates.side_effect = CertTransparencyClientError("CT service error")

        with app.app_context():
            # Create test PSK for template rendering
            from app.models.presharedkey import PreSharedKey
            from app.extensions import db

            psk = PreSharedKey(description="test.vpn.com", psk_type="computer", is_enabled=True, key="test-key-unique-6")
            db.session.add(psk)
            db.session.commit()

        response = admin_client.post('/admin/computer-certificates/bulk-revoke', data={
            'psk_filter': 'computer-*',
            'reason': 'key_compromise'
        })

        assert response.status_code == 200
        assert b'Certificate Transparency service unavailable' in response.data

    @patch('app.routes.admin.get_certtransparency_client')
    def test_bulk_revoke_computer_certificates_unexpected_error(self, mock_get_client, admin_client, app):
        """Test bulk revocation with unexpected error."""
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        mock_client.bulk_revoke_computer_certificates.side_effect = Exception("Unexpected error")

        with app.app_context():
            # Create test PSK for template rendering
            from app.models.presharedkey import PreSharedKey
            from app.extensions import db

            psk = PreSharedKey(description="test.vpn.com", psk_type="computer", is_enabled=True, key="test-key-unique-7")
            db.session.add(psk)
            db.session.commit()

        response = admin_client.post('/admin/computer-certificates/bulk-revoke', data={
            'psk_filter': 'computer-*',
            'reason': 'key_compromise'
        })

        assert response.status_code == 200
        assert b'Internal server error during bulk computer certificate revocation' in response.data

    def test_bulk_revoke_computer_certificates_requires_admin(self, client):
        """Test that bulk computer certificate revocation requires admin permissions."""
        response = client.get('/admin/computer-certificates/bulk-revoke')
        assert response.status_code == 302  # Redirect to login

    @patch('app.routes.admin.get_certtransparency_client')
    @patch('app.utils.security_logging.security_logger.log_certificate_bulk_revoked')
    def test_bulk_revoke_computer_certificates_all_valid_reasons(self, mock_log_bulk, mock_get_client, admin_client):
        """Test bulk computer certificate revocation with all valid reasons."""
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        mock_client.bulk_revoke_computer_certificates.return_value = {'revoked_count': 1}

        valid_reasons = [
            'key_compromise', 'ca_compromise', 'affiliation_changed',
            'superseded', 'cessation_of_operation', 'certificate_hold',
            'remove_from_crl', 'privilege_withdrawn', 'aa_compromise',
            'admin_revocation', 'admin_bulk_revocation'
        ]

        for reason in valid_reasons:
            response = admin_client.post('/admin/computer-certificates/bulk-revoke', data={
                'psk_filter': 'test-computer-*',
                'reason': reason
            })

            assert response.status_code == 302  # Redirect to certificates list
            mock_client.bulk_revoke_computer_certificates.assert_called_with(
                psk_filter='test-computer-*',
                reason=reason,
                revoked_by='admin@example.com'
            )

    @patch('app.routes.admin.get_certtransparency_client')
    @patch('app.utils.security_logging.security_logger.log_certificate_bulk_revoked')
    def test_bulk_revoke_computer_certificates_with_comment(self, mock_log_bulk, mock_get_client, admin_client):
        """Test bulk computer certificate revocation with admin comment."""
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        mock_client.bulk_revoke_computer_certificates.return_value = {'revoked_count': 3}

        response = admin_client.post('/admin/computer-certificates/bulk-revoke', data={
            'psk_filter': 'lab-computers-*',
            'reason': 'cessation_of_operation',
            'comment': 'Lab renovation - computers being decommissioned'
        })

        assert response.status_code == 302  # Redirect to certificates list
        mock_client.bulk_revoke_computer_certificates.assert_called_once_with(
            psk_filter='lab-computers-*',
            reason='cessation_of_operation',
            revoked_by='admin@example.com'
        )
        mock_log_bulk.assert_called_once_with(
            revocation_type="computer_psk",
            target_identifier='lab-computers-*',
            reason='cessation_of_operation',
            user_id='admin@example.com',
            certificates_affected=3
        )

    @patch('app.routes.admin.get_certtransparency_client')
    def test_list_certificates_invalid_page_parameter_valueerror(self, mock_get_client, admin_client):
        """Test certificate listing with invalid page parameter causing ValueError - lines 111-112."""
        mock_client = Mock()
        mock_get_client.return_value = mock_client

        mock_client.list_certificates.return_value = {
            'certificates': [],
            'pagination': {'page': 1, 'pages': 0, 'total': 0},
            'filters': {}
        }
        mock_client.get_statistics.return_value = {}

        # Test with invalid page parameter that causes ValueError when converted to int
        response = admin_client.get('/admin/certificates?page=invalid_number')

        assert response.status_code == 200
        # Should default to page 1 due to exception handling
        mock_client.list_certificates.assert_called_once_with(
            page=1,  # Should default to 1 despite invalid input
            limit=50
        )

    @patch('app.routes.admin.get_certtransparency_client')
    def test_list_certificates_invalid_limit_parameter_typeerror(self, mock_get_client, admin_client):
        """Test certificate listing with invalid limit parameter causing TypeError - lines 116-117."""
        mock_client = Mock()
        mock_get_client.return_value = mock_client

        mock_client.list_certificates.return_value = {
            'certificates': [],
            'pagination': {'page': 1, 'pages': 0, 'total': 0},
            'filters': {}
        }
        mock_client.get_statistics.return_value = {}

        # Test with limit parameter that causes TypeError when converted to int
        response = admin_client.get('/admin/certificates?limit=not_a_number')

        assert response.status_code == 200
        # Should default to limit 50 due to exception handling
        mock_client.list_certificates.assert_called_once_with(
            page=1,
            limit=50  # Should default to 50 despite invalid input
        )

    @patch('app.routes.admin.get_certtransparency_client')
    def test_certificate_detail_certificate_is_none(self, mock_get_client, admin_client):
        """Test certificate detail when certificate is None - line 195."""
        mock_client = Mock()
        mock_get_client.return_value = mock_client

        # Mock response where certificate is None (not just missing key)
        mock_client.get_certificate_by_fingerprint.return_value = {'certificate': None}

        # Use a valid SHA256 fingerprint format (64 hex characters, all hex digits)
        valid_fingerprint = 'AAAAAAAA1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF12345678'
        response = admin_client.get(f'/admin/certificates/{valid_fingerprint}')

        # Should abort with 404 when certificate is None (line 195)
        assert response.status_code == 404
        mock_client.get_certificate_by_fingerprint.assert_called_once_with(valid_fingerprint, include_pem=True)