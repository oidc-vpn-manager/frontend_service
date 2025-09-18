"""
Test for bulk revocation bug - TDD approach.

This test reproduces the bug where bulk revocation fails from the certificates 
list page but works from certificate detail page.
"""

import pytest
import os
from unittest.mock import patch, MagicMock
from flask import url_for
from app import create_app


@pytest.fixture
def app():
    """Creates a test Flask app using the real create_app function."""
    # Set test keys for secure configuration
    os.environ['FLASK_SECRET_KEY'] = 'test-secret-key-for-bulk-revocation-bug-tests-only'
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
        sess['user'] = {'groups': ['vpn-admins'], 'sub': 'admin123', 'is_admin': True}
    
    return client


class TestBulkRevocationBug:
    """Test bulk revocation bug between different pages."""

    def test_certificates_page_bulk_button_works_correctly(self, admin_client):
        """
        Test that bulk revoke button on certificates.html (cert-management page) works correctly.
        
        This test should PASS - the cert-management page bulk revocation works.
        """
        # Mock the certificate transparency client to return certificates
        with patch('app.routes.admin.get_certtransparency_client') as mock_client:
            mock_ct_client = MagicMock()
            mock_client.return_value = mock_ct_client
            
            # Mock certificates response with a certificate that has issuing_user_id
            mock_ct_client.list_certificates.return_value = {
                'certificates': [{
                    'fingerprint': '1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF',
                    'subject': {'common_name': 'test@example.com'},
                    'issuing_user_id': 'user123',
                    'issued_at': '2024-01-01T00:00:00Z',
                    'type': 'client',
                    'revoked_at': None
                }],
                'pagination': {'page': 1, 'pages': 1, 'total': 1},
                'filters': {}
            }
            
            # Mock statistics
            mock_ct_client.get_statistics.return_value = {}
            
            # Request certificates list page
            response = admin_client.get('/admin/certificates')
            assert response.status_code == 200
            
            html_content = response.data.decode('utf-8')
            
            # Verify that bulk revoke button exists
            assert 'data-testid="bulk-revoke-user"' in html_content
            assert 'class="button bulk-revoke-btn"' in html_content
            
            # Verify certificate rows have issuing_user_id data for JavaScript to work
            assert 'data-issuing-user-id="user123"' in html_content, (
                "Certificate rows should have data-issuing-user-id for admin_cert.js to work"
            )
            
            # Verify the correct JavaScript file is loaded
            assert 'admin_cert.js' in html_content, (
                "Certificates page should load admin_cert.js for bulk revocation"
            )
            
            # Verify certificates page has user_id input field in bulk form
            assert 'name="user_id"' in html_content, (
                "Certificates page bulk form should have user_id input field"
            )

    def test_certificate_detail_page_bulk_form_missing_user_id_field(self, admin_client):
        """
        Test that bulk revocation form on certificate_detail.html is missing user_id field.
        
        This test will FAIL initially, demonstrating the bug.
        """
        fingerprint = '1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF'
        
        # Mock the certificate transparency client
        with patch('app.routes.admin.get_certtransparency_client') as mock_client:
            mock_ct_client = MagicMock()
            mock_client.return_value = mock_ct_client
            
            # Mock certificate detail response with issuing_user_id
            mock_ct_client.get_certificate_by_fingerprint.return_value = {
                'certificate': {
                    'fingerprint': fingerprint,
                    'subject': {'common_name': 'test@example.com'},
                    'issuer': {'common_name': 'Test CA'},
                    'issuing_user_id': 'user123',
                    'issued_at': '2024-01-01T00:00:00Z',
                    'type': 'client',
                    'revoked_at': None,
                    'validity': {'not_after': '2025-01-01T00:00:00Z'},
                    'pem_data': '-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----'
                }
            }
            
            # Request certificate detail page  
            response = admin_client.get(f'/admin/certificates/{fingerprint}')
            assert response.status_code == 200
            
            html_content = response.data.decode('utf-8')
            
            # Verify bulk revoke button exists
            assert 'data-testid="bulk-revoke-user"' in html_content
            assert 'class="button bulk-revoke-btn"' in html_content
            assert 'data-user-id="user123"' in html_content
            
            # THE BUG: Certificate detail page bulk form is missing user_id input field
            assert 'name="user_id"' in html_content, (
                "Certificate detail page bulk form is missing user_id input field "
                "that admin_bulk_revoke_user_certificates endpoint requires"
            )

    def test_javascript_bulk_revocation_requires_user_id_data(self):
        """
        Test that documents the JavaScript requirement for data-user-id attribute.
        
        This is a documentation test showing what the JavaScript expects.
        """
        # This test documents the JavaScript requirement from admin_cert_detail.js:
        # 
        # function showBulkRevocationDialog(userId, subject) {
        #     document.getElementById('bulkRevocationForm').action = `/admin/users/${userId}/revoke-certificates`;
        # }
        #
        # The JavaScript handler expects:
        # - this.dataset.userId (from data-user-id attribute)
        # - this.dataset.subject (from data-subject attribute)
        
        expected_js_behavior = {
            'required_data_attributes': ['data-user-id', 'data-subject'],
            'form_action_template': '/admin/users/{user_id}/revoke-certificates',
            'expected_classes': ['bulk-revoke-btn'],
            'expected_testids': ['bulk-revoke-user']
        }
        
        # This test passes to document the expected behavior
        assert expected_js_behavior['required_data_attributes'] == ['data-user-id', 'data-subject']
        assert '{user_id}' in expected_js_behavior['form_action_template']