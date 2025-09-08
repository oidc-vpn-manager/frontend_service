import pytest
from flask import Flask, session
from unittest.mock import MagicMock, patch
import json

from app.routes.profile import bp as profile_blueprint  
from app.routes.auth import bp as auth_blueprint
from app.extensions import db
from app.models import DownloadToken # Needed for db.create_all

@pytest.fixture
def app():
    """Provides a test app with the necessary config and extensions."""
    app = Flask(__name__)
    app.config.update({
        "TESTING": True,
        "SECRET_KEY": "test-secret",
        "WTF_CSRF_ENABLED": False,
        "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
        "SQLALCHEMY_TRACK_MODIFICATIONS": False
    })
    
    # Initialize the database with this app instance
    db.init_app(app)
    
    app.register_blueprint(profile_blueprint)
    app.register_blueprint(auth_blueprint)
    
    # Create the database tables needed for the test
    with app.app_context():
        db.create_all()

    return app

def test_profile_requires_login(app):
    """
    Tests that accessing a profile page without being logged in redirects to login.
    """
    client = app.test_client()
    response = client.get('/profile/certificates')

    assert response.status_code == 302
    assert response.location == '/auth/login'


class TestProfileCertificateErrorHandling:
    """Test error handling in profile certificate routes."""
    
    @patch('app.routes.profile.render_template')
    @patch('app.routes.profile.request_certificate_revocation')
    @patch('app.routes.profile.get_certtransparency_client')
    def test_user_certificates_ct_service_error(self, mock_get_client, mock_revoke, mock_render, app):
        """Test CT service error handling in user certificates listing (lines 148-150)."""
        from app.utils.certtransparency_client import CertTransparencyClientError
        
        # Mock Certificate Transparency client to raise an error
        mock_client = MagicMock()
        mock_get_client.return_value = mock_client
        mock_client.list_certificates.side_effect = CertTransparencyClientError("Service error")
        
        # Mock render_template to return a simple response
        mock_render.return_value = "certificates page with error"
        
        with app.test_client() as client:
            with client.session_transaction() as sess:
                sess['user'] = {
                    'sub': 'user123',
                    'preferred_username': 'testuser',
                    'email': 'test@example.com'
                }
            
            response = client.get('/profile/certificates')
            
            # Should return 200 with error handling
            assert response.status_code == 200
            # Verify render_template was called with error and empty certificates list
            # The error should be passed as per lines 148-150 in profile.py
            mock_render.assert_called_with('profile/certificates.html', certificates=[], error="Service error")

    @patch('app.routes.profile.request_certificate_revocation')
    @patch('app.routes.profile.get_certtransparency_client')
    def test_user_certificate_revocation_not_found(self, mock_get_client, mock_revoke, app):
        """Test certificate not found handling in revocation (line 191)."""
        from app.utils.certtransparency_client import CertTransparencyClientError
        
        # Mock Certificate Transparency client
        mock_client = MagicMock()
        mock_get_client.return_value = mock_client
        mock_client.get_certificate_by_fingerprint.return_value = {'certificate': None}
        
        with app.test_client() as client:
            with client.session_transaction() as sess:
                sess['user'] = {
                    'sub': 'user123',
                    'preferred_username': 'testuser',
                    'email': 'test@example.com'
                }
            
            response = client.post(
                '/profile/certificates/ABC123/revoke',
                data={'reason': 'key_compromise'}
            )
            
            # Should return 404 for certificate not found
            assert response.status_code == 404
            response_data = json.loads(response.data)
            assert 'Certificate not found' in response_data.get('error', '')

    @patch('app.routes.profile.request_certificate_revocation')
    @patch('app.routes.profile.get_certtransparency_client')
    def test_user_certificate_revocation_unexpected_error(self, mock_get_client, mock_revoke, app):
        """Test unexpected error handling in revocation (lines 230-232)."""
        # Mock Certificate Transparency client to raise an unexpected error
        mock_client = MagicMock()
        mock_get_client.return_value = mock_client
        mock_client.get_certificate_by_fingerprint.side_effect = RuntimeError("Unexpected error")
        
        with app.test_client() as client:
            with client.session_transaction() as sess:
                sess['user'] = {
                    'sub': 'user123',
                    'preferred_username': 'testuser',
                    'email': 'test@example.com'
                }
            
            response = client.post(
                '/profile/certificates/ABC123/revoke',
                data={'reason': 'key_compromise'}
            )
            
            # Should return 500 for internal server error
            assert response.status_code == 500
            response_data = json.loads(response.data)
            assert 'Internal server error' in response_data.get('error', '')

    @patch('app.routes.profile.get_certtransparency_client')
    def test_certificate_detail_no_user_session(self, mock_get_client, app):
        """Test certificate detail access without user session - lines 177-179."""
        with app.test_client() as client:
            # No user session set
            response = client.get('/profile/certificates/ABC123')
            
            # Should redirect to login due to @login_required decorator
            assert response.status_code == 302
            assert '/auth/login' in response.location
            
    @patch('app.routes.profile.get_certtransparency_client')
    def test_certificate_detail_no_user_id(self, mock_get_client, app):
        """Test certificate detail access with session but no user ID - lines 178-179."""
        with app.test_client() as client:
            with client.session_transaction() as sess:
                # Set user session but without 'sub' field
                sess['user'] = {
                    'preferred_username': 'testuser',
                    'email': 'test@example.com'
                }
            
            response = client.get('/profile/certificates/ABC123')
            
            # Should redirect to profile certificates page  
            assert response.status_code == 302
            assert '/profile/certificates' in response.location

    @patch('app.routes.profile.get_certtransparency_client')
    def test_certificate_detail_certificate_not_found(self, mock_get_client, app):
        """Test certificate detail when certificate not found - lines 183-188."""
        mock_client = MagicMock()
        mock_get_client.return_value = mock_client
        mock_client.get_certificate_by_fingerprint.side_effect = Exception("Certificate not found")
        
        with app.test_client() as client:
            with client.session_transaction() as sess:
                sess['user'] = {
                    'sub': 'user123',
                    'preferred_username': 'testuser',
                    'email': 'test@example.com'
                }
            
            response = client.get('/profile/certificates/ABC123')
            
            # Should redirect to profile certificates page
            assert response.status_code == 302
            assert '/profile/certificates' in response.location

    @patch('app.routes.profile.get_certtransparency_client')
    def test_certificate_detail_access_denied(self, mock_get_client, app):
        """Test certificate detail access denied for other user's certificate - lines 191-193."""
        mock_client = MagicMock()
        mock_get_client.return_value = mock_client
        mock_client.get_certificate_by_fingerprint.return_value = {
            'issuing_user_id': 'other_user_456',  # Different user
            'fingerprint': 'ABC123',
            'status': 'issued'
        }
        
        with app.test_client() as client:
            with client.session_transaction() as sess:
                sess['user'] = {
                    'sub': 'user123',  # Different from certificate owner
                    'preferred_username': 'testuser',
                    'email': 'test@example.com'
                }
            
            response = client.get('/profile/certificates/ABC123')
            
            # Should redirect to profile certificates page
            assert response.status_code == 302
            assert '/profile/certificates' in response.location

    @patch('app.routes.profile.render_template')
    @patch('app.routes.profile.get_certtransparency_client')
    def test_certificate_detail_success(self, mock_get_client, mock_render, app):
        """Test successful certificate detail access - line 195."""
        mock_client = MagicMock()
        mock_get_client.return_value = mock_client
        mock_client.get_certificate_by_fingerprint.return_value = {
            'issuing_user_id': 'user123',  # Same user
            'fingerprint': 'ABC123',
            'status': 'issued'
        }
        
        mock_render.return_value = "certificate detail page"
        
        with app.test_client() as client:
            with client.session_transaction() as sess:
                sess['user'] = {
                    'sub': 'user123',
                    'preferred_username': 'testuser',
                    'email': 'test@example.com'
                }
            
            response = client.get('/profile/certificates/ABC123')
            
            # Should render the certificate detail template
            assert response.status_code == 200
            mock_render.assert_called_with('profile/certificate_detail.html', certificate={
                'issuing_user_id': 'user123',
                'fingerprint': 'ABC123', 
                'status': 'issued'
            })

    def test_revoke_certificate_invalid_reason(self, app):
        """Test certificate revocation with invalid reason - line 232."""
        with app.test_client() as client:
            with client.session_transaction() as sess:
                sess['user'] = {
                    'sub': 'user123',
                    'preferred_username': 'testuser',
                    'email': 'test@example.com'
                }
            
            response = client.post(
                '/profile/certificates/ABC123/revoke',
                data={'reason': 'invalid_reason_not_in_list'}
            )
            
            # Should return 400 for invalid reason
            assert response.status_code == 400
            response_data = json.loads(response.data)
            assert 'Invalid revocation reason' in response_data.get('error', '')

    @patch('app.routes.profile.render_template')
    @patch('app.routes.profile.get_certtransparency_client')
    def test_certificate_detail_nested_certificate_response(self, mock_get_client, mock_render, app):
        """Test certificate detail with nested certificate response - covers line 90."""
        mock_client = MagicMock()
        mock_get_client.return_value = mock_client
        # Return certificate wrapped in another certificate object
        mock_client.get_certificate_by_fingerprint.return_value = {
            'certificate': {
                'issuing_user_id': 'user123',  
                'fingerprint': 'ABC123',
                'status': 'issued',
                'nested': 'data'
            }
        }
        
        mock_render.return_value = "certificate detail page"
        
        with app.test_client() as client:
            with client.session_transaction() as sess:
                sess['user'] = {
                    'sub': 'user123',
                    'preferred_username': 'testuser',
                    'email': 'test@example.com'
                }
            
            response = client.get('/profile/certificates/ABC123')
            
            # Should render with extracted nested certificate
            assert response.status_code == 200
            mock_render.assert_called_with('profile/certificate_detail.html', certificate={
                'issuing_user_id': 'user123',
                'fingerprint': 'ABC123', 
                'status': 'issued',
                'nested': 'data'
            })
