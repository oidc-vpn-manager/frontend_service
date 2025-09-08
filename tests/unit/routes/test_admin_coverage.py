"""
Additional unit tests to achieve 100% coverage for admin routes.

These tests target specific error conditions and edge cases that were
previously uncovered.
"""

import pytest
import json
from unittest.mock import Mock, patch
from flask import Flask

from app.routes.admin import bp as admin_blueprint
from app.routes.auth import bp as auth_blueprint
from app.extensions import db
from app.models import PreSharedKey
from app.utils.certtransparency_client import CertTransparencyClientError


@pytest.fixture
def app():
    """Create test Flask app with admin routes."""
    app = Flask(__name__)
    app.config.update({
        "TESTING": True,
        "SECRET_KEY": "test-secret",
        "WTF_CSRF_ENABLED": False,
        "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
        "SQLALCHEMY_TRACK_MODIFICATIONS": False,
        "OIDC_ADMIN_GROUP": "admins"  # Set admin group for tests
    })
    
    db.init_app(app)
    app.register_blueprint(admin_blueprint)
    app.register_blueprint(auth_blueprint)
    
    with app.app_context():
        db.create_all()

    return app


class TestAdminCoverage:
    """Tests to achieve 100% coverage for admin routes."""
    
    @patch('app.routes.admin.get_certtransparency_client')
    def test_admin_revoke_certificate_invalid_reason(self, mock_get_client, app):
        """Test admin certificate revocation with invalid reason."""
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        
        with app.test_client() as client:
            with client.session_transaction() as sess:
                sess['user'] = {
                    'sub': 'admin123',
                    'groups': ['admins']
                }
            
            response = client.post(
                '/admin/certificates/ABC123/revoke',
                data={'reason': 'invalid_reason'}
            )
            
            assert response.status_code == 302  # Redirect after validation error
            assert '/admin/certificates' in response.location
    
    @patch('app.routes.admin.get_certtransparency_client')
    def test_admin_revoke_certificate_not_found(self, mock_get_client, app):
        """Test admin certificate revocation when certificate not found."""
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        mock_client.get_certificate_by_fingerprint.return_value = {
            'certificate': None
        }
        
        with app.test_client() as client:
            with client.session_transaction() as sess:
                sess['user'] = {
                    'sub': 'admin123', 
                    'groups': ['admins']
                }
            
            response = client.post(
                '/admin/certificates/ABC123/revoke',
                data={'reason': 'admin_revocation'}
            )
            
            assert response.status_code == 302  # Redirect after not found error
            assert '/admin/certificates' in response.location
    
    @patch('app.routes.admin.get_certtransparency_client')
    def test_admin_revoke_certificate_ct_not_found_error(self, mock_get_client, app):
        """Test admin revocation when CT service returns not found error."""
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        mock_client.get_certificate_by_fingerprint.side_effect = CertTransparencyClientError('Certificate not found in CT log')
        
        with app.test_client() as client:
            with client.session_transaction() as sess:
                sess['user'] = {
                    'sub': 'admin123',
                    'groups': ['admins']
                }
            
            response = client.post(
                '/admin/certificates/ABC123/revoke',
                data={'reason': 'admin_revocation'}
            )
            
            assert response.status_code == 302  # Redirect after not found error
            assert '/admin/certificates' in response.location
    
    @patch('app.routes.admin.get_certtransparency_client')
    def test_admin_revoke_certificate_already_revoked(self, mock_get_client, app):
        """Test admin revocation when certificate is already revoked."""
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        mock_client.get_certificate_by_fingerprint.return_value = {
            'certificate': {
                'fingerprint_sha256': 'ABC123',
                'revoked_at': '2023-01-01T00:00:00Z'
            }
        }
        
        with app.test_client() as client:
            with client.session_transaction() as sess:
                sess['user'] = {
                    'sub': 'admin123',
                    'groups': ['admins']
                }
            
            response = client.post(
                '/admin/certificates/ABC123/revoke',
                data={'reason': 'admin_revocation'}
            )
            
            assert response.status_code == 302  # Redirect after already revoked error
            assert '/admin/certificates' in response.location
    
    @patch('app.routes.admin.get_certtransparency_client')
    def test_admin_revoke_certificate_already_revoked_with_revocation_field(self, mock_get_client, app):
        """Test admin revocation when certificate has revocation field set."""
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        mock_client.get_certificate_by_fingerprint.return_value = {
            'certificate': {
                'fingerprint_sha256': 'ABC123',
                'revocation': {'reason': 'key_compromise'}
            }
        }
        
        with app.test_client() as client:
            with client.session_transaction() as sess:
                sess['user'] = {
                    'sub': 'admin123',
                    'groups': ['admins']
                }
            
            response = client.post(
                '/admin/certificates/ABC123/revoke',
                data={'reason': 'admin_revocation'}
            )
            
            assert response.status_code == 302  # Redirect after already revoked error
            assert '/admin/certificates' in response.location
    
    @patch('app.routes.admin.get_certtransparency_client')  
    def test_bulk_revocation_invalid_reason(self, mock_get_client, app):
        """Test bulk revocation with invalid reason."""
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        
        with app.test_client() as client:
            with client.session_transaction() as sess:
                sess['user'] = {
                    'sub': 'admin123',
                    'groups': ['admins']
                }
            
            response = client.post(
                '/admin/users/user123/revoke-certificates',
                data={'reason': 'invalid_reason'}
            )
            
            assert response.status_code == 302  # Redirect after validation error
            assert '/admin/certificates' in response.location
    
    def test_bulk_revocation_empty_user_id(self, app):
        """Test bulk revocation with empty user ID."""
        with app.test_client() as client:
            with client.session_transaction() as sess:
                sess['user'] = {
                    'sub': 'admin123',
                    'groups': ['admins']
                }
            
            response = client.post(
                '/admin/users/ /revoke-certificates',
                data={'reason': 'admin_bulk_revocation'}
            )
            
            assert response.status_code == 302  # Redirect after validation error
            assert '/admin/certificates' in response.location
    
    @patch('app.routes.admin.get_certtransparency_client')
    def test_bulk_revocation_ct_service_error(self, mock_get_client, app):
        """Test bulk revocation when CT service returns error."""
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        mock_client.bulk_revoke_user_certificates.side_effect = CertTransparencyClientError('Service unavailable')
        
        with app.test_client() as client:
            with client.session_transaction() as sess:
                sess['user'] = {
                    'sub': 'admin123',
                    'groups': ['admins']  
                }
            
            response = client.post(
                '/admin/users/user123/revoke-certificates',
                data={'reason': 'admin_bulk_revocation'}
            )
            
            assert response.status_code == 302  # Redirect after service error
            assert '/admin/certificates' in response.location
    
    @patch('app.routes.admin.get_certtransparency_client')
    def test_bulk_revocation_unexpected_error(self, mock_get_client, app):
        """Test bulk revocation with unexpected error."""
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        mock_client.bulk_revoke_user_certificates.side_effect = Exception('Unexpected error')
        
        with app.test_client() as client:
            with client.session_transaction() as sess:
                sess['user'] = {
                    'sub': 'admin123',
                    'groups': ['admins']
                }
            
            response = client.post(
                '/admin/users/user123/revoke-certificates',
                data={'reason': 'admin_bulk_revocation'}
            )
            
            assert response.status_code == 302  # Redirect after unexpected error
            assert '/admin/certificates' in response.location
    
    @patch('app.routes.admin.get_certtransparency_client')
    def test_admin_revoke_certificate_ct_service_error(self, mock_get_client, app):
        """Test admin revocation when CT service has error."""
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        mock_client.get_certificate_by_fingerprint.return_value = {
            'certificate': {
                'fingerprint_sha256': 'ABC123',
                'issuing_user_id': 'user123'
            }
        }
        mock_client.revoke_certificate.side_effect = CertTransparencyClientError('Service error')
        
        with app.test_client() as client:
            with client.session_transaction() as sess:
                sess['user'] = {
                    'sub': 'admin123',
                    'groups': ['admins']
                }
            
            response = client.post(
                '/admin/certificates/ABC123/revoke',
                data={'reason': 'admin_revocation'}
            )
            
            assert response.status_code == 302  # Redirect after service error
            assert '/admin/certificates' in response.location
    
    @patch('app.routes.admin.get_certtransparency_client')
    def test_admin_revoke_certificate_unexpected_error(self, mock_get_client, app):
        """Test admin revocation with unexpected error."""
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        mock_client.get_certificate_by_fingerprint.return_value = {
            'certificate': {
                'fingerprint_sha256': 'ABC123',
                'issuing_user_id': 'user123'
            }
        }
        mock_client.revoke_certificate.side_effect = Exception('Unexpected error')
        
        with app.test_client() as client:
            with client.session_transaction() as sess:
                sess['user'] = {
                    'sub': 'admin123',
                    'groups': ['admins']
                }
            
            response = client.post(
                '/admin/certificates/ABC123/revoke',
                data={'reason': 'admin_revocation'}
            )
            
            assert response.status_code == 302  # Redirect after unexpected error
            assert '/admin/certificates' in response.location

    @patch('app.routes.admin.request_certificate_revocation')
    @patch('app.routes.admin.get_certtransparency_client')
    def test_admin_revoke_certificate_signing_not_found_error(self, mock_get_ct_client, mock_revoke, app):
        """Test admin certificate revocation with signing service 'not found' error - line 215."""
        from app.utils.signing_client import SigningServiceError
        
        mock_ct_client = Mock()
        mock_get_ct_client.return_value = mock_ct_client
        mock_ct_client.get_certificate_by_fingerprint.return_value = {'certificate': {'status': 'issued'}}
        
        mock_revoke.side_effect = SigningServiceError("Certificate not found")
        
        with app.test_client() as client:
            with client.session_transaction() as sess:
                sess['user'] = {
                    'sub': 'test_admin',
                    'email': 'admin@example.org',
                    'groups': ['admins']
                }
            
            response = client.post(
                '/admin/certificates/ABC123/revoke',
                data={'reason': 'key_compromise'}
            )
            
            assert response.status_code == 302  # Redirect after error
            assert '/admin/certificates/ABC123' in response.location

    @patch('app.routes.admin.request_certificate_revocation')
    @patch('app.routes.admin.get_certtransparency_client')
    def test_admin_revoke_certificate_signing_unavailable_error(self, mock_get_ct_client, mock_revoke, app):
        """Test admin certificate revocation with signing service 'unavailable' error - line 217."""
        from app.utils.signing_client import SigningServiceError
        
        mock_ct_client = Mock()
        mock_get_ct_client.return_value = mock_ct_client
        mock_ct_client.get_certificate_by_fingerprint.return_value = {'certificate': {'status': 'issued'}}
        
        mock_revoke.side_effect = SigningServiceError("Service unavailable")
        
        with app.test_client() as client:
            with client.session_transaction() as sess:
                sess['user'] = {
                    'sub': 'test_admin',
                    'email': 'admin@example.org',
                    'groups': ['admins']
                }
            
            response = client.post(
                '/admin/certificates/ABC123/revoke',
                data={'reason': 'key_compromise'}
            )
            
            assert response.status_code == 302  # Redirect after error
            assert '/admin/certificates/ABC123' in response.location

    @patch('app.routes.admin.get_certtransparency_client')
    def test_admin_revoke_certificate_general_exception(self, mock_get_ct_client, app):
        """Test admin certificate revocation with general exception - lines 226-229."""
        mock_ct_client = Mock()
        mock_get_ct_client.return_value = mock_ct_client
        mock_ct_client.get_certificate_by_fingerprint.side_effect = Exception("Unexpected database error")
        
        with app.test_client() as client:
            with client.session_transaction() as sess:
                sess['user'] = {
                    'sub': 'test_admin',
                    'email': 'admin@example.org',
                    'groups': ['admins']
                }
            
            response = client.post(
                '/admin/certificates/ABC123/revoke',
                data={'reason': 'key_compromise'}
            )
            
            assert response.status_code == 302  # Redirect after error
            assert '/admin/certificates/ABC123' in response.location

    @patch('app.routes.admin.request_bulk_certificate_revocation')
    def test_bulk_revocation_signing_unavailable_error(self, mock_bulk_revoke, app):
        """Test bulk revocation with signing service 'unavailable' error - line 291."""
        from app.utils.signing_client import SigningServiceError
        
        mock_bulk_revoke.side_effect = SigningServiceError("Service unavailable")
        
        with app.test_client() as client:
            with client.session_transaction() as sess:
                sess['user'] = {
                    'sub': 'test_admin',
                    'email': 'admin@example.org',
                    'groups': ['admins']
                }
            
            response = client.post(
                '/admin/users/test_user/revoke-certificates',
                data={'reason': 'cessation_of_operation'}
            )
            
            assert response.status_code == 302  # Redirect after error
            assert '/admin/certificates' in response.location

    @patch('app.routes.admin.request_bulk_certificate_revocation')
    def test_bulk_revocation_ct_client_error(self, mock_bulk_revoke, app):
        """Test bulk revocation with CT client error - lines 295-303."""
        from app.utils.certtransparency_client import CertTransparencyClientError
        
        mock_bulk_revoke.side_effect = CertTransparencyClientError("CT service unavailable")
        
        with app.test_client() as client:
            with client.session_transaction() as sess:
                sess['user'] = {
                    'sub': 'test_admin',
                    'email': 'admin@example.org',
                    'groups': ['admins']
                }
            
            response = client.post(
                '/admin/users/test_user/revoke-certificates',
                data={'reason': 'cessation_of_operation'}
            )
            
            assert response.status_code == 302  # Redirect after error
            assert '/admin/certificates' in response.location

    @patch('app.routes.admin.request_bulk_certificate_revocation')
    def test_bulk_revocation_general_exception(self, mock_bulk_revoke, app):
        """Test bulk revocation with general exception - lines 300-303."""
        mock_bulk_revoke.side_effect = Exception("Unexpected error")
        
        with app.test_client() as client:
            with client.session_transaction() as sess:
                sess['user'] = {
                    'sub': 'test_admin',
                    'email': 'admin@example.org',
                    'groups': ['admins']
                }
            
            response = client.post(
                '/admin/users/test_user/revoke-certificates',
                data={'reason': 'cessation_of_operation'}
            )
            
            assert response.status_code == 302  # Redirect after error
            assert '/admin/certificates' in response.location

def test_create_psk_no_template_sets(app):
    """
    Test create PSK page when no server template sets are found (lines 39-40).
    """
    # Mock get_template_set_choices to return empty list
    with patch('app.utils.server_templates.get_template_set_choices') as mock_template_choices:
        mock_template_choices.return_value = []
        
        with app.test_client() as client:
            with client.session_transaction() as sess:
                sess['user'] = {
                    'sub': 'test_admin', 
                    'email': 'admin@example.org',
                    'groups': ['admins']
                }
            
            response = client.get('/admin/psk/new')
            
            # Should redirect to PSK list with error message
            assert response.status_code == 302
            assert '/admin/psk' in response.location


@patch('app.routes.admin.render_template')
def test_create_psk_successful_form_submission(mock_render_template, app):
    """
    Test successful PSK creation form submission (lines 42, 44-64).
    """
    # Mock render_template to return a fake response
    mock_render_template.return_value = 'Mocked PSK Created Page'
    
    with patch('app.utils.server_templates.get_template_set_choices') as mock_template_choices:
        mock_template_choices.return_value = [('default', 'Default Template Set')]
        
        with app.test_client() as client:
            with client.session_transaction() as sess:
                sess['user'] = {
                    'sub': 'test_admin', 
                    'email': 'admin@example.org',
                    'groups': ['admins']
                }
            
            # Submit valid form data
            response = client.post('/admin/psk/new', data={
                'description': 'Test PSK',
                'template_set': 'default'
            })
            
            # Should successfully create PSK and render success template
            assert response.status_code == 200
            assert b'Mocked PSK Created Page' in response.data
            
            # Verify render_template was called with correct template
            mock_render_template.assert_called_once()
            call_args = mock_render_template.call_args
            assert call_args[0][0] == 'admin/psk_created.html'
            
            # Check that PSK was created in database
            with app.app_context():
                psk = PreSharedKey.query.filter_by(description='Test PSK').first()
                assert psk is not None
                assert psk.template_set == 'default'


@patch('app.routes.admin.render_template')
def test_create_psk_form_validation_failure(mock_render_template, app):
    """
    Test PSK creation form when validation fails (line 66).
    """
    # Mock render_template to return a fake form page
    mock_render_template.return_value = 'Mocked PSK Form Page'
    
    with patch('app.utils.server_templates.get_template_set_choices') as mock_template_choices:
        mock_template_choices.return_value = [('default', 'Default Template Set')]
        
        with app.test_client() as client:
            with client.session_transaction() as sess:
                sess['user'] = {
                    'sub': 'test_admin', 
                    'email': 'admin@example.org',
                    'groups': ['admins']
                }
            
            # Submit invalid form data (missing required description)
            response = client.post('/admin/psk/new', data={
                'template_set': 'default'
                # Missing 'description' field
            })
            
            # Should render the form again with validation errors
            assert response.status_code == 200
            assert b'Mocked PSK Form Page' in response.data
            
            # Verify render_template was called with form template
            mock_render_template.assert_called_once()
            call_args = mock_render_template.call_args
            assert call_args[0][0] == 'admin/psk_new.html'


@patch('app.routes.admin.render_template')
def test_create_psk_get_form_with_template_choices(mock_render_template, app):
    """
    Test GET request to PSK creation form with template choices populated (line 42).
    """
    # Mock render_template to return a fake form page
    mock_render_template.return_value = 'Mocked PSK Form with Choices'
    
    with patch('app.utils.server_templates.get_template_set_choices') as mock_template_choices:
        mock_template_choices.return_value = [('default', 'Default Template Set'), ('vpn', 'VPN Template Set')]
        
        with app.test_client() as client:
            with client.session_transaction() as sess:
                sess['user'] = {
                    'sub': 'test_admin', 
                    'email': 'admin@example.org',
                    'groups': ['admins']
                }
            
            response = client.get('/admin/psk/new')
            
            # Should render form template
            assert response.status_code == 200
            assert b'Mocked PSK Form with Choices' in response.data
            
            # Verify render_template was called with form template
            mock_render_template.assert_called_once()
            call_args = mock_render_template.call_args
            assert call_args[0][0] == 'admin/psk_new.html'
            
            # Verify form in template context has populated template choices
            template_context = call_args[1]
            form = template_context['form']
            assert len(form.template_set.choices) == 2
            assert form.template_set.choices[0] == ('default', 'Default Template Set')
            assert form.template_set.choices[1] == ('vpn', 'VPN Template Set')


@patch('app.routes.admin.render_template')
def test_create_psk_default_template_set_when_empty(mock_render_template, app):
    """
    Test PSK creation form defaults to first template when none selected (line 48).
    """
    # Mock render_template to return a fake response
    mock_render_template.return_value = 'Mocked PSK Created Page'
    
    with patch('app.utils.server_templates.get_template_set_choices') as mock_template_choices:
        mock_template_choices.return_value = [('default', 'Default Template Set'), ('vpn', 'VPN Template Set')]
        
        with app.test_client() as client:
            with client.session_transaction() as sess:
                sess['user'] = {
                    'sub': 'test_admin', 
                    'email': 'admin@example.org',
                    'groups': ['admins']
                }
            
            # Submit form with valid description but empty template_set
            response = client.post('/admin/psk/new', data={
                'description': 'Test PSK with Default Template'
                # template_set is empty, should default to first choice
            })
            
            # Should successfully create PSK and render success template
            assert response.status_code == 200
            assert b'Mocked PSK Created Page' in response.data
            
            # Check that PSK was created with default template set
            with app.app_context():
                psk = PreSharedKey.query.filter_by(description='Test PSK with Default Template').first()
                assert psk is not None
                assert psk.template_set == 'default'  # Should default to first choice


@patch('app.routes.admin.render_template')
def test_create_psk_invalid_template_set_validation(mock_render_template, app):
    """
    Test PSK creation form with invalid template set validation (lines 53-54).
    """
    # Mock render_template to return a fake form page
    mock_render_template.return_value = 'Mocked PSK Form Page'
    
    with patch('app.utils.server_templates.get_template_set_choices') as mock_template_choices:
        mock_template_choices.return_value = [('default', 'Default Template Set')]
        
        with app.test_client() as client:
            with client.session_transaction() as sess:
                sess['user'] = {
                    'sub': 'test_admin', 
                    'email': 'admin@example.org',
                    'groups': ['admins']
                }
            
            # Submit form with invalid template_set (not in choices)
            response = client.post('/admin/psk/new', data={
                'description': 'Test PSK with Invalid Template',
                'template_set': 'invalid_template_not_in_choices'
            })
            
            # Should render form again with validation error
            assert response.status_code == 200
            assert b'Mocked PSK Form Page' in response.data
            
            # Verify render_template was called with form template
            mock_render_template.assert_called_once()
            call_args = mock_render_template.call_args
            assert call_args[0][0] == 'admin/psk_new.html'
            
            # Verify form has validation errors
            template_context = call_args[1]
            form = template_context['form']
            assert 'Invalid template set selected.' in form.template_set.errors


@patch('app.routes.admin.render_template')
def test_list_certificates_show_uncollapsed_true(mock_render_template, app):
    """
    Test certificates list with show_uncollapsed=true parameter (line 120).
    """
    from app.utils.certtransparency_client import CertTransparencyClientError
    
    # Mock render_template to return a fake response
    mock_render_template.return_value = 'Mocked Certificates Page'
    
    with patch('app.routes.admin.get_certtransparency_client') as mock_get_client:
        # Mock successful response
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        mock_client.list_certificates.return_value = {
            'certificates': [],
            'pagination': {},
            'filters': {'show_uncollapsed': 'true'}
        }
        mock_client.get_statistics.return_value = {}
        
        with app.test_client() as client:
            with client.session_transaction() as sess:
                sess['user'] = {
                    'sub': 'test_admin',
                    'email': 'admin@example.org', 
                    'groups': ['admins']
                }
            
            # Request certificates with show_uncollapsed=true parameter
            response = client.get('/admin/certificates?show_uncollapsed=true')
            
            # Should successfully render certificates page
            assert response.status_code == 200
            assert b'Mocked Certificates Page' in response.data
            
            # Verify the filter was passed to the client
            mock_client.list_certificates.assert_called_once()
            call_kwargs = mock_client.list_certificates.call_args[1]
            assert 'show_uncollapsed' in call_kwargs
            assert call_kwargs['show_uncollapsed'] == 'true'


@patch('app.routes.admin.render_template')
def test_list_psks_basic_functionality(mock_render_template, app):
    """Test list_psks function basic functionality (lines 23-25)."""
    # Mock render_template to return a fake response
    mock_render_template.return_value = 'Mocked PSK List Page'
    
    with app.test_client() as client:
        with client.session_transaction() as sess:
            sess['user'] = {
                'sub': 'test_admin',
                'email': 'admin@example.org', 
                'groups': ['admins']
            }
        
        response = client.get('/admin/psk')
        
        # Should successfully render PSK list page
        assert response.status_code == 200
        assert b'Mocked PSK List Page' in response.data
        
        # Verify render_template was called with correct template
        mock_render_template.assert_called_once()
        call_args = mock_render_template.call_args
        assert call_args[0][0] == 'admin/psk_list.html'


def test_revoke_psk_functionality(app):
    """Test revoke_psk function (lines 83-91)."""
    from app.extensions import db
    
    with app.app_context():
        # Create a test PSK to revoke
        test_psk = PreSharedKey(
            description='Test PSK for Revocation',
            template_set='default',
            key='test-key-123'
        )
        db.session.add(test_psk)
        db.session.commit()
        psk_id = test_psk.id
        
        with app.test_client() as client:
            with client.session_transaction() as sess:
                sess['user'] = {
                    'sub': 'test_admin',
                    'email': 'admin@example.org',
                    'groups': ['admins']
                }
            
            # Revoke the PSK
            response = client.post(f'/admin/psk/{psk_id}/revoke')
            
            # Should redirect to PSK list after revocation
            assert response.status_code == 302
            assert '/admin/psk' in response.location
            
            # Verify the PSK was actually revoked in the database
            revoked_psk = db.session.get(PreSharedKey, psk_id)
            assert revoked_psk is not None
            assert revoked_psk.is_enabled is False


def test_revoke_psk_not_found(app):
    """Test revoke_psk when PSK doesn't exist (lines 85-86)."""
    with app.test_client() as client:
        with client.session_transaction() as sess:
            sess['user'] = {
                'sub': 'test_admin',
                'email': 'admin@example.org', 
                'groups': ['admins']
            }
        
        # Try to revoke non-existent PSK
        response = client.post('/admin/psk/99999/revoke')
        
        # Should return 404 for non-existent PSK
        assert response.status_code == 404
