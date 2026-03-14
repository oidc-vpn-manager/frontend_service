"""
Tests for CLI workflow (get_openvpn_config script support).
"""

import json
import pytest
from unittest.mock import patch, MagicMock
import uuid
from datetime import datetime, timezone, timedelta
from app.models import DownloadToken


@pytest.fixture
def mock_oauth():
    """Mock OAuth for testing."""
    with patch('app.routes.auth.oauth') as mock:
        yield mock


@pytest.fixture
def app_with_db(app):
    """Add database initialization to the app fixture."""
    from app.extensions import db
    
    with app.app_context():
        db.create_all()
    
    yield app
    
    with app.app_context():
        db.drop_all()


class TestAuthLogin:
    """Test /login route CLI parameter handling."""
    
    def test_login_without_cli_params(self, client, mock_oauth, app):
        """Test normal login without CLI parameters."""
        mock_oauth.oidc.authorize_redirect.return_value = app.response_class(status=302, headers={'Location': 'http://test.com'})
        
        response = client.get('/auth/login')
        assert response.status_code == 302
        
        # Should not have stored CLI params
        with client.session_transaction() as session:
            assert 'cli_port' not in session
            assert 'cli_optionset' not in session
    
    def test_login_with_cli_params(self, client, mock_oauth, app):
        """Test login with CLI parameters stores them in session."""
        mock_oauth.oidc.authorize_redirect.return_value = app.response_class(status=302, headers={'Location': 'http://test.com'})
        
        response = client.get('/auth/login?cli_port=12345&optionset=option1,option2')
        assert response.status_code == 302
        
        # Should have stored CLI params in session
        with client.session_transaction() as session:
            assert session['cli_port'] == 12345  # Port validation returns integer
            assert session['cli_optionset'] == 'option1,option2'
    
    def test_login_with_cli_port_only(self, client, mock_oauth, app):
        """Test login with only cli_port parameter."""
        mock_oauth.oidc.authorize_redirect.return_value = app.response_class(status=302, headers={'Location': 'http://test.com'})
        
        response = client.get('/auth/login?cli_port=8080')
        assert response.status_code == 302
        
        with client.session_transaction() as session:
            assert session['cli_port'] == 8080  # Port validation returns integer
            assert session['cli_optionset'] == ''  # Default empty string


class TestAuthCallback:
    """Test /callback route CLI workflow handling."""
    
    @patch('app.routes.auth.oauth.oidc')
    def test_callback_normal_workflow(self, mock_oidc, client, app):
        """Test normal callback without CLI workflow."""
        # Mock OIDC response
        mock_token = {'id_token': 'fake_id_token'}
        mock_oidc.authorize_access_token.return_value = mock_token
        mock_oidc.userinfo.return_value = {
            'sub': 'user123',
            'email': 'user@example.com',
            'groups': 'users'
        }
        
        response = client.get('/auth/callback')
        assert response.status_code == 302
        assert response.headers['Location'] == '/'
    
    @patch('app.routes.auth.oauth.oidc')
    def test_callback_cli_workflow(self, mock_oidc, client, app_with_db):
        """Test callback with CLI workflow creates token and redirects to localhost."""
        # Setup CLI session
        with client.session_transaction() as session:
            session['cli_port'] = '12345'
            session['cli_optionset'] = 'test_option'
        
        # Mock OIDC response
        mock_token = {'id_token': 'fake_id_token'}
        mock_oidc.authorize_access_token.return_value = mock_token
        mock_oidc.userinfo.return_value = {
            'sub': 'user123',
            'email': 'user@example.com',
            'groups': 'users'
        }
        
        response = client.get('/auth/callback')
        assert response.status_code == 302
        
        # Should redirect to localhost with token
        location = response.headers['Location']
        assert location.startswith('http://localhost:12345?token=')
        
        # Extract token from redirect URL
        token = location.split('token=')[1]
        
        # Verify token was created in database
        from app.models import DownloadToken
        download_token = DownloadToken.query.filter_by(token=token).first()
        assert download_token is not None
        assert download_token.user == 'user123'
        assert download_token.cn == 'user@example.com'
        assert download_token.optionset_used == 'test_option'
        assert not download_token.collected
        # OIDC groups must be stored for correct template selection at download time
        assert download_token.user_groups == json.dumps(['users'])

        # CLI params should be cleaned up from session
        with client.session_transaction() as session:
            assert 'cli_port' not in session
            assert 'cli_optionset' not in session


    @patch('app.routes.auth.oauth.oidc')
    def test_callback_cli_workflow_stores_groups_list(self, mock_oidc, client, app_with_db):
        """
        Test that CLI callback stores multiple OIDC groups when userinfo returns a list.

        Groups are stored as JSON on the DownloadToken so the download route
        can use them to select the correct OpenVPN template rather than
        always falling back to the default template.
        """
        with client.session_transaction() as session:
            session['cli_port'] = '9999'
            session['cli_optionset'] = ''

        mock_oidc.authorize_access_token.return_value = {'id_token': 'tok'}
        mock_oidc.userinfo.return_value = {
            'sub': 'user456',
            'email': 'other@example.com',
            'groups': ['engineering', 'vpn-users', 'contractors'],
        }

        response = client.get('/auth/callback')
        assert response.status_code == 302

        location = response.headers['Location']
        token_uuid = location.split('token=')[1]

        from app.models import DownloadToken
        download_token = DownloadToken.query.filter_by(token=token_uuid).first()
        assert download_token is not None
        stored_groups = json.loads(download_token.user_groups)
        assert stored_groups == ['engineering', 'vpn-users', 'contractors']

    @patch('app.routes.auth.oauth.oidc')
    def test_callback_cli_workflow_stores_groups_comma_separated(self, mock_oidc, client, app_with_db):
        """
        Test that CLI callback handles comma-separated group strings from some OIDC providers.
        """
        with client.session_transaction() as session:
            session['cli_port'] = '9998'
            session['cli_optionset'] = ''

        mock_oidc.authorize_access_token.return_value = {'id_token': 'tok'}
        mock_oidc.userinfo.return_value = {
            'sub': 'user789',
            'email': 'csv@example.com',
            'groups': 'engineering,vpn-users',
        }

        response = client.get('/auth/callback')
        assert response.status_code == 302

        location = response.headers['Location']
        token_uuid = location.split('token=')[1]

        from app.models import DownloadToken
        download_token = DownloadToken.query.filter_by(token=token_uuid).first()
        assert download_token is not None
        stored_groups = json.loads(download_token.user_groups)
        assert stored_groups == ['engineering', 'vpn-users']

    @patch('app.routes.auth.oauth.oidc')
    def test_callback_cli_workflow_stores_empty_list_when_no_groups(self, mock_oidc, client, app_with_db):
        """
        Tests that a user with no groups field in the OIDC response gets an
        empty JSON list stored on the token.

        Ensures the download route's fallback to default template is explicit
        and consistent rather than dependent on None-handling in multiple places.
        """
        with client.session_transaction() as session:
            session['cli_port'] = '9997'
            session['cli_optionset'] = ''

        mock_oidc.authorize_access_token.return_value = {'id_token': 'tok'}
        mock_oidc.userinfo.return_value = {
            'sub': 'nogroupuser',
            'email': 'nogroup@example.com',
            # No 'groups' key at all
        }

        response = client.get('/auth/callback')
        assert response.status_code == 302

        location = response.headers['Location']
        token_uuid = location.split('token=')[1]

        from app.models import DownloadToken
        download_token = DownloadToken.query.filter_by(token=token_uuid).first()
        assert download_token is not None
        assert json.loads(download_token.user_groups) == []

    @patch('app.routes.auth.oauth.oidc')
    def test_callback_cli_workflow_stores_empty_list_when_groups_is_empty_list(
            self, mock_oidc, client, app_with_db):
        """
        Tests that an empty groups list from the OIDC provider is stored correctly.
        """
        with client.session_transaction() as session:
            session['cli_port'] = '9996'
            session['cli_optionset'] = ''

        mock_oidc.authorize_access_token.return_value = {'id_token': 'tok'}
        mock_oidc.userinfo.return_value = {
            'sub': 'emptygroups',
            'email': 'empty@example.com',
            'groups': [],
        }

        response = client.get('/auth/callback')
        assert response.status_code == 302

        location = response.headers['Location']
        token_uuid = location.split('token=')[1]

        from app.models import DownloadToken
        download_token = DownloadToken.query.filter_by(token=token_uuid).first()
        assert download_token is not None
        assert json.loads(download_token.user_groups) == []


class TestDownloadRoute:
    """Test /download route for CLI workflow."""
    
    def test_download_without_token(self, client, app_with_db):
        """Test download request without token parameter."""
        response = client.get('/download')
        assert response.status_code == 400
        assert response.json['error'] == 'Token required'
    
    def test_download_with_invalid_token(self, client, app_with_db):
        """Test download request with invalid token."""
        response = client.get('/download?token=invalid-token')
        assert response.status_code == 400
        assert response.json['error'] == 'Invalid token'
    
    def test_download_with_expired_token(self, client, app_with_db):
        """Test download request with expired token."""
        # Create expired token
        with app_with_db.app_context():
            expired_token = DownloadToken(
                user='user123',
                cn='user@example.com',
                requester_ip='127.0.0.1',
                optionset_used=''
            )
            expired_token.token = str(uuid.uuid4())  # Set directly to bypass mass assignment protection
            expired_token.created_at = datetime.now(timezone.utc) - timedelta(minutes=10)  # Set directly to bypass mass assignment protection
            from app.extensions import db
            db.session.add(expired_token)
            db.session.commit()
            
            response = client.get(f'/download?token={expired_token.token}')
            assert response.status_code == 410
            assert response.json['error'] == 'Token expired'
    
    def test_download_with_used_token(self, client, app_with_db):
        """Test download request with already used token."""
        # Create used token
        with app_with_db.app_context():
            used_token = DownloadToken(
                user='user123',
                cn='user@example.com',
                requester_ip='127.0.0.1',
                optionset_used=''
            )
            used_token.token = str(uuid.uuid4())  # Set directly to bypass mass assignment protection
            used_token.collected = True  # Set directly to bypass mass assignment protection
            from app.extensions import db
            db.session.add(used_token)
            db.session.commit()
            
            response = client.get(f'/download?token={used_token.token}')
            assert response.status_code == 410
            assert response.json['error'] == 'Token already used'
    
    @patch('app.routes.download.request_signed_certificate')
    @patch('app.routes.download.generate_key_and_csr')
    @patch('app.routes.download.find_best_template_match')
    @patch('app.routes.download.render_config_template')
    @patch('app.routes.download.process_tls_crypt_key')
    def test_download_success(self, mock_tls_crypt, mock_render, mock_template,
                             mock_csr, mock_sign, client, app_with_db):
        """Test successful download with valid token."""
        # Setup mocks
        mock_key = MagicMock()
        mock_key.private_bytes.return_value = b'fake-private-key-pem'
        mock_csr_obj = MagicMock()
        mock_csr_obj.subject.get_attributes_for_oid.return_value = [
            MagicMock(value='user@example.com')
        ]
        mock_csr_obj.public_bytes.return_value = b'fake-csr-pem'
        
        mock_csr.return_value = (mock_key, mock_csr_obj)
        mock_sign.return_value = 'fake-signed-cert-pem'
        mock_template.return_value = ('default', 'fake-template-content')
        mock_render.return_value = 'fake-openvpn-config'
        mock_tls_crypt.return_value = ('v1', 'fake-tls-crypt-key')
        
        # Create valid token
        with app_with_db.app_context():
            valid_token = DownloadToken(
                token=str(uuid.uuid4()),
                user='user123',
                cn='user@example.com',
                requester_ip='127.0.0.1',
                optionset_used='option1,option2'
            )
            from app.extensions import db
            db.session.add(valid_token)
            db.session.commit()
            
            response = client.get(f'/download?token={valid_token.token}')
            assert response.status_code == 200
            assert response.headers['Content-Type'] == 'application/x-openvpn-profile'
            assert 'attachment' in response.headers['Content-Disposition']
            assert response.data == b'fake-openvpn-config'
            
            # Token should be marked as collected
            db.session.refresh(valid_token)
            assert valid_token.collected
            assert valid_token.ovpn_content == b'fake-openvpn-config'
    
    @patch('app.routes.download.request_signed_certificate')
    def test_download_signing_error(self, mock_sign, client, app_with_db):
        """Test download when signing service fails."""
        from app.utils.signing_client import SigningServiceError
        mock_sign.side_effect = SigningServiceError("Signing failed")
        
        # Create valid token
        with app_with_db.app_context():
            valid_token = DownloadToken(
                token=str(uuid.uuid4()),
                user='user123',
                cn='user@example.com',
                requester_ip='127.0.0.1',
                optionset_used=''
            )
            from app.extensions import db
            db.session.add(valid_token)
            db.session.commit()
            
            response = client.get(f'/download?token={valid_token.token}')
            assert response.status_code == 500
            assert response.json['error'] == 'Certificate signing failed'
    
    @patch('app.routes.download.generate_key_and_csr')
    def test_download_generic_error(self, mock_csr, client, app_with_db):
        """Test download when generic exception occurs."""
        mock_csr.side_effect = ValueError("Invalid key generation parameters")
        
        # Create valid token
        with app_with_db.app_context():
            valid_token = DownloadToken(
                token=str(uuid.uuid4()),
                user='user123',
                cn='user@example.com',
                requester_ip='127.0.0.1',
                optionset_used=''
            )
            from app.extensions import db
            db.session.add(valid_token)
            db.session.commit()
            
            response = client.get(f'/download?token={valid_token.token}')
            assert response.status_code == 500
            assert response.json['error'] == 'Profile generation failed'


class TestDownloadTokenModel:
    """Test DownloadToken model functionality."""
    
    def test_token_expiry_calculation(self, app_with_db):
        """Test is_download_window_expired method."""
        with app_with_db.app_context():
            # Fresh token (should not be expired)
            fresh_token = DownloadToken(
                user='user123',
                cn='user@example.com',
                requester_ip='127.0.0.1',
                optionset_used=''
            )
            fresh_token.token = str(uuid.uuid4())  # Set directly to bypass mass assignment protection
            fresh_token.created_at = datetime.now(timezone.utc)  # Set directly to bypass mass assignment protection
            assert not fresh_token.is_download_window_expired()
            
            # Expired token (older than 5 minutes)
            expired_token = DownloadToken(
                user='user123',
                cn='user@example.com',
                requester_ip='127.0.0.1',
                optionset_used=''
            )
            expired_token.token = str(uuid.uuid4())  # Set directly to bypass mass assignment protection
            expired_token.created_at = datetime.now(timezone.utc) - timedelta(minutes=6)  # Set directly to bypass mass assignment protection
            assert expired_token.is_download_window_expired()


class TestCLIWorkflowIntegration:
    """Integration tests for complete CLI workflow."""
    
    @patch('app.routes.auth.oauth.oidc')
    def test_complete_cli_workflow(self, mock_oidc, client, app_with_db):
        """Test complete workflow from login to download."""
        # Mock the authorize_redirect for login
        mock_oidc.authorize_redirect.return_value = app_with_db.response_class(status=302, headers={'Location': 'http://oidc.provider/auth'})
        
        # Step 1: Login with CLI parameters
        response = client.get('/auth/login?cli_port=8080&optionset=test')
        assert response.status_code == 302
        
        # Step 2: Mock OIDC callback
        mock_token = {'id_token': 'fake_id_token'}
        mock_oidc.authorize_access_token.return_value = mock_token
        mock_oidc.userinfo.return_value = {
            'sub': 'testuser',
            'email': 'test@example.com',
            'groups': 'users'
        }
        
        response = client.get('/auth/callback')
        assert response.status_code == 302
        
        # Extract token from redirect
        location = response.headers['Location']
        assert location.startswith('http://localhost:8080?token=')
        token = location.split('token=')[1]
        
        # Step 3: Verify token exists and is valid
        from app.models import DownloadToken
        download_token = DownloadToken.query.filter_by(token=token).first()
        assert download_token is not None
        assert download_token.user == 'testuser'
        assert download_token.optionset_used == 'test'
        
        # Step 4: Download profile using token
        with patch('app.routes.download.request_signed_certificate') as mock_sign, \
             patch('app.routes.download.generate_key_and_csr') as mock_csr, \
             patch('app.routes.download.find_best_template_match') as mock_template, \
             patch('app.routes.download.render_config_template') as mock_render, \
             patch('app.routes.download.process_tls_crypt_key') as mock_tls:
            
            # Setup mocks for successful download
            mock_key = MagicMock()
            mock_key.private_bytes.return_value = b'fake-key'
            mock_csr_obj = MagicMock()
            mock_csr_obj.subject.get_attributes_for_oid.return_value = [
                MagicMock(value='test@example.com')
            ]
            mock_csr_obj.public_bytes.return_value = b'fake-csr'
            
            mock_csr.return_value = (mock_key, mock_csr_obj)
            mock_sign.return_value = 'fake-cert'
            mock_template.return_value = ('default', 'template-content')
            mock_render.return_value = 'final-openvpn-config'
            mock_tls.return_value = ('v1', 'tls-key')
            
            download_response = client.get(f'/download?token={token}')
            assert download_response.status_code == 200
            assert download_response.data == b'final-openvpn-config'


class TestDownloadRouteCoverage:
    """Additional tests for download route coverage."""
    
    @patch('app.routes.download.request_signed_certificate')
    @patch('app.routes.download.generate_key_and_csr')
    @patch('app.routes.download.find_best_template_match')
    @patch('app.routes.download.render_config_template')
    @patch('app.routes.download.process_tls_crypt_key')
    def test_download_with_x_forwarded_for_header(self, mock_tls_crypt, mock_render, mock_template,
                                                mock_csr, mock_sign, client, app_with_db):
        """Test download handles X-Forwarded-For header for client IP."""
        # Setup mocks
        mock_key = MagicMock()
        mock_key.private_bytes.return_value = b'fake-key'
        mock_csr_obj = MagicMock()
        mock_csr_obj.subject.get_attributes_for_oid.return_value = [
            MagicMock(value='test@example.com')
        ]
        mock_csr_obj.public_bytes.return_value = b'fake-csr'
        
        mock_csr.return_value = (mock_key, mock_csr_obj)
        mock_sign.return_value = 'fake-cert'
        mock_template.return_value = ('default', 'template-content')
        mock_render.return_value = 'final-config'
        mock_tls_crypt.return_value = ('v1', 'tls-key')
        
        # Create valid token
        with app_with_db.app_context():
            valid_token = DownloadToken(
                token=str(uuid.uuid4()),
                user='testuser',
                cn='test@example.com',
                requester_ip='127.0.0.1',
                optionset_used=''
            )
            from app.extensions import db
            db.session.add(valid_token)
            db.session.commit()
            
            # Make request with X-Forwarded-For header
            response = client.get(f'/download?token={valid_token.token}',
                                headers={'X-Forwarded-For': '203.0.113.195, 70.41.3.18'})
            assert response.status_code == 200
            
            # Verify that the signing service was called with the forwarded IP
            mock_sign.assert_called_once()
            call_kwargs = mock_sign.call_args[1]
            assert call_kwargs['client_ip'] == '203.0.113.195'
    
    @patch('app.routes.download.request_signed_certificate')
    @patch('app.routes.download.generate_key_and_csr')
    @patch('app.routes.download.find_best_template_match')
    @patch('app.routes.download.render_config_template')
    @patch('app.routes.download.process_tls_crypt_key')
    def test_download_with_optionset_context_update(self, mock_tls_crypt, mock_render, mock_template,
                                                  mock_csr, mock_sign, client, app_with_db):
        """Test download updates context with optionset settings."""
        # Setup mocks
        mock_key = MagicMock()
        mock_key.private_bytes.return_value = b'fake-key'
        mock_csr_obj = MagicMock()
        mock_csr_obj.subject.get_attributes_for_oid.return_value = [
            MagicMock(value='test@example.com')
        ]
        mock_csr_obj.public_bytes.return_value = b'fake-csr'
        
        mock_csr.return_value = (mock_key, mock_csr_obj)
        mock_sign.return_value = 'fake-cert'
        mock_template.return_value = ('default', 'template-content')
        mock_render.return_value = 'final-config'
        mock_tls_crypt.return_value = ('v1', 'tls-key')
        
        # Create valid token with optionset that should have settings
        with app_with_db.app_context():
            valid_token = DownloadToken(
                token=str(uuid.uuid4()),
                user='testuser',
                cn='test@example.com',
                requester_ip='127.0.0.1',
                optionset_used='high_security,mobile_optimized'
            )
            from app.extensions import db
            db.session.add(valid_token)
            db.session.commit()
            
            # Mock the config to have optionset settings
            with patch.dict(app_with_db.config, {
                'OVPN_OPTIONS': {
                    'high_security': {
                        'name': 'High Security',
                        'settings': {'cipher': 'AES-256-GCM', 'auth': 'SHA512'}
                    },
                    'mobile_optimized': {
                        'name': 'Mobile Optimized',
                        'settings': {'fast-io': True, 'sndbuf': 65536}
                    }
                }
            }):
                response = client.get(f'/download?token={valid_token.token}')
                assert response.status_code == 200
                
                # Verify render_config_template was called with merged context
                mock_render.assert_called_once()
                render_kwargs = mock_render.call_args[1]
                assert render_kwargs['cipher'] == 'AES-256-GCM'
                assert render_kwargs['auth'] == 'SHA512'
                assert render_kwargs['fast-io'] == True
                assert render_kwargs['sndbuf'] == 65536

class TestDownloadRouteGroupsAndSessionToken:
    """
    Tests that the download route uses OIDC groups from the token for template
    selection, stores certificate expiry, and returns a VPN-Session-Token header.

    These cover the bug fix (CLI was always using default template regardless
    of OIDC groups) and new WEB_AUTH-supporting behaviour.

    Security considerations (OWASP API3 - Excessive Data Exposure):
    - VPN-Session-Token must only be the token UUID — no other user data leaked.
    - cert_expiry must be parsed defensively; malformed certs must not crash download.
    """

    @patch('app.routes.download.request_signed_certificate')
    @patch('app.routes.download.generate_key_and_csr')
    @patch('app.routes.download.find_best_template_match')
    @patch('app.routes.download.render_config_template')
    @patch('app.routes.download.process_tls_crypt_key')
    def test_download_uses_groups_from_token_for_template_selection(
            self, mock_tls, mock_render, mock_template, mock_csr, mock_sign,
            client, app_with_db):
        """
        Tests that find_best_template_match is called with the groups stored on
        the DownloadToken, not with an empty list.

        Regression test: previously the download route always passed [] to
        find_best_template_match, causing all CLI/WEB_AUTH users to receive the
        default template regardless of their OIDC group memberships.
        """
        mock_key = MagicMock()
        mock_key.private_bytes.return_value = b'key'
        mock_csr_obj = MagicMock()
        mock_csr_obj.subject.get_attributes_for_oid.return_value = [MagicMock(value='u@example.com')]
        mock_csr_obj.public_bytes.return_value = b'csr'
        mock_csr.return_value = (mock_key, mock_csr_obj)
        mock_sign.return_value = 'fake-cert'
        mock_template.return_value = ('engineering', 'template-content')
        mock_render.return_value = 'config'
        mock_tls.return_value = ('v1', 'tls-key')

        with app_with_db.app_context():
            token = DownloadToken(
                user='user123',
                cn='u@example.com',
                requester_ip='127.0.0.1',
                optionset_used='',
                user_groups=json.dumps(['engineering', 'vpn-users']),
            )
            token.token = str(uuid.uuid4())
            from app.extensions import db
            db.session.add(token)
            db.session.commit()

            response = client.get(f'/download?token={token.token}')
            assert response.status_code == 200

            # find_best_template_match must have been called with the stored groups
            mock_template.assert_called_once()
            call_args = mock_template.call_args
            passed_groups = call_args[0][1]  # second positional arg
            assert passed_groups == ['engineering', 'vpn-users']

    @patch('app.routes.download.request_signed_certificate')
    @patch('app.routes.download.generate_key_and_csr')
    @patch('app.routes.download.find_best_template_match')
    @patch('app.routes.download.render_config_template')
    @patch('app.routes.download.process_tls_crypt_key')
    def test_download_uses_empty_groups_when_token_has_none(
            self, mock_tls, mock_render, mock_template, mock_csr, mock_sign,
            client, app_with_db):
        """
        Tests backward compatibility: tokens without user_groups (e.g. created
        before the migration) pass an empty group list to find_best_template_match,
        resulting in the default template being selected.
        """
        mock_key = MagicMock()
        mock_key.private_bytes.return_value = b'key'
        mock_csr_obj = MagicMock()
        mock_csr_obj.subject.get_attributes_for_oid.return_value = [MagicMock(value='u@example.com')]
        mock_csr_obj.public_bytes.return_value = b'csr'
        mock_csr.return_value = (mock_key, mock_csr_obj)
        mock_sign.return_value = 'fake-cert'
        mock_template.return_value = ('Default', 'default-content')
        mock_render.return_value = 'config'
        mock_tls.return_value = ('v1', 'tls-key')

        with app_with_db.app_context():
            token = DownloadToken(
                user='user123',
                cn='u@example.com',
                requester_ip='127.0.0.1',
                optionset_used='',
            )
            token.token = str(uuid.uuid4())
            token.user_groups = None  # Explicit None, simulating legacy token
            from app.extensions import db
            db.session.add(token)
            db.session.commit()

            response = client.get(f'/download?token={token.token}')
            assert response.status_code == 200

            mock_template.assert_called_once()
            passed_groups = mock_template.call_args[0][1]
            assert passed_groups == []

    @patch('app.routes.download.request_signed_certificate')
    @patch('app.routes.download.generate_key_and_csr')
    @patch('app.routes.download.find_best_template_match')
    @patch('app.routes.download.render_config_template')
    @patch('app.routes.download.process_tls_crypt_key')
    def test_download_returns_vpn_session_token_header(
            self, mock_tls, mock_render, mock_template, mock_csr, mock_sign,
            client, app_with_db):
        """
        Tests that a successful download returns the VPN-Session-Token response
        header containing the token UUID.

        OpenVPN Connect stores this token and sends it on subsequent HEAD
        /openvpn-api/profile requests to check whether the profile needs renewal.
        """
        mock_key = MagicMock()
        mock_key.private_bytes.return_value = b'key'
        mock_csr_obj = MagicMock()
        mock_csr_obj.subject.get_attributes_for_oid.return_value = [MagicMock(value='u@example.com')]
        mock_csr_obj.public_bytes.return_value = b'csr'
        mock_csr.return_value = (mock_key, mock_csr_obj)
        mock_sign.return_value = 'fake-cert'
        mock_template.return_value = ('Default', 'content')
        mock_render.return_value = 'config'
        mock_tls.return_value = ('v1', 'tls-key')

        with app_with_db.app_context():
            token_uuid = str(uuid.uuid4())
            token = DownloadToken(
                user='user123',
                cn='u@example.com',
                requester_ip='127.0.0.1',
                optionset_used='',
            )
            token.token = token_uuid
            from app.extensions import db
            db.session.add(token)
            db.session.commit()

            response = client.get(f'/download?token={token_uuid}')
            assert response.status_code == 200
            assert 'VPN-Session-Token' in response.headers
            assert response.headers['VPN-Session-Token'] == token_uuid

    @patch('app.routes.download.request_signed_certificate')
    @patch('app.routes.download.generate_key_and_csr')
    @patch('app.routes.download.find_best_template_match')
    @patch('app.routes.download.render_config_template')
    @patch('app.routes.download.process_tls_crypt_key')
    def test_download_stores_cert_expiry_from_signed_cert(
            self, mock_tls, mock_render, mock_template, mock_csr, mock_sign,
            client, app_with_db):
        """
        Tests that a successful download parses the certificate expiry from the
        signed PEM and stores it on the DownloadToken.

        cert_expiry is used by the HEAD /openvpn-api/profile freshness check
        so OpenVPN Connect can determine whether a profile needs renewal.
        """
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.x509.oid import NameOID
        from datetime import datetime, timezone, timedelta

        # Generate a self-signed cert with a known expiry
        key = ec.generate_private_key(ec.SECP256R1())
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, u"test@example.com"),
        ])
        expected_expiry = datetime(2027, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc))
            .not_valid_after(expected_expiry)
            .sign(key, hashes.SHA256())
        )
        cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')

        mock_key = MagicMock()
        mock_key.private_bytes.return_value = b'key'
        mock_csr_obj = MagicMock()
        mock_csr_obj.subject.get_attributes_for_oid.return_value = [MagicMock(value='test@example.com')]
        mock_csr_obj.public_bytes.return_value = b'csr'
        mock_csr.return_value = (mock_key, mock_csr_obj)
        mock_sign.return_value = cert_pem
        mock_template.return_value = ('Default', 'content')
        mock_render.return_value = 'config'
        mock_tls.return_value = ('v1', 'tls-key')

        with app_with_db.app_context():
            token = DownloadToken(
                user='user123',
                cn='test@example.com',
                requester_ip='127.0.0.1',
                optionset_used='',
            )
            token.token = str(uuid.uuid4())
            from app.extensions import db
            db.session.add(token)
            db.session.commit()
            token_uuid = token.token

            response = client.get(f'/download?token={token_uuid}')
            assert response.status_code == 200

            db.session.refresh(token)
            assert token.cert_expiry is not None
            # Allow for UTC timezone representation differences
            stored = token.cert_expiry
            if stored.tzinfo is None:
                stored = stored.replace(tzinfo=timezone.utc)
            assert stored == expected_expiry

    @patch('app.routes.download.request_signed_certificate')
    @patch('app.routes.download.generate_key_and_csr')
    @patch('app.routes.download.find_best_template_match')
    @patch('app.routes.download.render_config_template')
    @patch('app.routes.download.process_tls_crypt_key')
    def test_download_tolerates_unparseable_cert_expiry(
            self, mock_tls, mock_render, mock_template, mock_csr, mock_sign,
            client, app_with_db):
        """
        Tests that a download succeeds and returns 200 even when the signed cert
        PEM cannot be parsed (e.g. mock returning a non-PEM string).

        cert_expiry is best-effort: failure to parse must not block profile delivery.
        """
        mock_key = MagicMock()
        mock_key.private_bytes.return_value = b'key'
        mock_csr_obj = MagicMock()
        mock_csr_obj.subject.get_attributes_for_oid.return_value = [MagicMock(value='u@example.com')]
        mock_csr_obj.public_bytes.return_value = b'csr'
        mock_csr.return_value = (mock_key, mock_csr_obj)
        mock_sign.return_value = 'this-is-not-a-pem-cert'
        mock_template.return_value = ('Default', 'content')
        mock_render.return_value = 'config'
        mock_tls.return_value = ('v1', 'tls-key')

        with app_with_db.app_context():
            token = DownloadToken(
                user='user123',
                cn='u@example.com',
                requester_ip='127.0.0.1',
                optionset_used='',
            )
            token.token = str(uuid.uuid4())
            from app.extensions import db
            db.session.add(token)
            db.session.commit()

            response = client.get(f'/download?token={token.token}')
            # Must still succeed — cert_expiry is optional
            assert response.status_code == 200
            assert response.headers['Content-Type'] == 'application/x-openvpn-profile'

    @patch('app.routes.download.request_signed_certificate')
    @patch('app.routes.download.generate_key_and_csr')
    @patch('app.routes.download.find_best_template_match')
    @patch('app.routes.download.render_config_template')
    @patch('app.routes.download.process_tls_crypt_key')
    def test_download_with_malformed_user_groups_json_falls_back_to_default(
            self, mock_tls, mock_render, mock_template, mock_csr, mock_sign,
            client, app_with_db):
        """
        Tests that when user_groups on the token contains malformed JSON,
        the download route falls back to an empty group list (default template)
        rather than crashing.

        Defensive against DB corruption or deliberate manipulation of stored data.
        """
        mock_key = MagicMock()
        mock_key.private_bytes.return_value = b'key'
        mock_csr_obj = MagicMock()
        mock_csr_obj.subject.get_attributes_for_oid.return_value = [MagicMock(value='u@example.com')]
        mock_csr_obj.public_bytes.return_value = b'csr'
        mock_csr.return_value = (mock_key, mock_csr_obj)
        mock_sign.return_value = 'fake-cert'
        mock_template.return_value = ('Default', 'content')
        mock_render.return_value = 'config'
        mock_tls.return_value = ('v1', 'tls-key')

        with app_with_db.app_context():
            token = DownloadToken(
                user='user123',
                cn='u@example.com',
                requester_ip='127.0.0.1',
                optionset_used='',
            )
            token.token = str(uuid.uuid4())
            token.user_groups = 'not-valid-json'
            from app.extensions import db
            db.session.add(token)
            db.session.commit()

            response = client.get(f'/download?token={token.token}')
            assert response.status_code == 200

            # Should have called template match with empty list (safe fallback)
            passed_groups = mock_template.call_args[0][1]
            assert passed_groups == []

    @patch('app.routes.download.request_signed_certificate')
    @patch('app.routes.download.generate_key_and_csr')
    @patch('app.routes.download.find_best_template_match')
    @patch('app.routes.download.render_config_template')
    @patch('app.routes.download.process_tls_crypt_key')
    def test_download_vpn_session_token_header_contains_only_uuid(
            self, mock_tls, mock_render, mock_template, mock_csr, mock_sign,
            client, app_with_db):
        """
        OWASP API3 (Excessive Data Exposure): Verifies that the VPN-Session-Token
        response header contains only the token UUID and no other user data
        (no email, groups, sub, or PII is leaked in the header).
        """
        mock_key = MagicMock()
        mock_key.private_bytes.return_value = b'key'
        mock_csr_obj = MagicMock()
        mock_csr_obj.subject.get_attributes_for_oid.return_value = [MagicMock(value='u@example.com')]
        mock_csr_obj.public_bytes.return_value = b'csr'
        mock_csr.return_value = (mock_key, mock_csr_obj)
        mock_sign.return_value = 'fake-cert'
        mock_template.return_value = ('Default', 'content')
        mock_render.return_value = 'config'
        mock_tls.return_value = ('v1', 'tls-key')

        with app_with_db.app_context():
            token_uuid = str(uuid.uuid4())
            token = DownloadToken(
                user='sensitive-user-sub',
                cn='sensitive@example.com',
                requester_ip='127.0.0.1',
                optionset_used='',
                user_groups=json.dumps(['engineering']),
            )
            token.token = token_uuid
            from app.extensions import db
            db.session.add(token)
            db.session.commit()

            response = client.get(f'/download?token={token_uuid}')
            assert response.status_code == 200

            session_token_header = response.headers['VPN-Session-Token']
            # Must be exactly the UUID — no PII
            assert session_token_header == token_uuid
            assert 'sensitive' not in session_token_header
            assert 'engineering' not in session_token_header


class TestRetainGeneratedTemplate:
    """Tests for RETAIN_GENERATED_TEMPLATE debug feature."""

    @patch('app.routes.download.request_signed_certificate')
    @patch('app.routes.download.generate_key_and_csr')
    @patch('app.routes.download.find_best_template_match')
    @patch('app.routes.download.render_config_template')
    @patch('app.routes.download.process_tls_crypt_key')
    def test_retain_generated_template_writes_file(
            self, mock_tls, mock_render, mock_template, mock_csr, mock_sign,
            client, app_with_db, monkeypatch, tmp_path):
        """When RETAIN_GENERATED_TEMPLATE=1, the rendered profile is written to a temp file."""
        import tempfile
        monkeypatch.setenv('RETAIN_GENERATED_TEMPLATE', '1')
        monkeypatch.setattr(tempfile, 'gettempdir', lambda: str(tmp_path))

        mock_key = MagicMock()
        mock_key.private_bytes.return_value = b'key'
        mock_csr_obj = MagicMock()
        mock_csr_obj.subject.get_attributes_for_oid.return_value = [MagicMock(value='u@example.com')]
        mock_csr_obj.public_bytes.return_value = b'csr'
        mock_csr.return_value = (mock_key, mock_csr_obj)
        mock_sign.return_value = 'fake-cert'
        mock_template.return_value = ('Default', 'content')
        mock_render.return_value = 'debug-config-content'
        mock_tls.return_value = ('v1', 'tls-key')

        with app_with_db.app_context():
            token_uuid = str(uuid.uuid4())
            token = DownloadToken(user='u', cn='u@example.com', requester_ip='127.0.0.1', optionset_used='')
            token.token = token_uuid
            from app.extensions import db
            db.session.add(token)
            db.session.commit()

            response = client.get(f'/download?token={token_uuid}')
            assert response.status_code == 200

        debug_file = tmp_path / f'ovpn_debug_{token_uuid}.ovpn'
        assert debug_file.exists()
        assert debug_file.read_text(encoding='utf-8') == 'debug-config-content'

    @patch('app.routes.download.request_signed_certificate')
    @patch('app.routes.download.generate_key_and_csr')
    @patch('app.routes.download.find_best_template_match')
    @patch('app.routes.download.render_config_template')
    @patch('app.routes.download.process_tls_crypt_key')
    def test_retain_generated_template_off_by_default(
            self, mock_tls, mock_render, mock_template, mock_csr, mock_sign,
            client, app_with_db, monkeypatch, tmp_path):
        """When RETAIN_GENERATED_TEMPLATE is not set, no debug file is written."""
        import tempfile
        monkeypatch.delenv('RETAIN_GENERATED_TEMPLATE', raising=False)
        monkeypatch.setattr(tempfile, 'gettempdir', lambda: str(tmp_path))

        mock_key = MagicMock()
        mock_key.private_bytes.return_value = b'key'
        mock_csr_obj = MagicMock()
        mock_csr_obj.subject.get_attributes_for_oid.return_value = [MagicMock(value='u@example.com')]
        mock_csr_obj.public_bytes.return_value = b'csr'
        mock_csr.return_value = (mock_key, mock_csr_obj)
        mock_sign.return_value = 'fake-cert'
        mock_template.return_value = ('Default', 'content')
        mock_render.return_value = 'config'
        mock_tls.return_value = ('v1', 'tls-key')

        with app_with_db.app_context():
            token_uuid = str(uuid.uuid4())
            token = DownloadToken(user='u', cn='u@example.com', requester_ip='127.0.0.1', optionset_used='')
            token.token = token_uuid
            from app.extensions import db
            db.session.add(token)
            db.session.commit()

            response = client.get(f'/download?token={token_uuid}')
            assert response.status_code == 200

        assert not any(tmp_path.iterdir())
