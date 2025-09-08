"""
Tests for CLI workflow (get_openvpn_config script support).
"""

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
            assert session['cli_port'] == '12345'
            assert session['cli_optionset'] == 'option1,option2'
    
    def test_login_with_cli_port_only(self, client, mock_oauth, app):
        """Test login with only cli_port parameter."""
        mock_oauth.oidc.authorize_redirect.return_value = app.response_class(status=302, headers={'Location': 'http://test.com'})
        
        response = client.get('/auth/login?cli_port=8080')
        assert response.status_code == 302
        
        with client.session_transaction() as session:
            assert session['cli_port'] == '8080'
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
        
        # CLI params should be cleaned up from session
        with client.session_transaction() as session:
            assert 'cli_port' not in session
            assert 'cli_optionset' not in session


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
                token=str(uuid.uuid4()),
                user='user123',
                cn='user@example.com',
                requester_ip='127.0.0.1',
                optionset_used='',
                created_at=datetime.now(timezone.utc) - timedelta(minutes=10)  # 10 minutes ago
            )
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
                token=str(uuid.uuid4()),
                user='user123',
                cn='user@example.com',
                requester_ip='127.0.0.1',
                optionset_used='',
                collected=True  # Already collected
            )
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
                token=str(uuid.uuid4()),
                user='user123',
                cn='user@example.com',
                requester_ip='127.0.0.1',
                optionset_used='',
                created_at=datetime.now(timezone.utc)
            )
            assert not fresh_token.is_download_window_expired()
            
            # Expired token (older than 5 minutes)
            expired_token = DownloadToken(
                token=str(uuid.uuid4()),
                user='user123',
                cn='user@example.com',
                requester_ip='127.0.0.1',
                optionset_used='',
                created_at=datetime.now(timezone.utc) - timedelta(minutes=6)
            )
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