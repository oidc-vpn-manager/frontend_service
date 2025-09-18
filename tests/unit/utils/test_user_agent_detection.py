"""
Tests for User-Agent detection and OS parsing functionality.
"""

import pytest
from app.utils.user_agent_detection import parse_user_agent, detect_os_from_user_agent


@pytest.fixture
def app_with_db(app):
    """Add database initialization to the app fixture."""
    from app.extensions import db
    
    with app.app_context():
        db.create_all()
    
    yield app
    
    with app.app_context():
        db.drop_all()


class TestUserAgentDetection:
    """Test suite for user agent detection and OS parsing."""

    def test_parse_windows_user_agents(self):
        """Test parsing Windows user agents."""
        # Windows 10 Chrome
        user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        result = parse_user_agent(user_agent)
        
        assert result['os'] == 'Windows'
        assert result['os_version'] == '10'
        assert result['browser'] == 'Chrome'
        assert result['raw_user_agent'] == user_agent
        
        # Windows 11 Edge
        user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36 Edg/96.0.1054.62"
        result = parse_user_agent(user_agent)
        
        assert result['os'] == 'Windows'
        assert result['browser'] == 'Edge'

    def test_parse_macos_user_agents(self):
        """Test parsing macOS user agents."""
        # macOS Safari
        user_agent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Version/14.1.1 Safari/537.36"
        result = parse_user_agent(user_agent)
        
        assert result['os'] == 'macOS'
        assert result['os_version'] == '10.15.7'
        assert result['browser'] == 'Safari'
        
        # macOS Chrome
        user_agent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36"
        result = parse_user_agent(user_agent)
        
        assert result['os'] == 'macOS'
        assert result['browser'] == 'Chrome'

    def test_parse_linux_user_agents(self):
        """Test parsing Linux user agents."""
        # Ubuntu Firefox
        user_agent = "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0"
        result = parse_user_agent(user_agent)
        
        assert result['os'] == 'Linux'
        assert result['os_version'] == 'Ubuntu'
        assert result['browser'] == 'Firefox'
        
        # Generic Linux Chrome
        user_agent = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        result = parse_user_agent(user_agent)
        
        assert result['os'] == 'Linux'
        assert result['browser'] == 'Chrome'

    def test_parse_mobile_user_agents(self):
        """Test parsing mobile device user agents."""
        # iPhone
        user_agent = "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1"
        result = parse_user_agent(user_agent)
        
        assert result['os'] == 'iOS'
        assert result['os_version'] == '14.6'
        assert result['browser'] == 'Safari'
        assert result['is_mobile'] == True
        
        # Android
        user_agent = "Mozilla/5.0 (Linux; Android 11; SM-G991B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.120 Mobile Safari/537.36"
        result = parse_user_agent(user_agent)
        
        assert result['os'] == 'Android'
        assert result['os_version'] == '11'
        assert result['browser'] == 'Chrome'
        assert result['is_mobile'] == True

    def test_parse_unknown_user_agent(self):
        """Test parsing unknown or malformed user agents."""
        # Empty user agent
        result = parse_user_agent("")
        assert result['os'] == 'Unknown'
        assert result['browser'] == 'Unknown'
        assert result['raw_user_agent'] == ""
        
        # Custom/unknown user agent
        user_agent = "CustomBot/1.0 (Unknown Platform)"
        result = parse_user_agent(user_agent)
        assert result['os'] == 'Unknown'
        assert result['browser'] == 'Unknown'
        assert result['raw_user_agent'] == user_agent

    def test_detect_os_from_user_agent_simple(self):
        """Test simplified OS detection function."""
        # This is a simpler function that just returns OS name
        assert detect_os_from_user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64)") == "Windows"
        assert detect_os_from_user_agent("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)") == "macOS"
        assert detect_os_from_user_agent("Mozilla/5.0 (X11; Linux x86_64)") == "Linux"
        assert detect_os_from_user_agent("Mozilla/5.0 (iPhone; CPU iPhone OS 14_6)") == "iOS"
        assert detect_os_from_user_agent("Mozilla/5.0 (Linux; Android 11)") == "Android"
        assert detect_os_from_user_agent("") == "Unknown"
        assert detect_os_from_user_agent("CustomBot/1.0") == "Unknown"

    def test_user_agent_edge_cases(self):
        """Test edge cases and special user agents."""
        # None user agent
        result = parse_user_agent(None)
        assert result['os'] == 'Unknown'
        
        # Very long user agent (should be truncated in storage)
        long_ua = "Mozilla/5.0 " + "A" * 2000
        result = parse_user_agent(long_ua)
        assert result['raw_user_agent'] == long_ua  # Function returns full, storage will truncate
        
        # User agent with special characters
        special_ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; 中文) Chrome/91.0"
        result = parse_user_agent(special_ua)
        assert result['os'] == 'Windows'
        assert result['raw_user_agent'] == special_ua


class TestUserAgentIntegration:
    """Test integration of user agent detection with profile generation."""

    def test_profile_generation_captures_user_agent(self, app_with_db):
        """Test that profile generation captures and stores user agent data."""
        from app.models.certificate_request import CertificateRequest
        from app.extensions import db
        from unittest.mock import patch, MagicMock
        
        with app_with_db.app_context():
            # Mock signing service
            mock_cert = "-----BEGIN CERTIFICATE-----\nMOCK_CERT\n-----END CERTIFICATE-----"
            
            with patch('app.routes.root.request_signed_certificate', return_value=mock_cert), \
                 patch('app.routes.root.process_tls_crypt_key', return_value=('v2', 'mock_key')), \
                 patch('app.routes.root.find_best_template_match', return_value=('default.ovpn', 'mock template')), \
                 patch('app.routes.root.render_config_template', return_value='mock config'):
                
                with app_with_db.test_client() as client:
                    # Set up user session
                    with client.session_transaction() as sess:
                        sess['user'] = {
                            'sub': 'testuser123',
                            'email': 'test@example.com',
                            'groups': 'users'
                        }
                    
                    # Make request with specific user agent
                    user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
                    response = client.post('/', 
                                         data={'csrf_token': 'mock_token'},
                                         headers={'User-Agent': user_agent})
                    
                    # Check that certificate request was created
                    cert_requests = CertificateRequest.query.filter_by(user_id='testuser123').all()
                    assert len(cert_requests) >= 1
                    
                    cert_req = cert_requests[-1]  # Get the latest one
                    assert cert_req.detected_os == 'Windows'
                    assert cert_req.os_version == '10'
                    assert cert_req.browser == 'Chrome'
                    assert cert_req.certificate_type == 'user'
                    assert cert_req.request_source == 'web'
                    assert cert_req.signing_successful == True

    def test_api_server_bundle_captures_user_agent(self, app_with_db):
        """Test that API server bundle generation captures user agent data."""
        from app.models.certificate_request import CertificateRequest
        from app.models.presharedkey import PreSharedKey
        from app.extensions import db
        from unittest.mock import patch
        
        with app_with_db.app_context():
            # Create a test PSK
            test_key = 'test-key-123'
            psk = PreSharedKey(description='test-server', key=test_key)
            db.session.add(psk)
            db.session.commit()
            
            # Mock signing service
            mock_cert = "-----BEGIN CERTIFICATE-----\nMOCK_SERVER_CERT\n-----END CERTIFICATE-----"
            
            with patch('app.routes.api.v1.request_signed_certificate', return_value=mock_cert), \
                 patch('app.routes.api.v1.process_tls_crypt_key', return_value=('v2', 'mock_key')):
                
                with app_with_db.test_client() as client:
                    # Make API request with specific user agent
                    user_agent = 'curl/7.68.0'
                    response = client.get('/api/v1/server/bundle',
                                        headers={
                                            'Authorization': f'Bearer {test_key}',
                                            'User-Agent': user_agent
                                        })
                    
                    # Check that certificate request was created
                    cert_requests = CertificateRequest.query.filter_by(certificate_type='server').all()
                    assert len(cert_requests) >= 1
                    
                    cert_req = cert_requests[-1]  # Get the latest one
                    assert cert_req.detected_os == 'Unknown'  # curl doesn't have clear OS info
                    assert cert_req.certificate_type == 'server'
                    assert cert_req.request_source == 'api'
                    assert cert_req.template_set == psk.template_set
                    assert cert_req.signing_successful == True