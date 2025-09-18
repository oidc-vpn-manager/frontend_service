"""
Tests for CertificateRequest model.
"""

import pytest
from unittest.mock import MagicMock
from app.models.certificate_request import CertificateRequest


class TestCertificateRequestModel:
    """Test suite for CertificateRequest model."""

    def test_certificate_request_creation(self, app):
        """Test basic CertificateRequest creation."""
        with app.app_context():
            cert_req = CertificateRequest(
                common_name='test@example.com',
                certificate_type='user',
                user_id='user123',
                user_email='test@example.com',
                client_ip='192.168.1.100',
                detected_os='Windows',
                os_version='10',
                browser='Chrome',
                browser_version='91.0.4472.124',
                is_mobile=False,
                request_source='web'
            )
            
            assert cert_req.common_name == 'test@example.com'
            assert cert_req.certificate_type == 'user'
            assert cert_req.detected_os == 'Windows'
            assert cert_req.is_mobile == False

    def test_certificate_request_create_from_request(self, app):
        """Test creating CertificateRequest from Flask request object."""
        with app.app_context():
            # Mock Flask request
            mock_request = MagicMock()
            mock_request.headers.get.side_effect = lambda key, default=None: {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                'X-Forwarded-For': None
            }.get(key, default)
            mock_request.remote_addr = '192.168.1.100'
            
            user_info = {
                'sub': 'user123',
                'email': 'test@example.com'
            }
            
            cert_req = CertificateRequest.create_from_request(
                flask_request=mock_request,
                common_name='test@example.com',
                certificate_type='user',
                user_info=user_info,
                template_name='default.ovpn',
                request_source='web'
            )
            
            assert cert_req.common_name == 'test@example.com'
            assert cert_req.certificate_type == 'user'
            assert cert_req.user_id == 'user123'
            assert cert_req.user_email == 'test@example.com'
            assert cert_req.client_ip == '192.168.1.100'
            assert cert_req.detected_os == 'Windows'
            assert cert_req.os_version == '10'
            assert cert_req.browser == 'Chrome'
            assert cert_req.template_name == 'default.ovpn'
            assert cert_req.request_source == 'web'
            assert cert_req.is_mobile == False

    def test_certificate_request_with_forwarded_ip(self, app):
        """Test CertificateRequest creation with X-Forwarded-For header."""
        with app.app_context():
            mock_request = MagicMock()
            mock_request.headers.get.side_effect = lambda key, default=None: {
                'User-Agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15',
                'X-Forwarded-For': '203.0.113.195, 192.168.1.1'
            }.get(key, default)
            mock_request.remote_addr = '10.0.0.1'
            
            cert_req = CertificateRequest.create_from_request(
                flask_request=mock_request,
                common_name='mobile@example.com'
            )
            
            # Should use first IP from X-Forwarded-For
            assert cert_req.client_ip == '203.0.113.195'
            assert cert_req.detected_os == 'iOS'
            assert cert_req.is_mobile == True

    def test_certificate_request_summaries(self, app):
        """Test OS and browser summary methods."""
        with app.app_context():
            cert_req = CertificateRequest(
                detected_os='Windows',
                os_version='10',
                browser='Chrome',
                browser_version='91.0.4472.124',
                is_mobile=False
            )
            
            assert cert_req.get_os_summary() == 'Windows 10'
            assert cert_req.get_browser_summary() == 'Chrome 91'
            
            # Test mobile browser
            cert_req.is_mobile = True
            assert cert_req.get_browser_summary() == 'Chrome 91 (Mobile)'
            
            # Test unknown OS/browser
            cert_req.detected_os = 'Unknown'
            cert_req.browser = 'Unknown'
            assert cert_req.get_os_summary() == 'Unknown'
            assert cert_req.get_browser_summary() == 'Unknown'

    def test_certificate_request_to_dict(self, app):
        """Test conversion to dictionary."""
        with app.app_context():
            cert_req = CertificateRequest(
                common_name='test@example.com',
                certificate_type='user',
                detected_os='macOS',
                os_version='11.6',
                browser='Safari',
                is_mobile=False
            )
            
            data = cert_req.to_dict()
            
            assert data['common_name'] == 'test@example.com'
            assert data['certificate_type'] == 'user'
            assert data['detected_os'] == 'macOS'
            assert data['os_version'] == '11.6'
            assert data['browser'] == 'Safari'
            assert data['is_mobile'] == False

    def test_certificate_request_server_type(self, app):
        """Test CertificateRequest for server certificate type."""
        with app.app_context():
            mock_request = MagicMock()
            mock_request.headers.get.side_effect = lambda key, default=None: {
                'User-Agent': 'curl/7.68.0',
                'X-Forwarded-For': None
            }.get(key, default)
            mock_request.remote_addr = '10.0.0.1'
            
            cert_req = CertificateRequest.create_from_request(
                flask_request=mock_request,
                common_name='server-vpn-001',
                certificate_type='server',
                user_info=None,  # No user for server certs
                template_set='JustTCP',
                request_source='api'
            )
            
            assert cert_req.certificate_type == 'server'
            assert cert_req.user_id is None
            assert cert_req.user_email is None
            assert cert_req.template_set == 'JustTCP'
            assert cert_req.request_source == 'api'
            assert cert_req.detected_os == 'Unknown'  # curl doesn't have clear OS info

    def test_certificate_request_repr(self, app):
        """Test string representation."""
        with app.app_context():
            cert_req = CertificateRequest(
                common_name='test@example.com',
                certificate_type='user'
            )
            
            repr_str = repr(cert_req)
            assert 'CertificateRequest' in repr_str
            assert 'test@example.com' in repr_str
            assert 'user' in repr_str