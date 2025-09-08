"""
Unit tests for Certificate Transparency client utility.
"""

import pytest
import requests
from unittest.mock import Mock, patch
from flask import Flask

from app.utils.certtransparency_client import (
    CertTransparencyClient, 
    CertTransparencyClientError, 
    get_certtransparency_client
)


class TestCertTransparencyClient:
    """Test the Certificate Transparency client."""

    def test_init_with_default_config(self, app):
        """Test client initialization with default configuration."""
        with app.app_context():
            client = CertTransparencyClient()
            assert client.base_url == 'http://certtransparency:8400'
            assert client.timeout == 30

    def test_init_with_custom_config(self, app):
        """Test client initialization with custom configuration."""
        with app.app_context():
            app.config['CERTTRANSPARENCY_SERVICE_URL'] = 'http://custom:9000'
            client = CertTransparencyClient()
            assert client.base_url == 'http://custom:9000'

    def test_init_with_explicit_url(self, app):
        """Test client initialization with explicit URL."""
        with app.app_context():
            client = CertTransparencyClient(base_url='http://explicit:7000', timeout=60)
            assert client.base_url == 'http://explicit:7000'
            assert client.timeout == 60

    @patch('app.utils.certtransparency_client.requests.get')
    def test_make_request_success(self, mock_get, app):
        """Test successful API request."""
        mock_response = Mock()
        mock_response.json.return_value = {'test': 'data'}
        mock_response.raise_for_status.return_value = None
        mock_get.return_value = mock_response

        with app.app_context():
            client = CertTransparencyClient()
            result = client._make_request('test', {'param': 'value'})

        assert result == {'test': 'data'}
        mock_get.assert_called_once_with(
            'http://certtransparency:8400/test',
            params={'param': 'value'},
            timeout=30
        )

    @patch('app.utils.certtransparency_client.requests.get')
    def test_make_request_http_error(self, mock_get, app):
        """Test API request with HTTP error."""
        mock_get.side_effect = requests.HTTPError("404 Not Found")

        with app.app_context():
            client = CertTransparencyClient()
            with pytest.raises(CertTransparencyClientError) as exc_info:
                client._make_request('test')

        assert "Failed to communicate with Certificate Transparency service" in str(exc_info.value)

    @patch('app.utils.certtransparency_client.requests.get')
    def test_make_request_json_error(self, mock_get, app):
        """Test API request with invalid JSON response."""
        mock_response = Mock()
        mock_response.raise_for_status.return_value = None
        mock_response.json.side_effect = ValueError("Invalid JSON")
        mock_get.return_value = mock_response

        with app.app_context():
            client = CertTransparencyClient()
            with pytest.raises(CertTransparencyClientError) as exc_info:
                client._make_request('test')

        assert "Invalid response from Certificate Transparency service" in str(exc_info.value)

    @patch('app.utils.certtransparency_client.requests.get')
    def test_list_certificates(self, mock_get, app):
        """Test listing certificates."""
        mock_response = Mock()
        mock_response.json.return_value = {'certificates': []}
        mock_response.raise_for_status.return_value = None
        mock_get.return_value = mock_response

        with app.app_context():
            client = CertTransparencyClient()
            result = client.list_certificates(page=2, limit=50, type='client')

        expected_params = {'page': 2, 'limit': 50, 'type': 'client'}
        mock_get.assert_called_once_with(
            'http://certtransparency:8400/certificates',
            params=expected_params,
            timeout=30
        )
        assert result == {'certificates': []}

    @patch('app.utils.certtransparency_client.requests.get')
    def test_get_certificate_by_fingerprint(self, mock_get, app):
        """Test getting certificate by fingerprint."""
        mock_response = Mock()
        mock_response.json.return_value = {'certificate': {'subject': 'test'}}
        mock_response.raise_for_status.return_value = None
        mock_get.return_value = mock_response

        with app.app_context():
            client = CertTransparencyClient()
            result = client.get_certificate_by_fingerprint('abc123', include_pem=False)

        mock_get.assert_called_once_with(
            'http://certtransparency:8400/certificates/abc123',
            params={'include_pem': 'false'},
            timeout=30
        )
        assert result == {'certificate': {'subject': 'test'}}

    @patch('app.utils.certtransparency_client.requests.get')
    def test_get_certificate_by_serial(self, mock_get, app):
        """Test getting certificate by serial number."""
        mock_response = Mock()
        mock_response.json.return_value = {'certificate': {'serial': '123'}}
        mock_response.raise_for_status.return_value = None
        mock_get.return_value = mock_response

        with app.app_context():
            client = CertTransparencyClient()
            result = client.get_certificate_by_serial('123456', include_pem=True)

        mock_get.assert_called_once_with(
            'http://certtransparency:8400/certificates/serial/123456',
            params={'include_pem': 'true'},
            timeout=30
        )

    @patch('app.utils.certtransparency_client.requests.get')
    def test_get_certificates_by_subject(self, mock_get, app):
        """Test getting certificates by subject."""
        mock_response = Mock()
        mock_response.json.return_value = {'certificates': []}
        mock_response.raise_for_status.return_value = None
        mock_get.return_value = mock_response

        with app.app_context():
            client = CertTransparencyClient()
            result = client.get_certificates_by_subject('test@example.com')

        mock_get.assert_called_once_with(
            'http://certtransparency:8400/certificates/subject/test@example.com',
            params={'include_pem': 'false', 'include_revoked': 'true'},
            timeout=30
        )

    @patch('app.utils.certtransparency_client.requests.get')
    def test_get_statistics(self, mock_get, app):
        """Test getting statistics."""
        mock_response = Mock()
        mock_response.json.return_value = {'total': 100}
        mock_response.raise_for_status.return_value = None
        mock_get.return_value = mock_response

        with app.app_context():
            client = CertTransparencyClient()
            result = client.get_statistics()

        mock_get.assert_called_once_with(
            'http://certtransparency:8400/statistics',
            params=None,
            timeout=30
        )
        assert result == {'total': 100}

    @patch('app.utils.certtransparency_client.requests.get')
    def test_search_certificates(self, mock_get, app):
        """Test searching certificates."""
        mock_response = Mock()
        mock_response.json.return_value = {'results': []}
        mock_response.raise_for_status.return_value = None
        mock_get.return_value = mock_response

        with app.app_context():
            client = CertTransparencyClient()
            result = client.search_certificates('test query', exact=True, limit=50)

        expected_params = {
            'q': 'test query',
            'exact': 'true',
            'limit': 50,
            'include_pem': 'false'
        }
        mock_get.assert_called_once_with(
            'http://certtransparency:8400/search',
            params=expected_params,
            timeout=30
        )

    def test_get_certtransparency_client(self, app):
        """Test the client factory function."""
        with app.app_context():
            client = get_certtransparency_client()
            assert isinstance(client, CertTransparencyClient)
            assert client.base_url == 'http://certtransparency:8400'

    @patch('app.utils.certtransparency_client.requests.get')
    def test_list_certificates_with_all_filters(self, mock_get, app):
        """Test list certificates with all possible filters."""
        mock_response = Mock()
        mock_response.json.return_value = {'certificates': []}
        mock_response.raise_for_status.return_value = None
        mock_get.return_value = mock_response

        with app.app_context():
            client = CertTransparencyClient()
            client.list_certificates(
                page=3,
                limit=25,
                type='server',
                subject='example.com',
                issuer='CA',
                serial='ABC123',
                fingerprint='def456',
                from_date='2025-01-01',
                to_date='2025-12-31',
                include_revoked=False,
                include_pem=True,
                sort='issued_at',
                order='asc'
            )

        expected_params = {
            'page': 3,
            'limit': 25,
            'type': 'server',
            'subject': 'example.com',
            'issuer': 'CA',
            'serial': 'ABC123',
            'fingerprint': 'def456',
            'from_date': '2025-01-01',
            'to_date': '2025-12-31',
            'include_revoked': False,
            'include_pem': True,
            'sort': 'issued_at',
            'order': 'asc'
        }
        mock_get.assert_called_once_with(
            'http://certtransparency:8400/certificates',
            params=expected_params,
            timeout=30
        )

    @patch('app.utils.certtransparency_client.requests.get')
    def test_timeout_configuration(self, mock_get, app):
        """Test that timeout is properly configured."""
        mock_response = Mock()
        mock_response.json.return_value = {}
        mock_response.raise_for_status.return_value = None
        mock_get.return_value = mock_response

        with app.app_context():
            client = CertTransparencyClient(timeout=120)
            client.get_statistics()

        mock_get.assert_called_once_with(
            'http://certtransparency:8400/statistics',
            params=None,
            timeout=120
        )

    @patch('app.utils.certtransparency_client.requests.get')
    def test_get_revoked_certificates_success(self, mock_get, app):
        """Test successful retrieval of revoked certificates."""
        # Mock response with both revoked and active certificates
        mock_response = Mock()
        mock_response.json.return_value = {
            'certificates': [
                {
                    'serial_number': 'abc123',
                    'revoked_at': '2025-08-26T10:00:00Z',
                    'revocation_reason': 'key_compromise'
                },
                {
                    'serial_number': 'def456',
                    'revoked_at': None  # Active certificate
                },
                {
                    'serial_number': 'ghi789',
                    'revoked_at': '2025-08-26T11:00:00Z'
                    # Missing revocation_reason should default to 'unspecified'
                }
            ]
        }
        mock_response.raise_for_status.return_value = None
        mock_get.return_value = mock_response

        with app.app_context():
            client = CertTransparencyClient()
            result = client.get_revoked_certificates()

        # Should only return revoked certificates with proper transformation
        expected_revoked = [
            {
                'serial_number': 'abc123',
                'revoked_at': '2025-08-26T10:00:00Z',
                'revocation_reason': 'key_compromise'
            },
            {
                'serial_number': 'ghi789',
                'revoked_at': '2025-08-26T11:00:00Z',
                'revocation_reason': 'unspecified'
            }
        ]
        
        assert result == expected_revoked
        mock_get.assert_called_once_with(
            'http://certtransparency:8400/certificates',
            params={
                'revoked_only': 'true',
                'include_revocation_details': 'true',
                'limit': 10000
            },
            timeout=30
        )

    @patch('app.utils.certtransparency_client.requests.get')
    def test_get_revoked_certificates_request_error(self, mock_get, app):
        """Test error handling in get_revoked_certificates."""
        mock_get.side_effect = requests.RequestException("Connection error")

        with app.app_context():
            client = CertTransparencyClient()
            
            with pytest.raises(CertTransparencyClientError) as exc_info:
                client.get_revoked_certificates()
            
            assert "Failed to retrieve revoked certificates" in str(exc_info.value)
            assert "Connection error" in str(exc_info.value)

    @patch('app.utils.certtransparency_client.requests.post')
    def test_revoke_certificate_success(self, mock_post, app):
        """Test successful certificate revocation."""
        mock_response = Mock()
        mock_response.json.return_value = {'status': 'revoked', 'revoked_at': '2025-08-26T10:00:00Z'}
        mock_response.raise_for_status.return_value = None
        mock_post.return_value = mock_response

        with app.app_context():
            client = CertTransparencyClient()
            result = client.revoke_certificate('abc123', 'key_compromise', 'admin')

        assert result == {'status': 'revoked', 'revoked_at': '2025-08-26T10:00:00Z'}
        mock_post.assert_called_once_with(
            'http://certtransparency:8400/certificates/abc123/revoke',
            json={
                'reason': 'key_compromise',
                'revoked_by': 'admin'
            },
            timeout=30
        )

    @patch('app.utils.certtransparency_client.requests.post')
    def test_revoke_certificate_request_error(self, mock_post, app):
        """Test error handling in certificate revocation."""
        mock_post.side_effect = requests.RequestException("HTTP 404 Not Found")

        with app.app_context():
            client = CertTransparencyClient()
            
            with pytest.raises(CertTransparencyClientError) as exc_info:
                client.revoke_certificate('abc123', 'key_compromise', 'admin')
            
            assert "Failed to revoke certificate" in str(exc_info.value)
            assert "HTTP 404 Not Found" in str(exc_info.value)

    @patch('app.utils.certtransparency_client.requests.post')
    def test_bulk_revoke_user_certificates_success(self, mock_post, app):
        """Test successful bulk revocation of user certificates."""
        mock_response = Mock()
        mock_response.json.return_value = {
            'revoked_count': 3,
            'user_id': 'testuser',
            'revoked_certificates': ['abc123', 'def456', 'ghi789']
        }
        mock_response.raise_for_status.return_value = None
        mock_post.return_value = mock_response

        with app.app_context():
            client = CertTransparencyClient()
            result = client.bulk_revoke_user_certificates('testuser', 'user_terminated', 'admin')

        expected_result = {
            'revoked_count': 3,
            'user_id': 'testuser',
            'revoked_certificates': ['abc123', 'def456', 'ghi789']
        }
        
        assert result == expected_result
        mock_post.assert_called_once_with(
            'http://certtransparency:8400/users/testuser/revoke-certificates',
            json={
                'reason': 'user_terminated',
                'revoked_by': 'admin'
            },
            timeout=30
        )

    @patch('app.utils.certtransparency_client.requests.post')
    def test_bulk_revoke_user_certificates_request_error(self, mock_post, app):
        """Test error handling in bulk certificate revocation."""
        mock_post.side_effect = requests.RequestException("HTTP 500 Internal Server Error")

        with app.app_context():
            client = CertTransparencyClient()
            
            with pytest.raises(CertTransparencyClientError) as exc_info:
                client.bulk_revoke_user_certificates('testuser', 'user_terminated', 'admin')
            
            assert "Failed to bulk revoke certificates" in str(exc_info.value)
            assert "HTTP 500 Internal Server Error" in str(exc_info.value)