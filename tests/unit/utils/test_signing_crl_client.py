"""
Unit tests for the signing service CRL client.

Tests the SigningCRLClient class that communicates with the signing service
to generate Certificate Revocation Lists.
"""

import pytest
import requests
from unittest.mock import Mock, patch, MagicMock
from flask import Flask
from app import create_app

from app.utils.signing_crl_client import SigningCRLClient, SigningCRLClientError, get_signing_crl_client


class TestSigningCRLClient:
    """Test the SigningCRLClient class."""

    @pytest.fixture
    def app(self):
        """Create a test Flask app."""
        import os
        # Set required environment variables for testing
        os.environ['FLASK_SECRET_KEY'] = 'test-secret-key-for-testing-only'
        os.environ['FERNET_ENCRYPTION_KEY'] = 'test-encryption-key-for-testing-only-32-chars-long'
        os.environ['TESTING'] = 'True'
        
        app = create_app('testing')
        app.config.update({
            'TESTING': True,
            'SECRET_KEY': 'test-secret-key-for-testing-only',
        })
        
        with app.app_context():
            yield app
    
    def test_get_signing_crl_client_factory(self, app):
        """Test the factory function returns a SigningCRLClient instance."""
        client = get_signing_crl_client()
        assert isinstance(client, SigningCRLClient)
    
    @patch('app.utils.signing_crl_client.loadConfigValueFromFileOrEnvironment')
    def test_init_with_default_config(self, mock_load_config, app):
        """Test initialization with default configuration values."""
        mock_load_config.side_effect = [
            'http://localhost:8500',  # SIGNING_SERVICE_URL
            'test-secret'             # SIGNING_SERVICE_API_SECRET
        ]
        
        client = SigningCRLClient()
        
        assert client.base_url == 'http://localhost:8500'
        assert client.api_secret == 'test-secret'
        assert client.session.headers['Content-Type'] == 'application/json'
        assert client.session.headers['Authorization'] == 'Bearer test-secret'
    
    @patch('app.utils.signing_crl_client.loadConfigValueFromFileOrEnvironment')
    def test_init_with_custom_config(self, mock_load_config, app):
        """Test initialization with custom configuration values."""
        mock_load_config.side_effect = [
            'https://signing.example.com',  # SIGNING_SERVICE_URL
            'custom-api-key'                # SIGNING_SERVICE_API_SECRET
        ]
        
        client = SigningCRLClient()
        
        assert client.base_url == 'https://signing.example.com'
        assert client.api_secret == 'custom-api-key'
        assert client.session.headers['Authorization'] == 'Bearer custom-api-key'
    
    @patch('app.utils.signing_crl_client.loadConfigValueFromFileOrEnvironment')
    def test_generate_crl_success(self, mock_load_config, app):
        """Test successful CRL generation."""
        mock_load_config.side_effect = ['http://localhost:8500', 'test-secret']
        
        client = SigningCRLClient()
        
        # Mock the session.post response
        mock_response = Mock()
        mock_response.content = b'\\x30\\x82\\x01\\x23'  # Mock DER-encoded CRL
        mock_response.raise_for_status.return_value = None
        
        with patch.object(client.session, 'post', return_value=mock_response) as mock_post:
            with app.test_request_context():
                revoked_certs = [
                    {'serial_number': 'abc123', 'revoked_at': '2025-08-26T10:00:00Z'},
                    {'serial_number': 'def456', 'revoked_at': '2025-08-26T11:00:00Z'}
                ]
                
                result = client.generate_crl(revoked_certs, 24)
                
                # Verify the request was made correctly
                mock_post.assert_called_once_with(
                    'http://localhost:8500/api/v1/generate-crl',
                    json={
                        'revoked_certificates': revoked_certs,
                        'next_update_hours': 24
                    },
                    timeout=30
                )
                
                # Verify the result
                assert result == b'\\x30\\x82\\x01\\x23'
    
    @patch('app.utils.signing_crl_client.loadConfigValueFromFileOrEnvironment')
    def test_generate_crl_with_default_next_update_hours(self, mock_load_config, app):
        """Test CRL generation with default next_update_hours parameter."""
        mock_load_config.side_effect = ['http://localhost:8500', 'test-secret']
        
        client = SigningCRLClient()
        
        mock_response = Mock()
        mock_response.content = b'\\x30\\x82\\x01\\x23'
        mock_response.raise_for_status.return_value = None
        
        with patch.object(client.session, 'post', return_value=mock_response) as mock_post:
            with app.test_request_context():
                revoked_certs = [{'serial_number': 'abc123', 'revoked_at': '2025-08-26T10:00:00Z'}]
                
                # Call without next_update_hours parameter (should default to 24)
                result = client.generate_crl(revoked_certs)
                
                # Verify default value was used
                mock_post.assert_called_once_with(
                    'http://localhost:8500/api/v1/generate-crl',
                    json={
                        'revoked_certificates': revoked_certs,
                        'next_update_hours': 24
                    },
                    timeout=30
                )
    
    @patch('app.utils.signing_crl_client.loadConfigValueFromFileOrEnvironment')
    def test_generate_crl_empty_revoked_list(self, mock_load_config, app):
        """Test CRL generation with empty revoked certificates list."""
        mock_load_config.side_effect = ['http://localhost:8500', 'test-secret']
        
        client = SigningCRLClient()
        
        mock_response = Mock()
        mock_response.content = b'\\x30\\x82\\x00\\x0A'  # Mock smaller CRL for empty list
        mock_response.raise_for_status.return_value = None
        
        with patch.object(client.session, 'post', return_value=mock_response) as mock_post:
            with app.test_request_context():
                result = client.generate_crl([], 48)
                
                mock_post.assert_called_once_with(
                    'http://localhost:8500/api/v1/generate-crl',
                    json={
                        'revoked_certificates': [],
                        'next_update_hours': 48
                    },
                    timeout=30
                )
                
                assert result == b'\\x30\\x82\\x00\\x0A'
    
    @patch('app.utils.signing_crl_client.loadConfigValueFromFileOrEnvironment')
    def test_generate_crl_http_error(self, mock_load_config, app):
        """Test CRL generation when signing service returns HTTP error."""
        mock_load_config.side_effect = ['http://localhost:8500', 'test-secret']
        
        client = SigningCRLClient()
        
        # Mock HTTP error response
        mock_response = Mock()
        mock_response.raise_for_status.side_effect = requests.exceptions.HTTPError("500 Server Error")
        
        with patch.object(client.session, 'post', return_value=mock_response):
            with app.test_request_context():
                with pytest.raises(SigningCRLClientError) as exc_info:
                    client.generate_crl([])
                
                assert "Failed to generate CRL from signing service" in str(exc_info.value)
                assert "500 Server Error" in str(exc_info.value)
    
    @patch('app.utils.signing_crl_client.loadConfigValueFromFileOrEnvironment')
    def test_generate_crl_connection_error(self, mock_load_config, app):
        """Test CRL generation when connection to signing service fails."""
        mock_load_config.side_effect = ['http://localhost:8500', 'test-secret']
        
        client = SigningCRLClient()
        
        # Mock connection error
        with patch.object(client.session, 'post', side_effect=requests.exceptions.ConnectionError("Connection refused")):
            with app.test_request_context():
                with pytest.raises(SigningCRLClientError) as exc_info:
                    client.generate_crl([])
                
                assert "Failed to generate CRL from signing service" in str(exc_info.value)
                assert "Connection refused" in str(exc_info.value)
    
    @patch('app.utils.signing_crl_client.loadConfigValueFromFileOrEnvironment')
    def test_generate_crl_timeout_error(self, mock_load_config, app):
        """Test CRL generation when request to signing service times out."""
        mock_load_config.side_effect = ['http://localhost:8500', 'test-secret']
        
        client = SigningCRLClient()
        
        # Mock timeout error
        with patch.object(client.session, 'post', side_effect=requests.exceptions.Timeout("Request timed out")):
            with app.test_request_context():
                with pytest.raises(SigningCRLClientError) as exc_info:
                    client.generate_crl([])
                
                assert "Failed to generate CRL from signing service" in str(exc_info.value)
                assert "Request timed out" in str(exc_info.value)
    
    @patch('app.utils.signing_crl_client.loadConfigValueFromFileOrEnvironment')
    def test_generate_crl_request_exception(self, mock_load_config, app):
        """Test CRL generation when general request exception occurs."""
        mock_load_config.side_effect = ['http://localhost:8500', 'test-secret']
        
        client = SigningCRLClient()
        
        # Mock general request exception
        with patch.object(client.session, 'post', side_effect=requests.exceptions.RequestException("Unknown error")):
            with app.test_request_context():
                with pytest.raises(SigningCRLClientError) as exc_info:
                    client.generate_crl([])
                
                assert "Failed to generate CRL from signing service" in str(exc_info.value)
                assert "Unknown error" in str(exc_info.value)
    
    @patch('app.utils.signing_crl_client.loadConfigValueFromFileOrEnvironment')
    def test_generate_crl_logs_request_details(self, mock_load_config, app, caplog):
        """Test that CRL generation logs request details for debugging."""
        mock_load_config.side_effect = ['http://localhost:8500', 'test-secret']
        
        client = SigningCRLClient()
        
        mock_response = Mock()
        mock_response.content = b'\\x30\\x82\\x01\\x23'
        mock_response.raise_for_status.return_value = None
        
        with patch.object(client.session, 'post', return_value=mock_response):
            with app.test_request_context():
                revoked_certs = [{'serial_number': 'abc123', 'revoked_at': '2025-08-26T10:00:00Z'}]
                client.generate_crl(revoked_certs, 12)
                
                # Check that appropriate log messages were generated
                assert any("Requesting CRL generation for 1 revoked certificates" in record.message 
                          for record in caplog.records)
                assert any("Successfully generated CRL from signing service, size: 16 bytes" in record.message 
                          for record in caplog.records)
    
    @patch('app.utils.signing_crl_client.loadConfigValueFromFileOrEnvironment')
    def test_generate_crl_logs_errors(self, mock_load_config, app, caplog):
        """Test that CRL generation logs errors appropriately."""
        mock_load_config.side_effect = ['http://localhost:8500', 'test-secret']
        
        client = SigningCRLClient()
        
        with patch.object(client.session, 'post', side_effect=requests.exceptions.HTTPError("403 Forbidden")):
            with app.test_request_context():
                with pytest.raises(SigningCRLClientError):
                    client.generate_crl([])
                
                # Check that error was logged
                assert any("Failed to generate CRL from signing service" in record.message 
                          for record in caplog.records)


class TestSigningCRLClientError:
    """Test the SigningCRLClientError exception class."""
    
    def test_signing_crl_client_error_inheritance(self):
        """Test that SigningCRLClientError inherits from Exception."""
        error = SigningCRLClientError("test error")
        assert isinstance(error, Exception)
        assert str(error) == "test error"
    
    def test_signing_crl_client_error_with_message(self):
        """Test SigningCRLClientError with custom message."""
        message = "Custom error message for testing"
        error = SigningCRLClientError(message)
        assert str(error) == message
    
    def test_signing_crl_client_error_can_be_raised(self):
        """Test that SigningCRLClientError can be raised and caught."""
        with pytest.raises(SigningCRLClientError) as exc_info:
            raise SigningCRLClientError("Test exception")
        
        assert str(exc_info.value) == "Test exception"