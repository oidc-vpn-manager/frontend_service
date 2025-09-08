"""
Unit tests for user tracking functionality in signing client.

These tests follow TDD methodology for implementing user tracking
in certificate signing requests.
"""

import pytest
from unittest.mock import patch, Mock
import json
from flask import Flask

from app.utils.signing_client import request_signed_certificate, SigningServiceError


@pytest.fixture
def app():
    """Create test Flask app with signing service configuration."""
    app = Flask(__name__)
    app.config['SIGNING_SERVICE_URL'] = 'http://signing:8300'
    app.config['SIGNING_SERVICE_API_SECRET'] = 'secret123'
    return app


class TestSigningClientUserTracking:
    """Test user tracking functionality in signing client using TDD approach."""
    
    def test_request_signed_certificate_accepts_user_id_parameter(self, app):
        """Test that request_signed_certificate accepts optional user_id parameter."""
        with patch('app.utils.signing_client.requests.post') as mock_post:
            mock_response = Mock()
            mock_response.json.return_value = {'certificate': 'CERT_PEM'}
            mock_response.raise_for_status = Mock()
            mock_post.return_value = mock_response
            
            with app.app_context():
                # Should accept user_id parameter without error
                result = request_signed_certificate('CSR_PEM', user_id='user123')
                assert result == 'CERT_PEM'
    
    def test_request_signed_certificate_passes_user_id_in_payload(self, app):
        """Test that user_id is included in the signing service request payload."""
        with patch('app.utils.signing_client.requests.post') as mock_post:
            mock_response = Mock()
            mock_response.json.return_value = {'certificate': 'CERT_PEM'}
            mock_response.raise_for_status = Mock()
            mock_post.return_value = mock_response
            
            with app.app_context():
                request_signed_certificate('CSR_PEM', user_id='user456')
                
                # Verify the payload includes user_id
                call_args = mock_post.call_args
                assert call_args[1]['json'] == {
                    'csr': 'CSR_PEM',
                    'user_id': 'user456',
                    'certificate_type': 'client'
                }
    
    def test_request_signed_certificate_works_without_user_id(self, app):
        """Test that request_signed_certificate works without user_id for backward compatibility."""
        with patch('app.utils.signing_client.requests.post') as mock_post:
            mock_response = Mock()
            mock_response.json.return_value = {'certificate': 'CERT_PEM'}
            mock_response.raise_for_status = Mock()
            mock_post.return_value = mock_response
            
            with app.app_context():
                # Should work without user_id for backward compatibility
                result = request_signed_certificate('CSR_PEM')
                assert result == 'CERT_PEM'
                
                # Verify the payload doesn't include user_id
                call_args = mock_post.call_args
                assert call_args[1]['json'] == {
                    'csr': 'CSR_PEM',
                    'certificate_type': 'client'
                }
    
    def test_request_signed_certificate_handles_none_user_id(self, app):
        """Test that None user_id is handled gracefully."""
        with patch('app.utils.signing_client.requests.post') as mock_post:
            mock_response = Mock()
            mock_response.json.return_value = {'certificate': 'CERT_PEM'}
            mock_response.raise_for_status = Mock()
            mock_post.return_value = mock_response
            
            with app.app_context():
                # Should work with None user_id
                result = request_signed_certificate('CSR_PEM', user_id=None)
                assert result == 'CERT_PEM'
                
                # Verify the payload doesn't include user_id when None
                call_args = mock_post.call_args
                assert call_args[1]['json'] == {
                    'csr': 'CSR_PEM',
                    'certificate_type': 'client'
                }
    
    def test_request_signed_certificate_handles_empty_user_id(self, app):
        """Test that empty user_id is handled gracefully."""
        with patch('app.utils.signing_client.requests.post') as mock_post:
            mock_response = Mock()
            mock_response.json.return_value = {'certificate': 'CERT_PEM'}
            mock_response.raise_for_status = Mock()
            mock_post.return_value = mock_response
            
            with app.app_context():
                # Should work with empty string user_id
                result = request_signed_certificate('CSR_PEM', user_id='')
                assert result == 'CERT_PEM'
                
                # Verify the payload doesn't include user_id when empty
                call_args = mock_post.call_args
                assert call_args[1]['json'] == {
                    'csr': 'CSR_PEM',
                    'certificate_type': 'client'
                }