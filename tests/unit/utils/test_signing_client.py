"""
Unit tests for the signing_client utility.
"""

import pytest
import requests
from flask import Flask
from unittest.mock import MagicMock

from app.utils.signing_client import (
    request_signed_certificate, 
    request_certificate_revocation, 
    request_bulk_certificate_revocation,
    SigningServiceError
)

@pytest.fixture
def app():
    """Provides a basic Flask app with signing service config."""
    app = Flask(__name__)
    app.config['SIGNING_SERVICE_URL'] = 'http://test-signing-service'
    app.config['SIGNING_SERVICE_API_SECRET'] = 'test-secret'
    return app

class TestRequestSignedCertificate:
    """
    Tests for the request_signed_certificate function.
    """

    def test_request_success(self, app, monkeypatch):
        """
        Tests the successful path where a valid certificate is returned.
        """
        # Arrange: Mock the requests.post call
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'certificate': '---BEGIN CERT---...'}
        monkeypatch.setattr(requests, 'post', MagicMock(return_value=mock_response))

        with app.app_context():
            # Act
            cert = request_signed_certificate('---BEGIN CSR---...')
        
        # Assert
        assert cert == '---BEGIN CERT---...'
        requests.post.assert_called_once()
        call_args, call_kwargs = requests.post.call_args
        assert call_kwargs['json']['csr'] == '---BEGIN CSR---...'
        assert 'Bearer test-secret' in call_kwargs['headers']['Authorization']

    def test_request_success_with_user_id(self, app, monkeypatch):
        """
        Tests the successful path where a valid certificate is returned with user_id provided.
        """
        # Arrange: Mock the requests.post call
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'certificate': '---BEGIN CERT---...'}
        monkeypatch.setattr(requests, 'post', MagicMock(return_value=mock_response))

        with app.app_context():
            # Act
            cert = request_signed_certificate('---BEGIN CSR---...', user_id='testuser')
        
        # Assert
        assert cert == '---BEGIN CERT---...'
        requests.post.assert_called_once()
        call_args, call_kwargs = requests.post.call_args
        assert call_kwargs['json']['csr'] == '---BEGIN CSR---...'
        assert call_kwargs['json']['user_id'] == 'testuser'  # Should include user_id
        assert 'Bearer test-secret' in call_kwargs['headers']['Authorization']

    def test_request_http_error(self, app, monkeypatch):
        """
        Tests that an HTTP error from the service raises SigningServiceError.
        """
        mock_response = MagicMock()
        mock_response.raise_for_status.side_effect = requests.exceptions.HTTPError("401 Client Error")
        monkeypatch.setattr(requests, 'post', MagicMock(return_value=mock_response))
        
        with app.app_context():
            with pytest.raises(SigningServiceError, match="Failed to connect"):
                request_signed_certificate('...')

    def test_request_connection_error(self, app, monkeypatch):
        """
        Tests that a network error raises SigningServiceError.
        """
        monkeypatch.setattr(requests, 'post', MagicMock(side_effect=requests.exceptions.ConnectionError("Connection failed")))
        
        with app.app_context():
            with pytest.raises(SigningServiceError, match="Failed to connect"):
                request_signed_certificate('...')
    
    def test_request_bad_response_json(self, app, monkeypatch):
        """
        Tests that a malformed JSON response raises SigningServiceError.
        """
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'wrong_key': '...'} # Missing 'certificate'
        monkeypatch.setattr(requests, 'post', MagicMock(return_value=mock_response))

        with app.app_context():
            with pytest.raises(SigningServiceError, match="Invalid response"):
                request_signed_certificate('...')

    def test_missing_configuration(self, app):
        """
        Tests that an error is raised if the service is not configured.
        """
        app.config['SIGNING_SERVICE_URL'] = None
        
        with app.app_context():
            with pytest.raises(SigningServiceError, match="not configured"):
                request_signed_certificate('...')


class TestRequestCertificateRevocation:
    """
    Tests for the request_certificate_revocation function.
    """

    def test_revocation_success(self, app, monkeypatch):
        """
        Tests the successful path where certificate is revoked successfully.
        """
        # Arrange: Mock the requests.post call
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'status': 'revoked', 'fingerprint': 'abc123'}
        monkeypatch.setattr(requests, 'post', MagicMock(return_value=mock_response))

        with app.app_context():
            # Act
            result = request_certificate_revocation('abc123', 'key_compromise', 'admin')
        
        # Assert
        assert result == {'status': 'revoked', 'fingerprint': 'abc123'}
        requests.post.assert_called_once()
        call_args, call_kwargs = requests.post.call_args
        assert call_kwargs['json']['fingerprint'] == 'abc123'
        assert call_kwargs['json']['reason'] == 'key_compromise'
        assert call_kwargs['json']['revoked_by'] == 'admin'
        assert 'Bearer test-secret' in call_kwargs['headers']['Authorization']

    def test_revocation_404_not_found(self, app, monkeypatch):
        """
        Tests that 404 response raises SigningServiceError with certificate not found.
        """
        mock_response = MagicMock()
        mock_response.status_code = 404
        monkeypatch.setattr(requests, 'post', MagicMock(return_value=mock_response))
        
        with app.app_context():
            with pytest.raises(SigningServiceError, match="Certificate not found"):
                request_certificate_revocation('abc123', 'key_compromise', 'admin')

    def test_revocation_400_bad_request(self, app, monkeypatch):
        """
        Tests that 400 response raises SigningServiceError with invalid request.
        """
        mock_response = MagicMock()
        mock_response.status_code = 400
        mock_response.json.return_value = {'error': 'Invalid reason'}
        monkeypatch.setattr(requests, 'post', MagicMock(return_value=mock_response))
        
        with app.app_context():
            with pytest.raises(SigningServiceError, match="Invalid revocation request: Invalid reason"):
                request_certificate_revocation('abc123', 'invalid_reason', 'admin')

    def test_revocation_503_service_unavailable(self, app, monkeypatch):
        """
        Tests that 503 response raises SigningServiceError with service unavailable.
        """
        mock_response = MagicMock()
        mock_response.status_code = 503
        monkeypatch.setattr(requests, 'post', MagicMock(return_value=mock_response))
        
        with app.app_context():
            with pytest.raises(SigningServiceError, match="Certificate Transparency service unavailable"):
                request_certificate_revocation('abc123', 'key_compromise', 'admin')

    def test_revocation_other_http_error(self, app, monkeypatch):
        """
        Tests that other HTTP errors raise_for_status exceptions are caught.
        """
        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_response.raise_for_status.side_effect = requests.exceptions.HTTPError("500 Server Error")
        monkeypatch.setattr(requests, 'post', MagicMock(return_value=mock_response))
        
        with app.app_context():
            with pytest.raises(SigningServiceError, match="Failed to connect to signing service"):
                request_certificate_revocation('abc123', 'key_compromise', 'admin')

    def test_revocation_connection_error(self, app, monkeypatch):
        """
        Tests that network errors raise SigningServiceError.
        """
        monkeypatch.setattr(requests, 'post', MagicMock(side_effect=requests.exceptions.ConnectionError("Connection failed")))
        
        with app.app_context():
            with pytest.raises(SigningServiceError, match="Failed to connect to signing service"):
                request_certificate_revocation('abc123', 'key_compromise', 'admin')

    def test_revocation_json_error(self, app, monkeypatch):
        """
        Tests that malformed JSON responses raise SigningServiceError.
        """
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.side_effect = ValueError("Invalid JSON")
        monkeypatch.setattr(requests, 'post', MagicMock(return_value=mock_response))

        with app.app_context():
            with pytest.raises(SigningServiceError, match="Invalid response from signing service"):
                request_certificate_revocation('abc123', 'key_compromise', 'admin')

    def test_revocation_missing_configuration(self, app):
        """
        Tests that an error is raised if the service is not configured.
        """
        app.config['SIGNING_SERVICE_URL'] = None
        
        with app.app_context():
            with pytest.raises(SigningServiceError, match="not configured"):
                request_certificate_revocation('abc123', 'key_compromise', 'admin')


class TestRequestBulkCertificateRevocation:
    """
    Tests for the request_bulk_certificate_revocation function.
    """

    def test_bulk_revocation_success(self, app, monkeypatch):
        """
        Tests the successful path where bulk revocation completes successfully.
        """
        # Arrange: Mock the requests.post call
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'revoked_count': 5, 'user_id': 'testuser'}
        monkeypatch.setattr(requests, 'post', MagicMock(return_value=mock_response))

        with app.app_context():
            # Act
            result = request_bulk_certificate_revocation('testuser', 'user_terminated', 'admin')
        
        # Assert
        assert result == {'revoked_count': 5, 'user_id': 'testuser'}
        requests.post.assert_called_once()
        call_args, call_kwargs = requests.post.call_args
        assert call_kwargs['json']['user_id'] == 'testuser'
        assert call_kwargs['json']['reason'] == 'user_terminated'
        assert call_kwargs['json']['revoked_by'] == 'admin'
        assert 'Bearer test-secret' in call_kwargs['headers']['Authorization']
        assert call_kwargs['timeout'] == 30  # Bulk operations take longer

    def test_bulk_revocation_400_bad_request(self, app, monkeypatch):
        """
        Tests that 400 response raises SigningServiceError with invalid request.
        """
        mock_response = MagicMock()
        mock_response.status_code = 400
        mock_response.json.return_value = {'error': 'Invalid user ID'}
        monkeypatch.setattr(requests, 'post', MagicMock(return_value=mock_response))
        
        with app.app_context():
            with pytest.raises(SigningServiceError, match="Invalid bulk revocation request: Invalid user ID"):
                request_bulk_certificate_revocation('', 'user_terminated', 'admin')

    def test_bulk_revocation_503_service_unavailable(self, app, monkeypatch):
        """
        Tests that 503 response raises SigningServiceError with service unavailable.
        """
        mock_response = MagicMock()
        mock_response.status_code = 503
        monkeypatch.setattr(requests, 'post', MagicMock(return_value=mock_response))
        
        with app.app_context():
            with pytest.raises(SigningServiceError, match="Certificate Transparency service unavailable"):
                request_bulk_certificate_revocation('testuser', 'user_terminated', 'admin')

    def test_bulk_revocation_other_http_error(self, app, monkeypatch):
        """
        Tests that other HTTP errors raise_for_status exceptions are caught.
        """
        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_response.raise_for_status.side_effect = requests.exceptions.HTTPError("500 Server Error")
        monkeypatch.setattr(requests, 'post', MagicMock(return_value=mock_response))
        
        with app.app_context():
            with pytest.raises(SigningServiceError, match="Failed to connect to signing service"):
                request_bulk_certificate_revocation('testuser', 'user_terminated', 'admin')

    def test_bulk_revocation_connection_error(self, app, monkeypatch):
        """
        Tests that network errors raise SigningServiceError.
        """
        monkeypatch.setattr(requests, 'post', MagicMock(side_effect=requests.exceptions.ConnectionError("Connection failed")))
        
        with app.app_context():
            with pytest.raises(SigningServiceError, match="Failed to connect to signing service"):
                request_bulk_certificate_revocation('testuser', 'user_terminated', 'admin')

    def test_bulk_revocation_json_error(self, app, monkeypatch):
        """
        Tests that malformed JSON responses raise SigningServiceError.
        """
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.side_effect = ValueError("Invalid JSON")
        monkeypatch.setattr(requests, 'post', MagicMock(return_value=mock_response))

        with app.app_context():
            with pytest.raises(SigningServiceError, match="Invalid response from signing service"):
                request_bulk_certificate_revocation('testuser', 'user_terminated', 'admin')

    def test_bulk_revocation_missing_configuration(self, app):
        """
        Tests that an error is raised if the service is not configured.
        """
        app.config['SIGNING_SERVICE_URL'] = None
        
        with app.app_context():
            with pytest.raises(SigningServiceError, match="not configured"):
                request_bulk_certificate_revocation('testuser', 'user_terminated', 'admin')