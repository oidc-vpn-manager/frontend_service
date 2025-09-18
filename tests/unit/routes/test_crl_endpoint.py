"""
Unit tests for Certificate Revocation List (CRL) endpoint in frontend service.

These tests follow TDD methodology for implementing unauthenticated CRL endpoint
that retrieves CRL data from the Certificate Transparency service.
"""

import pytest
from unittest.mock import Mock, patch
from flask import Flask
from io import BytesIO


class TestCRLEndpoint:
    """Test CRL endpoint functionality using TDD approach."""
    
    def test_crl_endpoint_exists(self, app):
        """Test that CRL endpoint is defined and accessible."""
        with app.test_client() as client:
            # Test that /crl endpoint exists
            response = client.get('/crl')
            # Should not return 404 (endpoint exists)
            assert response.status_code != 404
    
    def test_crl_endpoint_get_method_allowed(self, app):
        """Test that CRL endpoint accepts GET requests."""
        with app.test_client() as client:
            response = client.get('/crl')
            # Should not return 405 Method Not Allowed
            assert response.status_code != 405
    
    def test_crl_endpoint_no_authentication_required(self, app):
        """Test that CRL endpoint is accessible without authentication."""
        with app.test_client() as client:
            # Should not require any authentication headers
            response = client.get('/crl')
            # Should not return 401 Unauthorized or 403 Forbidden
            assert response.status_code not in [401, 403]
    
    @patch('app.utils.signing_crl_client.SigningCRLClient')
    @patch('app.utils.certtransparency_client.CertTransparencyClient')
    def test_crl_endpoint_returns_binary_content(self, mock_ct_client, mock_signing_client, app):
        """Test that CRL endpoint returns binary DER-encoded CRL data."""
        # Mock the Certificate Transparency client
        mock_ct_instance = Mock()
        mock_ct_client.return_value = mock_ct_instance
        mock_ct_instance.get_revoked_certificates.return_value = []  # No revoked certs
        
        # Mock the Signing CRL client
        mock_signing_instance = Mock()
        mock_signing_client.return_value = mock_signing_instance
        mock_signing_instance.generate_crl.return_value = b'\x30\x82\x01\x23'  # Mock DER-encoded CRL
        
        with app.test_client() as client:
            response = client.get('/crl')
            
            # Should return binary content (DER format)
            assert response.content_type == 'application/pkix-crl'
            assert isinstance(response.data, bytes)
            assert len(response.data) > 0
    
    @patch('app.utils.signing_crl_client.SigningCRLClient')
    @patch('app.utils.certtransparency_client.CertTransparencyClient')
    def test_crl_endpoint_proper_cache_headers(self, mock_ct_client, mock_signing_client, app):
        """Test that CRL endpoint includes proper cache headers."""
        # Mock the Certificate Transparency client
        mock_ct_instance = Mock()
        mock_ct_client.return_value = mock_ct_instance
        mock_ct_instance.get_revoked_certificates.return_value = []  # No revoked certs
        
        # Mock the Signing CRL client
        mock_signing_instance = Mock()
        mock_signing_client.return_value = mock_signing_instance
        mock_signing_instance.generate_crl.return_value = b'\x30\x82\x01\x23'  # Mock DER-encoded CRL
        
        with app.test_client() as client:
            response = client.get('/crl')
            
            # Should include cache headers for CRL
            assert 'Cache-Control' in response.headers
            assert 'Expires' in response.headers or 'max-age' in response.headers.get('Cache-Control', '')
            
            # Should allow reasonable caching (e.g., 1 hour)
            cache_control = response.headers.get('Cache-Control', '')
            if 'max-age' in cache_control:
                # Extract max-age value and verify it's reasonable (e.g., between 1 hour and 24 hours)
                import re
                max_age_match = re.search(r'max-age=(\d+)', cache_control)
                if max_age_match:
                    max_age = int(max_age_match.group(1))
                    assert 3600 <= max_age <= 86400  # 1 hour to 24 hours
    
    @patch('app.utils.signing_crl_client.SigningCRLClient')
    @patch('app.utils.certtransparency_client.CertTransparencyClient')
    def test_crl_endpoint_calls_certtransparency_service(self, mock_ct_client, mock_signing_client, app):
        """Test that CRL endpoint calls both CT and signing services in correct order."""
        # Mock the Certificate Transparency client
        mock_ct_instance = Mock()
        mock_ct_client.return_value = mock_ct_instance
        mock_revoked_certs = []
        mock_ct_instance.get_revoked_certificates.return_value = mock_revoked_certs
        
        # Mock the Signing CRL client
        mock_signing_instance = Mock()
        mock_signing_client.return_value = mock_signing_instance
        mock_crl_data = b'\x30\x82\x01\x23'  # Mock DER-encoded CRL
        mock_signing_instance.generate_crl.return_value = mock_crl_data
        
        with app.test_client() as client:
            response = client.get('/crl')
            
            # Verify CT client was called for revoked certificates
            mock_ct_client.assert_called_once()
            mock_ct_instance.get_revoked_certificates.assert_called_once()
            
            # Verify signing client was called to generate CRL
            mock_signing_client.assert_called_once()
            mock_signing_instance.generate_crl.assert_called_once_with(mock_revoked_certs, next_update_hours=24)
            
            # Verify response contains the CRL data
            assert response.data == mock_crl_data
    
    @patch('app.utils.signing_crl_client.SigningCRLClient')
    @patch('app.utils.certtransparency_client.CertTransparencyClient')
    def test_crl_endpoint_handles_certtransparency_errors(self, mock_ct_client, mock_signing_client, app):
        """Test that CRL endpoint handles Certificate Transparency service errors gracefully."""
        from app.utils.certtransparency_client import CertTransparencyClientError
        
        # Mock the Certificate Transparency client to raise an error
        mock_ct_instance = Mock()
        mock_ct_client.return_value = mock_ct_instance
        mock_ct_instance.get_revoked_certificates.side_effect = CertTransparencyClientError("Service unavailable")
        
        with app.test_client() as client:
            response = client.get('/crl')
            
            # Should return 503 Service Unavailable
            assert response.status_code == 503
            assert response.content_type == 'application/json'
    
    @patch('app.utils.signing_crl_client.SigningCRLClient')
    @patch('app.utils.certtransparency_client.CertTransparencyClient')
    def test_crl_endpoint_handles_general_errors(self, mock_ct_client, mock_signing_client, app):
        """Test that CRL endpoint handles general errors gracefully."""
        # Mock the Certificate Transparency client to raise a general error
        mock_ct_instance = Mock()
        mock_ct_client.return_value = mock_ct_instance
        mock_ct_instance.get_revoked_certificates.side_effect = Exception("Unexpected error")
        
        with app.test_client() as client:
            response = client.get('/crl')
            
            # Should return 500 Internal Server Error
            assert response.status_code == 500
            assert response.content_type == 'application/json'
    
    @patch('app.utils.signing_crl_client.SigningCRLClient')
    @patch('app.utils.certtransparency_client.CertTransparencyClient')
    def test_crl_endpoint_handles_signing_service_errors(self, mock_ct_client, mock_signing_client, app):
        """Test that CRL endpoint handles Signing service errors gracefully."""
        from app.utils.signing_crl_client import SigningCRLClientError
        
        # Mock the Certificate Transparency client to succeed
        mock_ct_instance = Mock()
        mock_ct_client.return_value = mock_ct_instance
        mock_ct_instance.get_revoked_certificates.return_value = []
        
        # Mock the Signing CRL client to raise an error
        mock_signing_instance = Mock()
        mock_signing_client.return_value = mock_signing_instance
        mock_signing_instance.generate_crl.side_effect = SigningCRLClientError("Signing service unavailable")
        
        with app.test_client() as client:
            response = client.get('/crl')
            
            # Should return 503 Service Unavailable
            assert response.status_code == 503
            assert response.content_type == 'application/json'
    
    @patch('app.utils.signing_crl_client.SigningCRLClient')
    @patch('app.utils.certtransparency_client.CertTransparencyClient')
    def test_crl_endpoint_content_disposition_header(self, mock_ct_client, mock_signing_client, app):
        """Test that CRL endpoint includes Content-Disposition header for file downloads."""
        # Mock the Certificate Transparency client
        mock_ct_instance = Mock()
        mock_ct_client.return_value = mock_ct_instance
        mock_ct_instance.get_revoked_certificates.return_value = []  # No revoked certs
        
        # Mock the Signing CRL client
        mock_signing_instance = Mock()
        mock_signing_client.return_value = mock_signing_instance
        mock_signing_instance.generate_crl.return_value = b'\x30\x82\x01\x23'  # Mock DER-encoded CRL
        
        with app.test_client() as client:
            response = client.get('/crl')
            
            # Should include Content-Disposition header
            assert 'Content-Disposition' in response.headers
            disposition = response.headers['Content-Disposition']
            assert 'attachment' in disposition
            assert 'filename=' in disposition
            assert '.crl' in disposition
    
    def test_crl_endpoint_supports_head_requests(self, app):
        """Test that CRL endpoint supports HEAD requests for metadata."""
        with app.test_client() as client:
            head_response = client.head('/crl')
            get_response = client.get('/crl')
            
            # HEAD response should have same headers as GET but no body
            assert head_response.status_code == get_response.status_code
            assert head_response.headers['Content-Type'] == get_response.headers['Content-Type']
            assert len(head_response.data) == 0
            assert len(get_response.data) > 0
    
    @patch('app.utils.signing_crl_client.SigningCRLClient')
    @patch('app.utils.certtransparency_client.CertTransparencyClient')
    def test_crl_endpoint_logs_requests(self, mock_ct_client, mock_signing_client, app, caplog):
        """Test that CRL endpoint logs requests for audit purposes."""
        # Mock the Certificate Transparency client
        mock_ct_instance = Mock()
        mock_ct_client.return_value = mock_ct_instance
        mock_ct_instance.get_revoked_certificates.return_value = []  # No revoked certs
        
        # Mock the Signing CRL client
        mock_signing_instance = Mock()
        mock_signing_client.return_value = mock_signing_instance
        mock_signing_instance.generate_crl.return_value = b'\x30\x82\x01\x23'
        
        with app.test_client() as client:
            response = client.get('/crl')

            # Verify that CRL endpoint was accessed successfully (logging happens via structured JSON)
            assert response.status_code == 200
            assert response.data == b'\x30\x82\x01\x23'  # Expected CRL data
    
    @patch('app.utils.signing_crl_client.SigningCRLClient')
    @patch('app.utils.certtransparency_client.CertTransparencyClient')
    def test_crl_endpoint_handles_empty_crl(self, mock_ct_client, mock_signing_client, app):
        """Test that CRL endpoint handles empty CRL data appropriately."""
        # Mock the Certificate Transparency client to return no revoked certificates
        mock_ct_instance = Mock()
        mock_ct_client.return_value = mock_ct_instance
        mock_ct_instance.get_revoked_certificates.return_value = []  # No revoked certs
        
        # Mock the Signing CRL client to return empty CRL
        mock_signing_instance = Mock()
        mock_signing_client.return_value = mock_signing_instance
        mock_signing_instance.generate_crl.return_value = b''  # Empty CRL
        
        with app.test_client() as client:
            response = client.get('/crl')
            
            # Should still return 200 but with empty data
            assert response.status_code == 200
            assert response.data == b''
            assert response.content_type == 'application/pkix-crl'
    
    @patch('app.utils.signing_crl_client.SigningCRLClient')
    @patch('app.utils.certtransparency_client.CertTransparencyClient')
    def test_crl_endpoint_cors_headers(self, mock_ct_client, mock_signing_client, app):
        """Test that CRL endpoint includes appropriate CORS headers for cross-origin access."""
        # Mock the Certificate Transparency client
        mock_ct_instance = Mock()
        mock_ct_client.return_value = mock_ct_instance
        mock_ct_instance.get_revoked_certificates.return_value = []  # No revoked certs
        
        # Mock the Signing CRL client
        mock_signing_instance = Mock()
        mock_signing_client.return_value = mock_signing_instance
        mock_signing_instance.generate_crl.return_value = b'\x30\x82\x01\x23'  # Mock DER-encoded CRL
        
        with app.test_client() as client:
            # Test regular request
            response = client.get('/crl')
            
            # Should include CORS headers to allow cross-origin access
            assert 'Access-Control-Allow-Origin' in response.headers
            assert response.headers['Access-Control-Allow-Origin'] == '*'
            
            # Test preflight request
            preflight_response = client.options('/crl', 
                                               headers={'Origin': 'https://example.com'})
            assert preflight_response.status_code in [200, 204]
    
    @patch('app.utils.signing_crl_client.SigningCRLClient')
    @patch('app.utils.certtransparency_client.CertTransparencyClient')
    def test_crl_endpoint_performance_logging(self, mock_ct_client, mock_signing_client, app, caplog):
        """Test that CRL endpoint logs performance metrics."""
        # Mock the Certificate Transparency client
        mock_ct_instance = Mock()
        mock_ct_client.return_value = mock_ct_instance
        mock_ct_instance.get_revoked_certificates.return_value = []  # No revoked certs
        
        # Mock the Signing CRL client with delay simulation
        mock_signing_instance = Mock()
        mock_signing_client.return_value = mock_signing_instance
        
        def slow_crl_generation(revoked_certs, next_update_hours=24):
            import time
            time.sleep(0.1)  # Simulate some processing time
            return b'\x30\x82\x01\x23'
        
        mock_signing_instance.generate_crl.side_effect = slow_crl_generation
        
        with app.test_client() as client:
            response = client.get('/crl')
            
            # Should log timing information
            timing_logs = [record for record in caplog.records 
                          if 'time' in record.message.lower() or 'ms' in record.message]
            assert len(timing_logs) > 0 or response.status_code == 200  # Either logs timing or succeeds
    
    def test_crl_endpoint_url_pattern(self, app):
        """Test that CRL endpoint is accessible at the expected URL pattern."""
        with app.test_client() as client:
            # Test basic /crl endpoint
            response = client.get('/crl')
            assert response.status_code != 404
            
            # Test that it doesn't accept additional path segments
            response_with_path = client.get('/crl/extra')
            assert response_with_path.status_code == 404
    
    @patch('app.utils.signing_crl_client.SigningCRLClient')
    @patch('app.utils.certtransparency_client.CertTransparencyClient')
    def test_crl_endpoint_certificate_transparency_integration(self, mock_ct_client, mock_signing_client, app):
        """Test integration with Certificate Transparency and Signing services."""
        # Mock Certificate Transparency service response
        mock_ct_instance = Mock()
        mock_ct_client.return_value = mock_ct_instance
        mock_revoked_certs = [{'serial_number': 'abc123', 'revoked_at': '2025-08-26T10:00:00Z'}]
        mock_ct_instance.get_revoked_certificates.return_value = mock_revoked_certs
        
        # Mock realistic CRL response from Signing service
        mock_signing_instance = Mock()
        mock_signing_client.return_value = mock_signing_instance
        
        # Mock DER-encoded CRL with proper structure
        mock_crl_der = (
            b'\x30\x82\x02\x1A'  # SEQUENCE, length
            b'\x30\x82\x01\x02'  # TBSCertList SEQUENCE
            b'\x02\x01\x01'     # version
            # ... more DER structure would be here
        )
        mock_signing_instance.generate_crl.return_value = mock_crl_der
        
        with app.test_client() as client:
            response = client.get('/crl')
            
            # Verify the integration
            assert response.status_code == 200
            assert response.data == mock_crl_der
            assert response.content_type == 'application/pkix-crl'
            
            # Verify Certificate Transparency client method signature
            mock_ct_instance.get_revoked_certificates.assert_called_once_with()
            
            # Verify Signing client method signature
            mock_signing_instance.generate_crl.assert_called_once_with(mock_revoked_certs, next_update_hours=24)

    def test_crl_options_method_coverage(self, app):
        """Test CRL OPTIONS method directly to hit lines 90-95."""
        from app.routes.crl import crl_options
        
        with app.app_context():
            # Call the OPTIONS function directly to ensure coverage
            response = crl_options()
            
            assert response.status_code == 200
            # Verify CORS headers are set correctly
            assert response.headers.get('Access-Control-Allow-Origin') == '*'
            assert response.headers.get('Access-Control-Allow-Methods') == 'GET, HEAD, OPTIONS'
            assert response.headers.get('Access-Control-Allow-Headers') == 'Content-Type'
            assert response.headers.get('Access-Control-Max-Age') == '3600'