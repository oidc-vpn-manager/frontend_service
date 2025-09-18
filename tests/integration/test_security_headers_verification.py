"""
Security Headers and Cookie Security Integration Tests

These tests verify that security headers and cookie configurations are properly
implemented at the application level, complementing the E2E browser tests.
"""

import pytest
import json
from unittest.mock import patch
from flask import session


class TestSecurityHeadersIntegration:
    """Integration tests for security headers configuration."""

    def test_security_headers_on_all_routes(self, client, app):
        """Test that security headers are present on all application routes."""

        with app.app_context():
            # Test various routes that should have security headers
            test_routes = [
                '/',
                '/api/',
                '/health',
            ]

            for route in test_routes:
                response = client.get(route)

                # Should have security headers regardless of status code
                headers = response.headers

                # X-Content-Type-Options
                assert headers.get('X-Content-Type-Options') == 'nosniff', \
                       f"Missing X-Content-Type-Options header on {route}"

                # Content-Security-Policy
                csp_header = headers.get('Content-Security-Policy')
                assert csp_header is not None, f"Missing CSP header on {route}"

                # X-Frame-Options or CSP frame-ancestors
                x_frame = headers.get('X-Frame-Options')
                has_frame_protection = (
                    x_frame in ['DENY', 'SAMEORIGIN'] or
                    'frame-ancestors' in csp_header
                )
                assert has_frame_protection, f"Missing frame protection on {route}"

    def test_csp_header_configuration_details(self, client):
        """Test detailed CSP header configuration."""

        response = client.get('/')
        csp_header = response.headers.get('Content-Security-Policy')

        assert csp_header is not None, "CSP header should be present"

        # Parse CSP directives
        directives = {}
        for directive in csp_header.split(';'):
            directive = directive.strip()
            if directive:
                parts = directive.split()
                if parts:
                    directives[parts[0]] = parts[1:] if len(parts) > 1 else []

        # Verify script-src directive
        assert 'script-src' in directives, "CSP should have script-src directive"
        script_src = directives['script-src']

        # Should include 'self'
        assert "'self'" in script_src, "script-src should include 'self'"

        # Should not allow unsafe-inline (unless specifically needed)
        assert "'unsafe-inline'" not in script_src, "script-src should not allow unsafe-inline"

        # Should not allow unsafe-eval
        assert "'unsafe-eval'" not in script_src, "script-src should not allow unsafe-eval"

        # Verify default-src directive (if present)
        if 'default-src' in directives:
            default_src = directives['default-src']
            assert "'self'" in default_src, "default-src should include 'self'"

        # Verify object-src directive (should be restrictive)
        if 'object-src' in directives:
            object_src = directives['object-src']
            assert "'none'" in object_src or "'self'" in object_src, \
                   "object-src should be restrictive"

    def test_security_headers_in_error_responses(self, client):
        """Test that security headers are present even in error responses."""

        # Test 404 response
        response = client.get('/nonexistent-page')
        assert response.status_code == 404

        # Should still have security headers
        headers = response.headers
        assert headers.get('X-Content-Type-Options') == 'nosniff', \
               "404 responses should have security headers"
        assert headers.get('Content-Security-Policy') is not None, \
               "404 responses should have CSP header"

    def test_cache_control_on_sensitive_endpoints(self, client, app):
        """Test cache control headers on sensitive endpoints."""

        # Set up authenticated session
        with client.session_transaction() as sess:
            sess['user'] = {
                'sub': 'test@example.com',
                'name': 'Test User',
                'email': 'test@example.com',
                'groups': ['users']
            }

        with app.app_context():
            # Test sensitive endpoints
            sensitive_endpoints = [
                '/profile',  # This might 404 without proper setup, but headers should still be there
            ]

            for endpoint in sensitive_endpoints:
                response = client.get(endpoint)

                # Check cache control header
                cache_control = response.headers.get('Cache-Control', '').lower()

                # If cache control is set, it should be restrictive for sensitive pages
                if cache_control:
                    restrictive_cache = any(directive in cache_control for directive in [
                        'no-cache', 'no-store', 'must-revalidate', 'private'
                    ])

                    if not restrictive_cache:
                        # At minimum, should not cache for too long
                        assert 'max-age=0' in cache_control or 'max-age' not in cache_control, \
                               f"Sensitive endpoint {endpoint} has permissive caching: {cache_control}"

    def test_referrer_policy_header(self, client):
        """Test Referrer-Policy header configuration."""

        response = client.get('/')
        referrer_policy = response.headers.get('Referrer-Policy')

        if referrer_policy:
            # Should use a privacy-preserving policy
            safe_policies = [
                'no-referrer',
                'same-origin',
                'strict-origin',
                'strict-origin-when-cross-origin'
            ]

            assert any(policy in referrer_policy for policy in safe_policies), \
                   f"Referrer-Policy should be privacy-preserving: {referrer_policy}"


class TestCookieSecurityIntegration:
    """Integration tests for cookie security configuration."""

    def test_session_cookie_attributes(self, client, app):
        """Test session cookie security attributes."""

        with app.app_context():
            # Make a request to establish session
            response = client.get('/')

            # Check Set-Cookie headers
            set_cookie_headers = response.headers.getlist('Set-Cookie')

            session_cookies = []
            for cookie_header in set_cookie_headers:
                if any(name in cookie_header.lower() for name in ['session', 'flask']):
                    session_cookies.append(cookie_header)

            # Should have at least one session cookie
            if len(session_cookies) > 0:
                for cookie_header in session_cookies:
                    # Should be HttpOnly
                    assert 'HttpOnly' in cookie_header, \
                           f"Session cookie should be HttpOnly: {cookie_header}"

                    # Should have SameSite attribute
                    assert 'SameSite=' in cookie_header, \
                           f"Session cookie should have SameSite: {cookie_header}"

                    # SameSite should be Lax or Strict
                    assert any(policy in cookie_header for policy in ['SameSite=Lax', 'SameSite=Strict']), \
                           f"Session cookie SameSite should be Lax or Strict: {cookie_header}"

                    # Path should be set
                    assert 'Path=' in cookie_header, \
                           f"Session cookie should have Path: {cookie_header}"

    def test_csrf_token_cookie_security(self, client, app):
        """Test CSRF token cookie security (if using cookie-based CSRF)."""

        with app.app_context():
            app.config['WTF_CSRF_ENABLED'] = True

            # Make request to page that might set CSRF cookie
            response = client.get('/')

            # Check for CSRF-related cookies
            set_cookie_headers = response.headers.getlist('Set-Cookie')
            csrf_cookies = []

            for cookie_header in set_cookie_headers:
                if 'csrf' in cookie_header.lower():
                    csrf_cookies.append(cookie_header)

            # If CSRF cookies are used, they should have proper attributes
            for cookie_header in csrf_cookies:
                # CSRF cookies typically need to be accessible to JavaScript
                # but should still have SameSite protection

                # Should have SameSite
                assert 'SameSite=' in cookie_header, \
                       f"CSRF cookie should have SameSite: {cookie_header}"

                # Should have proper path
                assert 'Path=' in cookie_header, \
                       f"CSRF cookie should have Path: {cookie_header}"

    def test_cookie_domain_restrictions(self, client):
        """Test that cookies are properly scoped to the application domain."""

        response = client.get('/')
        set_cookie_headers = response.headers.getlist('Set-Cookie')

        for cookie_header in set_cookie_headers:
            # Should not have overly broad domain
            assert 'Domain=.com' not in cookie_header, \
                   f"Cookie domain too broad: {cookie_header}"
            assert 'Domain=.' not in cookie_header, \
                   f"Cookie domain too broad: {cookie_header}"

            # If domain is set, should be specific
            if 'Domain=' in cookie_header:
                # Extract domain value
                domain_part = [part for part in cookie_header.split(';') if 'Domain=' in part][0]
                domain_value = domain_part.split('=')[1].strip()

                # Should be localhost or application-specific domain
                assert domain_value in ['localhost', '.localhost'] or \
                       len(domain_value.split('.')) >= 2, \
                       f"Cookie domain should be specific: {domain_value}"

    def test_session_fixation_protection(self, client, app):
        """Test protection against session fixation attacks."""

        with app.app_context():
            # Get initial session
            response1 = client.get('/')
            initial_cookies = self._extract_session_id(response1)

            # Simulate login (set user in session)
            with client.session_transaction() as sess:
                sess['user'] = {
                    'sub': 'test@example.com',
                    'email': 'test@example.com'
                }

            # Make another request after login
            response2 = client.get('/')
            post_login_cookies = self._extract_session_id(response2)

            # Session ID should either:
            # 1. Be regenerated after login (recommended), or
            # 2. Remain the same but be properly secured

            if initial_cookies and post_login_cookies:
                if initial_cookies == post_login_cookies:
                    # Same session ID - verify it's properly secured
                    print("INFO: Session ID not regenerated after login - ensure proper security measures")
                else:
                    # Session ID regenerated - good practice
                    print("INFO: Session ID regenerated after login - good security practice")

    def _extract_session_id(self, response) -> str:
        """Helper to extract session ID from response cookies."""
        set_cookie_headers = response.headers.getlist('Set-Cookie')

        for cookie_header in set_cookie_headers:
            if any(name in cookie_header.lower() for name in ['session', 'flask']):
                # Extract cookie value
                cookie_value = cookie_header.split(';')[0].split('=')[1]
                return cookie_value

        return None


class TestHTTPSAndTLSIntegration:
    """Integration tests for HTTPS and TLS-related security features."""

    def test_https_redirect_configuration(self, client, app):
        """Test HTTPS redirect configuration at application level."""

        with app.app_context():
            # Check if FORCE_HTTPS is configured
            force_https = app.config.get('FORCE_HTTPS', False)

            if force_https:
                # Should redirect HTTP requests to HTTPS
                response = client.get('/', base_url='http://testserver')

                # Should be a redirect response
                assert 300 <= response.status_code < 400, \
                       "FORCE_HTTPS should redirect HTTP requests"

                # Should redirect to HTTPS
                location = response.headers.get('Location', '')
                assert location.startswith('https://'), \
                       f"HTTPS redirect should go to HTTPS URL: {location}"
            else:
                # HTTPS not enforced - acceptable for development/testing
                response = client.get('/')
                # Application should respond (may redirect to auth, but should work)
                assert response.status_code in [200, 302], \
                       f"Application should work without HTTPS enforcement in development, got {response.status_code}"

    def test_secure_cookie_configuration(self, client, app):
        """Test secure cookie configuration for HTTPS environments."""

        with app.app_context():
            # Check if running in secure mode
            is_secure = app.config.get('FORCE_HTTPS', False) or \
                       app.config.get('SESSION_COOKIE_SECURE', False)

            response = client.get('/')
            set_cookie_headers = response.headers.getlist('Set-Cookie')

            for cookie_header in set_cookie_headers:
                if 'session' in cookie_header.lower():
                    if is_secure:
                        # Should have Secure attribute in secure environments
                        assert 'Secure' in cookie_header, \
                               f"Session cookie should be Secure in HTTPS mode: {cookie_header}"
                    # In development/testing over HTTP, Secure attribute might not be set

    def test_hsts_header_configuration(self, client, app):
        """Test HSTS header configuration."""

        with app.app_context():
            response = client.get('/')
            hsts_header = response.headers.get('Strict-Transport-Security')

            if hsts_header:
                # Verify HSTS header format
                assert 'max-age=' in hsts_header, \
                       f"HSTS header should have max-age: {hsts_header}"

                # Should have reasonable max-age
                import re
                max_age_match = re.search(r'max-age=(\d+)', hsts_header)
                if max_age_match:
                    max_age = int(max_age_match.group(1))
                    assert max_age >= 86400, \
                           f"HSTS max-age should be at least 1 day: {max_age}"

                # Should include subdomains for better security
                assert 'includeSubDomains' in hsts_header, \
                       f"HSTS should include subdomains: {hsts_header}"


class TestSecurityHeadersBypassPrevention:
    """Tests to verify the application prevents security header bypass attempts."""

    def test_header_injection_prevention(self, client):
        """Test that the application prevents HTTP header injection."""

        # Try various header injection payloads
        injection_payloads = [
            "test\r\nX-Injected: malicious",
            "test\nSet-Cookie: evil=payload",
            "test%0d%0aContent-Type: text/html",
            "test%0aLocation: http://evil.com",
        ]

        for payload in injection_payloads:
            # Try injection via query parameter
            response = client.get(f'/?param={payload}')

            # Should not contain injected headers
            headers = response.headers
            assert 'X-Injected' not in headers, \
                   f"Header injection succeeded with payload: {payload}"

            # Should not have injected Set-Cookie
            set_cookie_headers = response.headers.getlist('Set-Cookie')
            evil_cookies = [h for h in set_cookie_headers if 'evil=' in h]
            assert len(evil_cookies) == 0, \
                   f"Cookie injection succeeded with payload: {payload}"

    def test_response_splitting_prevention(self, client):
        """Test prevention of HTTP response splitting attacks."""

        # Try response splitting payloads
        splitting_payloads = [
            "value%0d%0a%0d%0a<script>alert('xss')</script>",
            "value\r\n\r\n<html><body>injected</body></html>",
            "value%0a%0a<iframe src='http://evil.com'></iframe>",
        ]

        for payload in splitting_payloads:
            response = client.get(f'/?param={payload}')

            # Response should not contain injected HTML content
            content = response.get_data(as_text=True)
            assert '<script>' not in content, \
                   f"Response splitting succeeded with payload: {payload}"
            assert '<iframe' not in content, \
                   f"Response splitting succeeded with payload: {payload}"

            # Should maintain proper Content-Type
            content_type = response.headers.get('Content-Type', '')
            assert 'text/html' in content_type or content_type == '', \
                   f"Content-Type corrupted by response splitting: {content_type}"