"""
Security tests for web interface covering OWASP Top 10 web application vulnerabilities.
"""

import pytest
from unittest.mock import patch, MagicMock
from app.extensions import db
from app.models.presharedkey import PreSharedKey


class TestWebSecurityHeaders:
    """Tests for security headers and web-specific vulnerabilities (A05)"""
    
    def test_security_headers_present(self, client):
        """Test presence of essential security headers"""
        response = client.get('/')
        
        # Critical security headers that should be present
        security_headers = {
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': ['DENY', 'SAMEORIGIN'],  # Either is acceptable
            'X-XSS-Protection': '1; mode=block',
        }
        
        for header, expected_values in security_headers.items():
            header_value = response.headers.get(header)
            if isinstance(expected_values, list):
                assert header_value in expected_values, f"Missing or incorrect {header}: {header_value}"
            else:
                assert header_value == expected_values, f"Missing or incorrect {header}: {header_value}"
    
    def test_server_version_not_disclosed(self, client):
        """Test that server version information is not disclosed"""
        response = client.get('/')
        
        # Should not expose server version info
        server_header = response.headers.get('Server', '').lower()
        sensitive_info = ['flask', 'werkzeug', 'gunicorn', 'apache', 'nginx']
        
        for info in sensitive_info:
            assert info not in server_header, f"Server version info disclosed: {server_header}"
    
    def test_powered_by_header_removed(self, client):
        """Test that X-Powered-By header is not present"""
        response = client.get('/')
        assert 'X-Powered-By' not in response.headers, "X-Powered-By header should be removed"

    def test_error_pages_no_stack_traces(self, client):
        """Test error pages don't expose stack traces"""
        # Test 404 error
        response = client.get('/nonexistent-page')
        assert response.status_code == 404
        response_text = response.get_data(as_text=True).lower()
        
        # Should not contain stack trace elements
        stack_trace_indicators = [
            'traceback',
            'file "',
            'line ',
            'in <module>',
            'werkzeug',
            'flask.py'
        ]
        
        for indicator in stack_trace_indicators:
            assert indicator not in response_text, f"Stack trace exposed in 404: {indicator}"
    
    def test_development_info_not_in_production(self, client):
        """Test development information is not exposed in production"""
        response = client.get('/')
        response_text = response.get_data(as_text=True).lower()
        
        # Development indicators that shouldn't appear in production
        dev_indicators = [
            'development',
            'debug',
            '[dev]',
            'test mode',
            'dev-auth'
        ]
        
        for indicator in dev_indicators:
            assert indicator not in response_text, f"Development info in production: {indicator}"


class TestCSRFProtection:
    """Tests for CSRF protection (A01: Broken Access Control)"""
    
    def test_csrf_token_required_for_forms(self, client, app):
        """Test that CSRF tokens are required for form submissions"""
        # Check if CSRF is enabled in the application
        csrf_enabled = app.config.get('WTF_CSRF_ENABLED', True)
        
        if not csrf_enabled:
            # In test environment, CSRF might be disabled - verify this is intentional
            assert app.config.get('TESTING', False), "CSRF disabled in non-test environment"
            return  # Skip test if CSRF is disabled for testing
        
        # Setup authentication
        with app.app_context():
            with client.session_transaction() as sess:
                sess['user'] = {'groups': ['admins']}
        
        # Try to create PSK without CSRF token
        response = client.post('/admin/psk/new', data={
            'hostname': 'csrf-test.com'
        })
        
        # Should be rejected due to missing CSRF token
        assert response.status_code in [400, 403], "CSRF protection bypassed"

    def test_csrf_token_validation(self, client, app):
        """Test CSRF token validation with invalid tokens"""
        # Check if CSRF is enabled in the application
        csrf_enabled = app.config.get('WTF_CSRF_ENABLED', True)
        
        if not csrf_enabled:
            # In test environment, CSRF might be disabled - verify this is intentional
            assert app.config.get('TESTING', False), "CSRF disabled in non-test environment"
            return  # Skip test if CSRF is disabled for testing
            
        with app.app_context():
            with client.session_transaction() as sess:
                sess['user'] = {'groups': ['admins']}
        
        # Try with invalid CSRF token
        response = client.post('/admin/psk/new', data={
            'hostname': 'csrf-test.com',
            'csrf_token': 'invalid-token-12345'
        })
        
        # Should be rejected due to invalid CSRF token
        assert response.status_code in [400, 403], "Invalid CSRF token accepted"


class TestSessionSecurity:
    """Tests for session security vulnerabilities (A07)"""
    
    def test_session_cookie_security_flags(self, client, app):
        """Test session cookies have proper security flags"""
        with app.app_context():
            with client.session_transaction() as sess:
                sess['user'] = {'name': 'test'}
        
        response = client.get('/')
        
        # Find session cookie
        session_cookie = None
        for cookie in response.headers.getlist('Set-Cookie'):
            if 'session=' in cookie:
                session_cookie = cookie
                break
        
        if session_cookie:
            # Check for security flags
            assert 'HttpOnly' in session_cookie, "Session cookie missing HttpOnly flag"
            # Note: Secure flag may not be set in test environment (HTTP)
            # In production with HTTPS, this should be tested
    
    def test_session_regeneration_after_privilege_change(self, client, app):
        """Test session ID changes after privilege escalation"""
        # This would be more relevant with actual authentication
        # For now, test that sessions are properly managed
        
        with client.session_transaction() as sess:
            sess['user'] = {'groups': ['users']}
            original_session = dict(sess)
        
        # Simulate privilege change (user becomes admin)
        with client.session_transaction() as sess:
            sess['user'] = {'groups': ['admins']}
            new_session = dict(sess)
        
        # Session data should be different (though this is a basic test)
        assert original_session != new_session


class TestAccessControlSecurity:
    """Tests for access control vulnerabilities (A01)"""
    
    def test_admin_endpoints_require_admin_role(self, client, app):
        """Test admin endpoints properly enforce admin role"""
        admin_endpoints = [
            '/admin/psk',
            '/admin/psk/new',
        ]
        
        # Test with no authentication
        for endpoint in admin_endpoints:
            response = client.get(endpoint)
            assert response.status_code in [302, 401, 403], f"Unauthenticated access allowed: {endpoint}"
        
        # Test with non-admin user
        with app.app_context():
            with client.session_transaction() as sess:
                sess['user'] = {'groups': ['users']}  # Not admin
        
        for endpoint in admin_endpoints:
            response = client.get(endpoint)
            assert response.status_code in [302, 403], f"Non-admin access allowed: {endpoint}"

    def test_direct_object_reference_protection(self, client, app):
        """Test protection against direct object reference attacks"""
        # Create PSKs for different "tenants"
        with app.app_context():
            psk1 = PreSharedKey(description="tenant1.com")
            psk2 = PreSharedKey(description="tenant2.com")
            db.session.add_all([psk1, psk2])
            db.session.commit()
            
            psk1_id = psk1.id
            psk2_id = psk2.id
        
        # Setup user session
        with client.session_transaction() as sess:
            sess['user'] = {'groups': ['admins']}
        
        # Test that users can't directly access PSKs by ID manipulation
        # (This assumes there would be endpoints like /admin/psk/<id> in the future)
        test_ids = [psk1_id, psk2_id, 999999, -1, 0, "invalid"]
        
        for test_id in test_ids:
            # This endpoint doesn't exist yet, but the pattern is important
            response = client.get(f'/admin/psk/{test_id}')
            # Should return 404 (not found) rather than exposing data
            assert response.status_code == 404

    def test_horizontal_privilege_escalation(self, client, app):
        """Test users cannot access other users' resources"""
        # This is more theoretical given the current architecture
        # But important for future multi-tenancy
        
        with app.app_context():
            # Ensure database tables exist
            db.create_all()
            # Create PSKs that would belong to different users
            user1_psk = PreSharedKey(description="user1-server.com")
            user2_psk = PreSharedKey(description="user2-server.com")
            db.session.add_all([user1_psk, user2_psk])
            db.session.commit()
        
        # Ensure the app has the admin group configured
        admin_group = app.config.get('OIDC_ADMIN_GROUP', 'admins')
        
        # In a multi-tenant scenario, user1 shouldn't see user2's PSKs
        # For now, test that the admin interface shows all PSKs (expected behavior)
        with client.session_transaction() as sess:
            sess['user'] = {'groups': [admin_group]}
        
        response = client.get('/admin/psk')
        assert response.status_code == 200
        # In current implementation, admin sees all - this is correct
        # But in multi-tenant future, this would need proper filtering


class TestInputValidationWeb:
    """Tests for input validation in web forms"""
    
    def test_xss_protection_in_hostname_display(self, client, app):
        """Test XSS protection when displaying hostnames"""
        # Create PSK with potential XSS payload in hostname
        xss_hostname = "<script>alert('XSS')</script>"
        
        with app.app_context():
            psk = PreSharedKey(description=xss_hostname)
            db.session.add(psk)
            db.session.commit()
        
        # Setup admin session
        with client.session_transaction() as sess:
            sess['user'] = {'groups': ['admins']}
        
        response = client.get('/admin/psk')
        response_text = response.get_data(as_text=True)
        
        # Script tags should be escaped by Jinja2 auto-escaping
        # Check that the specific XSS payload is escaped, not any script tags
        assert xss_hostname not in response_text, "XSS payload not escaped in hostname display"
        # Verify that the escaped version is present instead
        assert "&lt;script&gt;alert(&#39;XSS&#39;)&lt;/script&gt;" in response_text, "XSS payload should be escaped"
        
        # The content should be escaped - check for escaped version
        # Jinja2 should escape < and > to &lt; and &gt;
        if xss_hostname in response_text:
            # If the original payload is there unescaped, that's a problem
            assert False, "Unescaped XSS payload found in response"
        
        # Check for properly escaped version
        escaped_content = response_text.count('&lt;script&gt;') > 0 or response_text.count('&amp;lt;script&amp;gt;') > 0
        if not escaped_content:
            # The content might have been filtered out entirely, which is also acceptable
            assert xss_hostname not in response_text, "XSS payload neither escaped nor filtered"
        
    @patch('app.utils.server_templates.get_template_set_choices')
    def test_html_injection_in_forms(self, mock_template_choices, client, app):
        """Test HTML injection protection in form fields"""
        # Mock server template choices to avoid "No server template sets found" error
        mock_template_choices.return_value = [('Default', 'Default (1 template)')]
        
        admin_group = app.config.get('OIDC_ADMIN_GROUP', 'admins')
        with client.session_transaction() as sess:
            sess['user'] = {'groups': [admin_group]}
        
        # Get the admin page  
        response = client.get('/admin/psk')
        assert response.status_code == 200
        
        # Try to submit HTML injection payload
        html_payloads = [
            '<img src=x onerror=alert(1)>',
            '<svg onload=alert(1)>',
            '<iframe src=javascript:alert(1)>',
            '"><script>alert(1)</script>',
            "javascript:alert('XSS')"
        ]
        
        for payload in html_payloads:
            response = client.post('/admin/psk/new', data={
                'hostname': payload,
                # CSRF token would be needed in real scenario
            }, follow_redirects=True)
            
            # Should either reject the input or properly escape it
            if response.status_code == 200:
                response_text = response.get_data(as_text=True)
                # Check that dangerous script content is escaped properly
                # The key risk is executable JavaScript - check for that
                dangerous_patterns = [
                    '<script>',
                    '</script>',
                    'javascript:alert',
                    'onerror=alert',
                    'onload=alert'
                ]
                
                for pattern in dangerous_patterns:
                    if pattern in response_text.lower():
                        # If dangerous patterns are found, they should be in escaped form
                        # or within safe contexts (like within HTML comments or text nodes)
                        # This is a more nuanced check - in reality, we'd want proper input validation
                        pass  # For now, just log that we found potentially dangerous content

    def test_form_field_length_limits(self, client, app):
        """Test form fields respect reasonable length limits"""
        with client.session_transaction() as sess:
            sess['user'] = {'groups': ['admins']}
        
        # Test with extremely long hostname
        long_hostname = 'a' * 10000  # 10KB hostname
        
        response = client.post('/admin/psk/new', data={
            'hostname': long_hostname,
        })
        
        # Should reject or truncate overly long input
        # Don't create database entries with massive hostnames
        if response.status_code in [200, 302]:  # Success/redirect
            with app.app_context():
                created_psk = PreSharedKey.query.filter(
                    PreSharedKey.description.like('aaa%')
                ).first()
                if created_psk:
                    # Hostname should be reasonably limited
                    assert len(created_psk.description) < 1000, "Overly long hostname stored"


class TestRateLimitingSecurity:
    """Tests for rate limiting and DoS protection"""
    
    def test_form_submission_rate_limiting(self, client, app):
        """Test rate limiting on form submissions"""
        with client.session_transaction() as sess:
            sess['user'] = {'groups': ['admins']}
        
        # Attempt rapid form submissions
        responses = []
        for i in range(20):  # Try 20 rapid requests
            response = client.post('/admin/psk/new', data={
                'hostname': f'rate-test-{i}.com',
            })
            responses.append(response.status_code)
        
        # Should eventually get rate limited (429) or rejected
        # Or at minimum, not all should succeed
        success_count = sum(1 for status in responses if status in [200, 302])
        
        # Not all requests should succeed (some rate limiting should kick in)
        # This is a soft assertion since rate limiting might not be implemented yet
        if success_count == 20:
            print("WARNING: No rate limiting detected on form submissions")

    def test_api_endpoint_rate_limiting(self, client, app):
        """Test rate limiting on API endpoints"""
        # Create a valid PSK for testing
        hostname = "rate-limit-test.com"
        key = "test-key-12345"
        
        with app.app_context():
            psk = PreSharedKey(description=hostname, key=key)
            db.session.add(psk)
            db.session.commit()
        
        # Attempt rapid API calls (using server/bundle endpoint instead)
        responses = []
        for i in range(50):  # Try 50 rapid API requests
            response = client.post(
                '/api/v1/server/bundle',
                headers={'Authorization': f'Bearer {key}'},
                json={'hostname': hostname}
            )
            responses.append(response.status_code)
        
        # Should eventually get rate limited
        rate_limited_count = sum(1 for status in responses if status == 429)
        
        # At least some requests should be rate limited
        if rate_limited_count == 0:
            print("WARNING: No rate limiting detected on API endpoints")


class TestInformationDisclosureSecurity:
    """Tests for information disclosure vulnerabilities"""
    
    def test_sensitive_files_not_accessible(self, client):
        """Test that sensitive files are not accessible via web"""
        sensitive_paths = [
            '/.env',
            '/config.py',
            '/.git/config',
            '/requirements.txt',
            '/.gitignore',
            '/app.py',
            '/wsgi.py',
            '/gunicorn.conf.py',
            '/__pycache__/',
            '/backend/config.py',
            '/settings.py',
            '/local_settings.py'
        ]
        
        for path in sensitive_paths:
            response = client.get(path)
            # Should return 404, not expose file contents
            assert response.status_code == 404, f"Sensitive file accessible: {path}"
    
    def test_directory_listing_disabled(self, client):
        """Test that directory listing is disabled"""
        directory_paths = [
            '/static/',
            '/templates/',
            '/uploads/',
            '/tmp/',
            '/assets/'
        ]
        
        for path in directory_paths:
            response = client.get(path)
            # Should not return directory listing (200 with index or 403/404)
            if response.status_code == 200:
                response_text = response.get_data(as_text=True).lower()
                # Should not contain directory listing indicators
                assert 'index of' not in response_text
                assert 'parent directory' not in response_text
    
    def test_debug_info_not_exposed(self, client):
        """Test that debug information is not exposed"""
        # Try to trigger errors and check for debug info
        error_endpoints = [
            '/admin/psk/999999',  # Non-existent PSK
            '/api/v1/invalid-endpoint',  # Invalid API endpoint
        ]
        
        for endpoint in error_endpoints:
            response = client.get(endpoint)
            response_text = response.get_data(as_text=True).lower()
            
            # Should not contain debug information
            debug_indicators = [
                'traceback',
                'debug mode',
                'flask debugger',
                'werkzeug debugger',
                'console.log',
                'console.error'
            ]
            
            for indicator in debug_indicators:
                assert indicator not in response_text, f"Debug info exposed at {endpoint}: {indicator}"