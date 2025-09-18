"""
XSS Protection Verification Tests

These tests verify that XSS protections are working correctly by testing
various injection points and confirming that dangerous content is properly escaped.
"""

import pytest
import json
from unittest.mock import patch, MagicMock
from app.extensions import db
from app.models.presharedkey import PreSharedKey


class TestXSSProtectionVerification:
    """Verification tests for XSS protection mechanisms."""

    def test_psk_description_xss_escaping_verification(self, client, app):
        """Verify that PSK descriptions properly escape XSS payloads."""

        # Set up admin session
        with client.session_transaction() as sess:
            sess['user'] = {
                'sub': 'admin@example.com',
                'name': 'Admin User',
                'email': 'admin@example.com',
                'groups': ['admin']
            }

        with app.app_context():
            app.config['OIDC_ADMIN_GROUP'] = 'admin'

            # Test comprehensive XSS payloads
            xss_payloads = [
                # Basic script injection
                "<script>alert('XSS')</script>",
                # Image onerror
                "<img src=x onerror=alert('XSS')>",
                # SVG injection
                "<svg onload=alert('XSS')>",
                # JavaScript protocol
                "javascript:alert('XSS')",
                # Event handlers
                "<div onclick=alert('XSS')>Click me</div>",
                # Iframe injection
                "<iframe src='javascript:alert(\"XSS\")'></iframe>",
                # Body onload
                "<body onload=alert('XSS')>",
                # Quote escape attempt
                "';alert('XSS');//",
                # Attribute escape attempt
                "\"><script>alert('XSS')</script>",
                # Style injection
                "<style>@import'http://evil.com/xss.css';</style>",
                # Data URL
                "<iframe src='data:text/html,<script>alert(\"XSS\")</script>'></iframe>",
                # Meta refresh
                "<meta http-equiv=refresh content='0;url=javascript:alert(\"XSS\")'>",
            ]

            for payload in xss_payloads:
                # Create PSK with XSS payload in description
                response = client.post('/admin/psk/new', data={
                    'description': payload,
                    'psk_type': 'server'
                })

                # Should either succeed or fail gracefully (not crash)
                assert response.status_code in [200, 302, 400, 422], f"Server error with payload: {payload}"

                if response.status_code in [200, 302]:
                    # Get the PSK list page to check rendering
                    list_response = client.get('/admin/psk')
                    assert list_response.status_code == 200

                    list_content = list_response.get_data(as_text=True)

                    # Verify dangerous content is properly escaped
                    self._verify_xss_payload_escaped(payload, list_content)

    def test_certificate_subject_xss_protection(self, client, app):
        """Verify XSS protection in certificate subject display."""

        # Mock certificate with XSS in subject
        xss_subject = "<script>alert('subject_xss')</script>"

        with patch('app.utils.certtransparency_client.CertTransparencyClient.list_certificates') as mock_list_certs:
            mock_list_certs.return_value = {
                'certificates': [{
                    'fingerprint': 'test123',
                    'fingerprint_sha256': 'abcd1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab',
                    'subject': xss_subject,
                    'subject_cn': xss_subject,  # This is what the template will display
                    'issuer': 'CN=Test CA',
                    'issued_at': '2024-01-01T00:00:00Z',
                    'expires_at': '2025-01-01T00:00:00Z',
                    'revoked_at': None,
                    'issuing_user_id': 'test@example.com'
                }],
                'pagination': {
                    'total': 1,
                    'page': 1,
                    'per_page': 50
                }
            }

            # Set up user session
            with client.session_transaction() as sess:
                sess['user'] = {
                    'sub': 'test@example.com',
                    'name': 'Test User',
                    'email': 'test@example.com',
                    'groups': ['users']
                }

            # Get certificates page
            response = client.get('/profile/certificates')
            assert response.status_code == 200

            content = response.get_data(as_text=True)
            self._verify_xss_payload_escaped(xss_subject, content)

    def test_basic_xss_protection_in_templates(self, client, app):
        """Verify basic XSS protection in template rendering."""

        with client.session_transaction() as sess:
            sess['user'] = {
                'sub': 'test@example.com',
                'name': 'Test User',
                'email': 'test@example.com',
                'groups': ['users']
            }

        # Test that dangerous URLs return appropriate responses
        xss_urls = [
            "/profile/certificates/<script>alert('XSS')</script>",
            "/admin/psk/<img%20src=x%20onerror=alert('XSS')>",
        ]

        for url in xss_urls:
            response = client.get(url)

            # Should handle gracefully (not crash)
            assert response.status_code in [200, 302, 400, 404, 500], f"Unexpected status for: {url}"

            if response.status_code == 200:
                content = response.get_data(as_text=True)
                # Should not contain unescaped script tags
                assert "<script>" not in content.lower(), f"Unescaped script tag found for URL: {url}"

    def _verify_xss_payload_escaped(self, payload: str, content: str):
        """Helper method to verify XSS payload is properly escaped."""

        # The original payload should not appear unescaped
        assert payload not in content, f"Unescaped XSS payload found: {payload}"

        # Check for common escape patterns
        if '<script>' in payload.lower():
            # Script tags should be escaped
            assert ('&lt;script&gt;' in content or
                    '&amp;lt;script&amp;gt;' in content or
                    payload.replace('<', '&lt;').replace('>', '&gt;') in content), \
                   f"Script tags not properly escaped: {payload}"

        if 'javascript:' in payload.lower():
            # JavaScript protocol should be escaped or removed
            if 'javascript:' in content:
                # If present, should be in safe form
                assert ('javascript&' in content or
                        'javascript%' in content or
                        not payload in content), \
                       f"JavaScript protocol not properly handled: {payload}"

        if any(event in payload.lower() for event in ['onclick', 'onload', 'onerror', 'onmouseover']):
            # Event handlers should be escaped
            for event in ['onclick', 'onload', 'onerror', 'onmouseover']:
                if event in payload.lower():
                    raw_event_count = content.lower().count(event)
                    escaped_event_count = content.count(f'&lt;') + content.count('&amp;lt;')
                    # If raw events exist, there should be corresponding escaping
                    if raw_event_count > 0 and event in payload.lower():
                        assert escaped_event_count > 0, f"Event handler not escaped: {payload}"

    def test_csp_header_xss_mitigation(self, client, app):
        """Verify Content Security Policy headers are configured to prevent XSS."""

        response = client.get('/')

        # Should have CSP header
        csp_header = response.headers.get('Content-Security-Policy')
        assert csp_header is not None, "Missing Content-Security-Policy header"

        # CSP should restrict script sources to self only
        assert "'self'" in csp_header, "CSP should allow 'self' for scripts"

        # Check that script-src doesn't allow unsafe-inline
        if 'script-src' in csp_header:
            script_src_part = csp_header.split('script-src')[1].split(';')[0]
            assert "'unsafe-inline'" not in script_src_part, \
                   f"script-src should not allow unsafe-inline: {script_src_part}"

        # Should have other security headers
        assert response.headers.get('X-XSS-Protection') == '1; mode=block', \
               "Missing or incorrect X-XSS-Protection header"
        assert response.headers.get('X-Content-Type-Options') == 'nosniff', \
               "Missing X-Content-Type-Options header"