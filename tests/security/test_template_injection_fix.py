"""
Security tests for CVE-6 Template Injection RCE vulnerability fix.

This test suite validates that the template injection vulnerability has been properly fixed
and that malicious template injection attempts are blocked.
"""

import pytest
import jinja2
from unittest.mock import Mock
from app.utils.render_config_template import render_config_template


class TestTemplateInjectionFix:
    """Test cases for template injection vulnerability fixes."""

    def test_safe_template_rendering(self):
        """Test that normal template rendering still works."""
        app_mock = Mock()
        app_mock.logger = Mock()

        template = "Hello {{ name }}, your cert is {{ cert_type }}"
        context = {
            'name': 'John Doe',
            'cert_type': 'client'
        }

        result = render_config_template(app_mock, template, **context)
        assert "Hello John Doe, your cert is client" in result

    def test_blocks_template_injection_rce_attempt(self):
        """Test that RCE attempts through template injection are blocked."""
        app_mock = Mock()
        app_mock.logger = Mock()

        template = "Config for {{ description }}"

        # This is the actual attack pattern that was possible before the fix
        malicious_description = "{{config.__class__.__init__.__globals__['os'].system('rm -rf /')}}"

        context = {
            'description': malicious_description
        }

        # Should not execute the malicious code, should escape it instead
        result = render_config_template(app_mock, template, **context)

        # The malicious content should be escaped, not executed
        # Check that the dangerous content has been HTML escaped
        assert "&#39;" in result  # Single quotes should be HTML escaped
        assert "__class__" in result  # Original text preserved but escaped
        # Verify no actual command execution occurred (result should contain template syntax, not execution results)
        assert "{{" in result and "}}" in result

    def test_blocks_config_access_attempt(self):
        """Test that attempts to access Flask config are blocked."""
        app_mock = Mock()
        app_mock.logger = Mock()

        template = "User: {{ user_info.name }}"

        # Attempt to access Flask config through template injection
        malicious_user_info = {
            'name': "{{config.SECRET_KEY}}"
        }

        context = {
            'user_info': malicious_user_info
        }

        result = render_config_template(app_mock, template, **context)

        # Should not expose config values - content should be escaped
        assert "{{" in result and "}}" in result  # Template syntax preserved
        assert "SECRET_KEY" in result  # Original text preserved but escaped

    def test_blocks_import_attempts(self):
        """Test that import attempts are blocked in templates."""
        app_mock = Mock()
        app_mock.logger = Mock()

        template = "Welcome {{ name }}"

        # Attempt to import modules
        malicious_name = "{{ __import__('os').system('echo pwned') }}"

        context = {
            'name': malicious_name
        }

        result = render_config_template(app_mock, template, **context)

        # Should be escaped, not executed
        assert "{{" in result and "}}" in result  # Template syntax preserved
        assert "__import__" in result  # Original text preserved but escaped
        # The word "pwned" should be HTML escaped if present
        if "pwned" in result:
            assert "&#39;" in result  # Indicates HTML escaping occurred

    def test_blocks_class_access_attempts(self):
        """Test that attempts to access Python classes are blocked."""
        app_mock = Mock()
        app_mock.logger = Mock()

        template = "Certificate for {{ common_name }}"

        # Attempt to access Python internals
        malicious_cn = "{{ ''.__class__.__mro__[1].__subclasses__() }}"

        context = {
            'common_name': malicious_cn
        }

        result = render_config_template(app_mock, template, **context)

        # Should be escaped
        assert "{{" in result and "}}" in result  # Template syntax preserved
        assert "__class__" in result  # Original text preserved but escaped
        assert "__mro__" in result  # Original text preserved but escaped

    def test_handles_nested_dict_injection(self):
        """Test that nested dictionary injection attempts are handled."""
        app_mock = Mock()
        app_mock.logger = Mock()

        template = "User: {{ userinfo.name }} Email: {{ userinfo.email }}"

        malicious_userinfo = {
            'name': "{{ config.SECRET_KEY }}",
            'email': "{{ __import__('os').getcwd() }}"
        }

        context = {
            'userinfo': malicious_userinfo
        }

        result = render_config_template(app_mock, template, **context)

        # Should be properly escaped
        assert "{{" in result and "}}" in result  # Template syntax preserved
        assert "SECRET_KEY" in result  # Original text preserved but escaped
        assert "__import__" in result  # Original text preserved but escaped

    def test_preserves_certificate_data(self):
        """Test that legitimate certificate data is preserved correctly."""
        app_mock = Mock()
        app_mock.logger = Mock()

        template = """
<cert>
{{ device_cert_pem }}
</cert>
<key>
{{ device_key_pem }}
</key>
"""

        # Legitimate certificate data (mock)
        cert_pem = "-----BEGIN CERTIFICATE-----\nMIICert...\n-----END CERTIFICATE-----"
        key_pem = "-----BEGIN PRIVATE KEY-----\nMIIKey...\n-----END PRIVATE KEY-----"

        context = {
            'device_cert_pem': cert_pem,
            'device_key_pem': key_pem
        }

        result = render_config_template(app_mock, template, **context)

        # Certificate data should be preserved
        assert "BEGIN CERTIFICATE" in result
        assert "BEGIN PRIVATE KEY" in result

    def test_security_error_handling(self):
        """Test that security errors are properly handled."""
        app_mock = Mock()
        app_mock.logger = Mock()

        # This template itself contains unsafe operations that should be caught
        unsafe_template = "{{ config.__class__ }}"

        context = {'name': 'test'}

        # Should raise ValueError due to security violation
        with pytest.raises(ValueError, match="Template contains unsafe operations"):
            render_config_template(app_mock, unsafe_template, **context)

    def test_strict_undefined_handling(self):
        """Test that undefined variables are handled strictly."""
        app_mock = Mock()
        app_mock.logger = Mock()

        template = "Hello {{ undefined_var }}"
        context = {'name': 'test'}

        # Should raise ValueError due to undefined variable
        with pytest.raises(ValueError, match="Template rendering failed"):
            render_config_template(app_mock, template, **context)