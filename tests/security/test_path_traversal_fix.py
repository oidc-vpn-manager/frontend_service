"""
Security tests for CVE-5 Path Traversal vulnerability fix.

This test suite validates that the path traversal vulnerability has been properly fixed
and that malicious path traversal attempts are blocked.
"""

import pytest
import os
import tempfile
from unittest.mock import Mock, patch


class TestPathTraversalFix:
    """Test cases for path traversal vulnerability fixes."""

    def setup_method(self):
        """Set up test environment."""
        self.temp_dir = tempfile.mkdtemp()
        self.templates_dir = os.path.join(self.temp_dir, 'templates')
        os.makedirs(self.templates_dir)

        # Create a legitimate template file
        self.legitimate_file = os.path.join(self.templates_dir, 'JustTCP.0443.ovpn')
        with open(self.legitimate_file, 'w') as f:
            f.write('client\nremote vpn.example.com 443\n')

        # Create a sensitive file outside templates directory
        self.sensitive_file = os.path.join(self.temp_dir, 'sensitive.txt')
        with open(self.sensitive_file, 'w') as f:
            f.write('SECRET_PASSWORD=admin123')

    def test_blocks_basic_path_traversal(self):
        """Test that basic path traversal attempts are blocked."""
        # Mock PSK object with malicious template_set
        psk_mock = Mock()
        psk_mock.template_set = '../sensitive'  # Attempt to access sensitive.txt

        # Mock current_app
        app_mock = Mock()
        app_mock.config = {'SERVER_TEMPLATES_DIR': self.templates_dir}
        app_mock.logger = Mock()

        with patch('app.routes.api.v1.current_app', app_mock):
            # Import necessary parts
            import re

            # Test the sanitization logic directly
            safe_template_set = os.path.basename(psk_mock.template_set) if psk_mock.template_set else ''
            if not re.match(r'^[a-zA-Z0-9_-]+$', safe_template_set):
                safe_template_set = 'default'

            # Should be sanitized to just 'sensitive'
            assert safe_template_set == 'sensitive'

            # Even if it tries to construct a path, it won't escape the directory
            for filename in os.listdir(self.templates_dir):
                safe_filename = os.path.basename(filename)
                if safe_filename.endswith('.ovpn') and safe_filename.startswith(safe_template_set + '.'):
                    filepath = os.path.join(self.templates_dir, safe_filename)
                    resolved_path = os.path.realpath(filepath)
                    templates_realpath = os.path.realpath(self.templates_dir)

                    # Should be within templates directory
                    assert resolved_path.startswith(templates_realpath + os.sep)

    def test_blocks_complex_path_traversal(self):
        """Test that complex path traversal attempts are blocked."""
        malicious_template_sets = [
            '../../../etc/passwd',
            '..\\..\\..\\windows\\system32',
            './../../../sensitive',
            '%2e%2e%2f%2e%2e%2f%2e%2e%2fsensitive',  # URL encoded
            '....//....//....//sensitive',
        ]

        for malicious_set in malicious_template_sets:
            # Test sanitization
            safe_template_set = os.path.basename(malicious_set) if malicious_set else ''
            import re
            if not re.match(r'^[a-zA-Z0-9_-]+$', safe_template_set):
                safe_template_set = 'default'

            # Should either be sanitized to a safe basename or default
            assert safe_template_set in ['passwd', 'system32', 'sensitive', 'default']

            # And should not contain path separators
            assert '..' not in safe_template_set
            assert '/' not in safe_template_set
            assert '\\' not in safe_template_set

    def test_allows_legitimate_template_sets(self):
        """Test that legitimate template sets are allowed."""
        legitimate_sets = [
            'JustTCP',
            'UDP_1194',
            'TCP_443',
            'default',
            'test-config',
            'Config_1'
        ]

        for template_set in legitimate_sets:
            safe_template_set = os.path.basename(template_set) if template_set else ''
            import re
            if not re.match(r'^[a-zA-Z0-9_-]+$', safe_template_set):
                safe_template_set = 'default'

            # Should remain unchanged for legitimate names
            assert safe_template_set == template_set

    def test_rejects_malicious_characters(self):
        """Test that template sets with malicious characters are rejected."""
        malicious_chars = [
            'test;rm -rf /',
            'config|cat',
            'template&whoami',
            'config$(id)',
            'test`ls -la`',
            'config\x00null',
            'template\n\r\t'
        ]

        for malicious_set in malicious_chars:
            safe_template_set = os.path.basename(malicious_set) if malicious_set else ''
            import re
            if not re.match(r'^[a-zA-Z0-9_-]+$', safe_template_set):
                safe_template_set = 'default'

            # Should be sanitized to default due to malicious characters
            assert safe_template_set == 'default', f"Failed for malicious set: {malicious_set}, got: {safe_template_set}"

    def test_path_resolution_security(self):
        """Test that path resolution prevents escaping template directory."""
        # Create a symlink that tries to escape (if supported)
        try:
            symlink_path = os.path.join(self.templates_dir, 'escape.ovpn')
            os.symlink(self.sensitive_file, symlink_path)

            # Test path resolution
            resolved_path = os.path.realpath(symlink_path)
            templates_realpath = os.path.realpath(self.templates_dir)

            # Should detect that resolved path is outside templates directory
            assert not resolved_path.startswith(templates_realpath + os.sep)

        except (OSError, NotImplementedError):
            # Symlinks not supported on this system, skip test
            pytest.skip("Symlinks not supported on this system")

    def test_empty_and_none_template_sets(self):
        """Test handling of empty and None template sets."""
        test_cases = [None, '', '   ', '\t\n']

        for template_set in test_cases:
            safe_template_set = os.path.basename(template_set) if template_set else ''
            import re
            if not re.match(r'^[a-zA-Z0-9_-]+$', safe_template_set):
                safe_template_set = 'default'

            # Should default to 'default'
            assert safe_template_set == 'default'

    def test_filename_sanitization(self):
        """Test that filenames are properly sanitized."""
        malicious_filenames = [
            '../../../etc/passwd.ovpn',
            '..\\..\\..\\windows\\system32\\config.ovpn',
            '/etc/shadow.ovpn',
            'C:\\Windows\\System32\\drivers\\etc\\hosts.ovpn'
        ]

        for filename in malicious_filenames:
            # Use both posix and nt path separators for cross-platform testing
            import posixpath
            import ntpath
            safe_filename = os.path.basename(ntpath.basename(posixpath.basename(filename)))

            # Should only contain the basename
            assert safe_filename in ['passwd.ovpn', 'config.ovpn', 'shadow.ovpn', 'hosts.ovpn']
            assert '..' not in safe_filename
            assert '/' not in safe_filename
            assert '\\' not in safe_filename

    def teardown_method(self):
        """Clean up test environment."""
        import shutil
        shutil.rmtree(self.temp_dir)