"""
Tests specifically targeting missing coverage in user agent detection.
"""

import pytest
from app.utils.user_agent_detection import parse_user_agent, format_user_agent_summary


class TestUserAgentCoverage:
    """Tests for missing code coverage lines."""

    def test_ios_version_with_three_parts(self):
        """Test iOS version parsing with three version parts (line 93)."""
        user_agent = "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6_1 like Mac OS X) AppleWebKit/605.1.15"
        result = parse_user_agent(user_agent)

        assert result['os'] == 'iOS'
        assert result['os_version'] == '14.6.1'  # This hits line 93

    def test_format_user_agent_summary_complete(self):
        """Test format_user_agent_summary function (lines 182-193)."""
        # Test with full data
        parsed_data = {
            'os': 'Windows',
            'os_version': '10',
            'browser': 'Chrome',
            'browser_version': '91.0.4472.124',
            'is_mobile': False
        }
        result = format_user_agent_summary(parsed_data)
        assert result == "Windows 10 - Chrome 91"

        # Test mobile device
        parsed_data['is_mobile'] = True
        result = format_user_agent_summary(parsed_data)
        assert result == "Windows 10 - Chrome 91 (Mobile)"

        # Test without versions
        parsed_data = {
            'os': 'Linux',
            'os_version': '',
            'browser': 'Firefox',
            'browser_version': '',
            'is_mobile': False
        }
        result = format_user_agent_summary(parsed_data)
        assert result == "Linux - Firefox"

        # Test browser version without dots
        parsed_data = {
            'os': 'macOS',
            'os_version': '11',
            'browser': 'Safari',
            'browser_version': '14',  # No dots
            'is_mobile': False
        }
        result = format_user_agent_summary(parsed_data)
        assert result == "macOS 11 - Safari 14"

    def test_mac_version_parsing(self):
        """Test macOS version parsing edge cases."""
        # Test version without third part
        user_agent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15) AppleWebKit/537.36"
        result = parse_user_agent(user_agent)
        assert result['os'] == 'macOS'
        assert result['os_version'] == '10.15'

        # Test with all three parts
        user_agent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"
        result = parse_user_agent(user_agent)
        assert result['os'] == 'macOS'
        assert result['os_version'] == '10.15.7'

    def test_windows_version_mapping(self):
        """Test Windows NT version mapping."""
        # Test Windows 10
        user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        result = parse_user_agent(user_agent)
        assert result['os'] == 'Windows'
        assert result['os_version'] == '10'

        # Test Windows 8.1
        user_agent = "Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36"
        result = parse_user_agent(user_agent)
        assert result['os'] == 'Windows'
        assert result['os_version'] == '8.1'

        # Test Windows 7
        user_agent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36"
        result = parse_user_agent(user_agent)
        assert result['os'] == 'Windows'
        assert result['os_version'] == '7'

        # Test unknown NT version
        user_agent = "Mozilla/5.0 (Windows NT 99.0; Win64; x64) AppleWebKit/537.36"
        result = parse_user_agent(user_agent)
        assert result['os'] == 'Windows'
        assert result['os_version'] == '99.0'  # Falls back to raw NT version

    def test_linux_distribution_detection(self):
        """Test Linux distribution detection."""
        # Test Ubuntu
        user_agent = "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0"
        result = parse_user_agent(user_agent)
        assert result['os'] == 'Linux'
        assert result['os_version'] == 'Ubuntu'

        # Test CentOS
        user_agent = "Mozilla/5.0 (X11; CentOS; Linux x86_64) AppleWebKit/537.36"
        result = parse_user_agent(user_agent)
        assert result['os'] == 'Linux'
        assert result['os_version'] == 'CentOS'

        # Test Fedora
        user_agent = "Mozilla/5.0 (X11; Fedora; Linux x86_64) AppleWebKit/537.36"
        result = parse_user_agent(user_agent)
        assert result['os'] == 'Linux'
        assert result['os_version'] == 'Fedora'

        # Test Debian
        user_agent = "Mozilla/5.0 (X11; Debian; Linux x86_64) AppleWebKit/537.36"
        result = parse_user_agent(user_agent)
        assert result['os'] == 'Linux'
        assert result['os_version'] == 'Debian'

    def test_browser_version_detection_edge_cases(self):
        """Test browser version detection edge cases."""
        # Test Edge
        user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/96.0.4664.110 Safari/537.36 Edg/96.0.1054.62"
        result = parse_user_agent(user_agent)
        assert result['browser'] == 'Edge'
        assert result['browser_version'] == '96.0.1054.62'

        # Test Chrome (should not be Edge)
        user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/96.0.4664.110 Safari/537.36"
        result = parse_user_agent(user_agent)
        assert result['browser'] == 'Chrome'
        assert result['browser_version'] == '96.0.4664.110'

        # Test Firefox
        user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0"
        result = parse_user_agent(user_agent)
        assert result['browser'] == 'Firefox'
        assert result['browser_version'] == '89.0'

        # Test Safari (not Chrome)
        user_agent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Version/14.1.1 Safari/537.36"
        result = parse_user_agent(user_agent)
        assert result['browser'] == 'Safari'
        assert result['browser_version'] == '14.1.1'