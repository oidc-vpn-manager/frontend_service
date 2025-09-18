"""
User-Agent detection and OS parsing utilities.

This module provides functionality to parse User-Agent strings and extract
operating system, browser, and device information from HTTP requests.
"""

import re
from typing import Dict, Optional


def detect_os_from_user_agent(user_agent: Optional[str]) -> str:
    """
    Simple OS detection from user agent string.
    
    Args:
        user_agent: The User-Agent header string
        
    Returns:
        String representing the detected OS: 'Windows', 'macOS', 'Linux', 'iOS', 'Android', 'Unknown'
    """
    if not user_agent:
        return 'Unknown'
    
    user_agent_lower = user_agent.lower()
    
    # Check for mobile platforms first (more specific)
    if 'iphone' in user_agent_lower or 'ipad' in user_agent_lower:
        return 'iOS'
    elif 'android' in user_agent_lower:
        return 'Android'
    
    # Check for desktop platforms
    elif 'windows' in user_agent_lower:
        return 'Windows'
    elif 'macintosh' in user_agent_lower or 'mac os x' in user_agent_lower:
        return 'macOS'
    elif 'linux' in user_agent_lower and 'android' not in user_agent_lower:
        return 'Linux'
    
    return 'Unknown'


def parse_user_agent(user_agent: Optional[str]) -> Dict[str, any]:
    """
    Comprehensive User-Agent parsing with detailed information extraction.
    
    Args:
        user_agent: The User-Agent header string
        
    Returns:
        Dictionary containing parsed information:
        - os: Operating system name
        - os_version: OS version if detectable
        - browser: Browser name
        - browser_version: Browser version if detectable
        - is_mobile: Boolean indicating if it's a mobile device
        - raw_user_agent: Original user agent string
    """
    if not user_agent:
        return {
            'os': 'Unknown',
            'os_version': '',
            'browser': 'Unknown', 
            'browser_version': '',
            'is_mobile': False,
            'raw_user_agent': user_agent or ''
        }
    
    result = {
        'os': 'Unknown',
        'os_version': '',
        'browser': 'Unknown',
        'browser_version': '',
        'is_mobile': False,
        'raw_user_agent': user_agent
    }
    
    user_agent_lower = user_agent.lower()
    
    # Detect mobile devices
    mobile_indicators = ['mobile', 'iphone', 'ipad', 'android', 'phone']
    result['is_mobile'] = any(indicator in user_agent_lower for indicator in mobile_indicators)
    
    # OS Detection with version parsing
    if 'iphone' in user_agent_lower or 'ipad' in user_agent_lower:
        result['os'] = 'iOS'
        # Extract iOS version: "iPhone OS 14_6" or "OS 14_6"
        ios_match = re.search(r'os (\d+)_(\d+)(?:_(\d+))?', user_agent_lower)
        if ios_match:
            version_parts = [ios_match.group(1), ios_match.group(2)]
            if ios_match.group(3):
                version_parts.append(ios_match.group(3))
            result['os_version'] = '.'.join(version_parts)
            
    elif 'android' in user_agent_lower:
        result['os'] = 'Android'
        # Extract Android version: "Android 11" or "Android 10; SM-G991B"
        android_match = re.search(r'android (\d+(?:\.\d+)?)', user_agent_lower)
        if android_match:
            result['os_version'] = android_match.group(1)
            
    elif 'windows nt' in user_agent_lower:
        result['os'] = 'Windows'
        # Extract Windows version: "Windows NT 10.0"
        windows_match = re.search(r'windows nt (\d+\.\d+)', user_agent_lower)
        if windows_match:
            nt_version = windows_match.group(1)
            # Map NT versions to user-friendly names
            version_map = {
                '10.0': '10',
                '6.3': '8.1',
                '6.2': '8',
                '6.1': '7',
                '6.0': 'Vista',
                '5.1': 'XP',
                '5.0': '2000'
            }
            result['os_version'] = version_map.get(nt_version, nt_version)
            
    elif 'macintosh' in user_agent_lower or 'mac os x' in user_agent_lower:
        result['os'] = 'macOS'
        # Extract macOS version: "Mac OS X 10_15_7" or "Intel Mac OS X 10.15"
        mac_match = re.search(r'mac os x (\d+)[._](\d+)(?:[._](\d+))?', user_agent_lower)
        if mac_match:
            version_parts = [mac_match.group(1), mac_match.group(2)]
            if mac_match.group(3):
                version_parts.append(mac_match.group(3))
            result['os_version'] = '.'.join(version_parts)
            
    elif 'linux' in user_agent_lower and 'android' not in user_agent_lower:
        result['os'] = 'Linux'
        # Try to detect Linux distribution
        if 'ubuntu' in user_agent_lower:
            result['os_version'] = 'Ubuntu'
        elif 'centos' in user_agent_lower:
            result['os_version'] = 'CentOS'
        elif 'fedora' in user_agent_lower:
            result['os_version'] = 'Fedora'
        elif 'debian' in user_agent_lower:
            result['os_version'] = 'Debian'
    
    # Browser Detection with version parsing
    if 'edg/' in user_agent_lower:  # Edge (Chromium-based)
        result['browser'] = 'Edge'
        edge_match = re.search(r'edg/(\d+(?:\.\d+)*)', user_agent_lower)
        if edge_match:
            result['browser_version'] = edge_match.group(1)
            
    elif 'chrome/' in user_agent_lower and 'edg/' not in user_agent_lower:
        result['browser'] = 'Chrome'
        chrome_match = re.search(r'chrome/(\d+(?:\.\d+)*)', user_agent_lower)
        if chrome_match:
            result['browser_version'] = chrome_match.group(1)
            
    elif 'firefox/' in user_agent_lower:
        result['browser'] = 'Firefox'
        firefox_match = re.search(r'firefox/(\d+(?:\.\d+)*)', user_agent_lower)
        if firefox_match:
            result['browser_version'] = firefox_match.group(1)
            
    elif 'safari/' in user_agent_lower and 'chrome' not in user_agent_lower:
        result['browser'] = 'Safari'
        # Safari version is tricky, try to get it from Version/ field
        safari_match = re.search(r'version/(\d+(?:\.\d+)*)', user_agent_lower)
        if safari_match:
            result['browser_version'] = safari_match.group(1)
    
    return result


def format_user_agent_summary(parsed_data: Dict[str, any]) -> str:
    """
    Create a human-readable summary of parsed user agent data.
    
    Args:
        parsed_data: Dictionary from parse_user_agent()
        
    Returns:
        Formatted string like "Windows 10 - Chrome 91.0" or "iOS 14.6 - Safari (Mobile)"
    """
    os_part = parsed_data['os']
    if parsed_data['os_version']:
        os_part += f" {parsed_data['os_version']}"
    
    browser_part = parsed_data['browser']
    if parsed_data['browser_version']:
        browser_part += f" {parsed_data['browser_version'].split('.')[0]}"  # Just major version
    
    if parsed_data['is_mobile']:
        browser_part += " (Mobile)"
    
    return f"{os_part} - {browser_part}"