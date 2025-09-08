"""
Test cases to achieve 100% coverage for PreSharedKey model.
"""

import pytest
from app.models.presharedkey import PreSharedKey


class TestPreSharedKeyCoverage:
    """Tests to cover all branches in PreSharedKey model."""
    
    def test_truncate_key_short_key_coverage(self):
        """Test truncate_key with short key (less than 8 characters) - covers line 52."""
        # Test with key shorter than 8 characters
        short_key = "abc"
        result = PreSharedKey.truncate_key(short_key)
        assert result == "****"
        
        # Test with exactly 7 characters  
        seven_char_key = "1234567"
        result = PreSharedKey.truncate_key(seven_char_key)
        assert result == "****"
        
        # Test with empty string
        empty_key = ""
        result = PreSharedKey.truncate_key(empty_key)
        assert result == "****"
        
        # Test with 8 characters should use normal truncation
        eight_char_key = "12345678"
        result = PreSharedKey.truncate_key(eight_char_key)
        assert result == "1234****-****-****-****-********5678"