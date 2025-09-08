"""
Tests for server_templates utility functions.
"""

import pytest
import os
import tempfile
from unittest.mock import patch, MagicMock
from flask import Flask

from app.utils.server_templates import get_template_set_choices


@pytest.fixture
def app():
    """Test Flask app instance."""
    app = Flask(__name__)
    app.config['TESTING'] = True
    return app


def test_get_template_set_choices_missing_directory(app):
    """Test get_template_set_choices with missing directory."""
    with app.app_context():
        app.config['SERVER_TEMPLATES_DIR'] = '/non/existent/directory'
        result = get_template_set_choices()
        
        assert result == {}


def test_get_template_set_choices_no_config(app):
    """Test get_template_set_choices with default relative path."""
    with app.app_context():
        # Don't set SERVER_TEMPLATES_DIR config - should use default
        with patch('os.path.exists') as mock_exists:
            mock_exists.return_value = False
            result = get_template_set_choices()
            
            assert result == {}
            # Should check for existence of default path relative to app root
            mock_exists.assert_called_once()
            called_path = mock_exists.call_args[0][0]
            assert 'settings/server_templates' in called_path


def test_get_template_set_choices_with_valid_templates(app):
    """Test get_template_set_choices with valid template files."""
    with tempfile.TemporaryDirectory() as temp_dir:
        # Create test template files
        test_files = [
            'Default.1.ovpn',  # Valid format
            'Admin.2.ovpn',    # Valid format  
            'Default.10.ovpn', # Valid format, different priority
            'invalid.ovpn',    # Invalid format - no priority
            'test.txt',        # Wrong extension
            'BadPriority.abc.ovpn'  # Invalid priority
        ]
        
        for filename in test_files:
            with open(os.path.join(temp_dir, filename), 'w') as f:
                f.write('client\nproto udp\n')
        
        with app.app_context():
            app.config['SERVER_TEMPLATES_DIR'] = temp_dir
            
            result = get_template_set_choices()
            
            # Should have Default and Admin template sets
            template_names = [choice[0] for choice in result]
            assert 'Default' in template_names
            assert 'Admin' in template_names
            
            # Check labels contain template counts
            labels = [choice[1] for choice in result]
            default_label = next(label for name, label in result if name == 'Default')
            admin_label = next(label for name, label in result if name == 'Admin')
            
            assert '2 templates' in default_label  # Default should have 2 templates (priority 1 and 10)
            assert '1 template' in admin_label     # Admin should have 1 template (priority 2)
            
            # Check that choices are sorted alphabetically by template name
            assert result == sorted(result, key=lambda x: x[0])
                

def test_get_template_set_choices_absolute_path(app):
    """Test get_template_set_choices with absolute path."""
    with tempfile.TemporaryDirectory() as temp_dir:
        template_file = os.path.join(temp_dir, 'Test.5.ovpn')
        with open(template_file, 'w') as f:
            f.write('client\nremote example.com\n')
        
        with app.app_context():
            # Use absolute path
            app.config['SERVER_TEMPLATES_DIR'] = temp_dir
            
            result = get_template_set_choices()
            
            template_names = [choice[0] for choice in result]
            assert 'Test' in template_names
            
            # Check the label shows 1 template
            test_label = next(label for name, label in result if name == 'Test')
            assert '1 template' in test_label


def test_get_template_set_choices_relative_path(app):
    """Test get_template_set_choices with relative path (hits line 26)."""
    with tempfile.TemporaryDirectory() as temp_dir:
        # Create a template file
        template_file = os.path.join(temp_dir, 'Test.1.ovpn')
        with open(template_file, 'w') as f:
            f.write('client\nremote example.com\n')
        
        with app.app_context():
            # Set relative path - this will trigger os.path.join with app.root_path
            relative_path = 'settings/server_templates'
            app.config['SERVER_TEMPLATES_DIR'] = relative_path
            
            # Mock the app.root_path to point to our temp directory parent
            original_root_path = app.root_path
            app.root_path = temp_dir.replace('/settings/server_templates', '')
            
            # Create the expected directory structure
            settings_dir = os.path.join(app.root_path, 'settings')
            templates_dir = os.path.join(settings_dir, 'server_templates')
            os.makedirs(templates_dir, exist_ok=True)
            
            # Copy template file to the expected location
            import shutil
            shutil.copy(template_file, os.path.join(templates_dir, 'Test.1.ovpn'))
            
            try:
                result = get_template_set_choices()
                template_names = [choice[0] for choice in result]
                assert 'Test' in template_names
                # Check the label shows 1 template
                test_label = next(label for name, label in result if name == 'Test')
                assert '1 template' in test_label
            finally:
                app.root_path = original_root_path


def test_get_template_set_choices_invalid_priority(app):
    """Test get_template_set_choices with invalid priority (hits lines 45-47)."""
    with tempfile.TemporaryDirectory() as temp_dir:
        # Create test template files with invalid priority
        test_files = [
            'Valid.1.ovpn',           # Valid
            'InvalidPriority.abc.ovpn'  # Invalid priority - should be skipped
        ]
        
        for filename in test_files:
            with open(os.path.join(temp_dir, filename), 'w') as f:
                f.write('client\nproto udp\n')
        
        with app.app_context():
            app.config['SERVER_TEMPLATES_DIR'] = temp_dir
            
            result = get_template_set_choices()
            
            # Should only have Valid template (InvalidPriority should be skipped)
            template_names = [choice[0] for choice in result]
            assert 'Valid' in template_names
            assert 'InvalidPriority' not in template_names
            
            # Check the label shows 1 template
            valid_label = next(label for name, label in result if name == 'Valid')
            assert '1 template' in valid_label


def test_get_template_set_choices_invalid_filename_format(app):
    """Test get_template_set_choices with invalid filename format (hits line 58)."""
    with tempfile.TemporaryDirectory() as temp_dir:
        # Create test template files
        test_files = [
            'Valid.1.ovpn',        # Valid format
            'invalid.ovpn',        # Invalid - no priority
            'also.invalid',        # Invalid - wrong extension
            'no-dots-at-all'       # Invalid - no dots
        ]
        
        for filename in test_files:
            with open(os.path.join(temp_dir, filename), 'w') as f:
                f.write('client\nproto udp\n')
        
        with app.app_context():
            app.config['SERVER_TEMPLATES_DIR'] = temp_dir
            
            result = get_template_set_choices()
            
            # Should only have Valid template
            template_names = [choice[0] for choice in result]
            assert 'Valid' in template_names
            assert len(result) == 1  # Only one template set
            
            # Check the label shows 1 template
            valid_label = next(label for name, label in result if name == 'Valid')
            assert '1 template' in valid_label