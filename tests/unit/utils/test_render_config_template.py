import pytest
from flask import Flask
from unittest.mock import patch

from app.utils.render_config_template import (
    load_config_templates,
    find_best_template_match,
    render_config_template
)

@pytest.fixture
def app():
    """Provides a basic Flask app instance for testing."""
    app = Flask(__name__)
    app.config.update({
        "TESTING": True,
        "TEMPLATE_COLLECTION": None, # Start clean for each test
    })
    return app

class TestLoadConfigTemplates:
    """Tests for the load_config_templates function."""

    def test_load_and_parse_success(self, app, tmp_path):
        """Tests successful loading and parsing of various correct template files."""
        d = tmp_path / "templates"
        d.mkdir()
        (d / "010.admins.ovpn").write_text("admin_content")
        (d / "999.default.ovpn").write_text("default_content")
        (d / "invalid.ovpn").write_text("skipped") # Bad name format
        (d / "config.txt").write_text("skipped")   # Not .ovpn extension

        with app.app_context():
            templates = load_config_templates(app, str(d))
        
        assert len(templates) == 2
        assert templates[0]['group_name'] == 'admins'
        assert templates[1]['content'] == 'default_content'
        # Check that the result is cached
        assert app.config['TEMPLATE_COLLECTION'] is not None

    def test_invalid_path_raises_error(self, app):
        """Tests that a FileNotFoundError is raised for a non-existent directory."""
        with app.app_context():
            with pytest.raises(FileNotFoundError):
                load_config_templates(app, "/non/existent/path")

class TestFindBestTemplateMatch:
    """Tests for the find_best_template_match function."""
    
    @pytest.fixture
    def preloaded_app(self, app):
        """Provides an app with a pre-loaded template collection."""
        app.config['TEMPLATE_COLLECTION'] = [
            {"priority": 10, "group_name": "super_users", "file_name": "10.super.ovpn", "content": "super_content"},
            {"priority": 20, "group_name": "admin_users", "file_name": "20.admin.ovpn", "content": "admin_content"},
            {"priority": 999, "group_name": "default", "file_name": "999.default.ovpn", "content": "default_content"}
        ]
        return app

    def test_highest_priority_match(self, preloaded_app):
        """Tests that the template with the lowest priority number is chosen."""
        with preloaded_app.app_context():
            name, content = find_best_template_match(preloaded_app, ['admin_users', 'super_users'])
        assert name == "10.super.ovpn"

    def test_case_insensitive_match(self, preloaded_app):
        """Tests that group matching is case-insensitive."""
        with preloaded_app.app_context():
            name, content = find_best_template_match(preloaded_app, ['ADMIN_USERS'])
        assert name == "20.admin.ovpn"

    def test_no_match_raises_error(self, preloaded_app):
        """Tests that a ValueError is raised if no suitable template can be found."""
        # Remove the 'default' template for this test
        preloaded_app.config['TEMPLATE_COLLECTION'] = [t for t in preloaded_app.config['TEMPLATE_COLLECTION'] if t['group_name'] != 'default']
        
        with preloaded_app.app_context():
            with pytest.raises(ValueError, match="No matching template found"):
                find_best_template_match(preloaded_app, ['other_users'])

    def test_handles_no_template_path(self, app):
        """
        Tests that a ValueError is raised if lazy-loading finds no path.
        """
        app.config['OVPN_TEMPLATE_PATH'] = None
        app.config['TEMPLATE_COLLECTION'] = None

        with app.app_context():
            with pytest.raises(ValueError, match="No matching template found"):
                find_best_template_match(app, ['any_group'])

class TestRenderConfigTemplate:
    """Tests for the render_config_template function."""
    def test_render_success(self, app):
        """Tests that a Jinja2 template string is rendered correctly."""
        with app.app_context():
            result = render_config_template(app, "Value is {{ val }}", val="test")
        assert result == "Value is test"