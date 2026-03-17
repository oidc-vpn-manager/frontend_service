import pytest
from flask import Flask
from unittest.mock import patch

from app.utils.render_config_template import (
    load_config_templates,
    find_best_template_match,
    render_config_template,
    validate_config_templates,
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


# Minimal valid template covering the variables provided by both routes.
_VALID_TEMPLATE = """\
client
{%- if protocol == 'tcp' %}
proto tcp-client
{%- else %}
proto udp
{%- endif %}
remote vpn.example.com {{ port | default('1194') }}
<ca>
{{ ca_cert_pem }}
</ca>
<cert>
{{ device_cert_pem }}
</cert>
<key>
{{ device_key_pem }}
</key>
{%- if tls_crypt_key %}
<tls-crypt>
{{ tls_crypt_key }}
</tls-crypt>
{%- endif %}
"""


class TestValidateConfigTemplates:
    """Tests for the validate_config_templates startup check."""

    def test_no_template_path_skips_validation(self, app):
        """When OVPN_TEMPLATE_PATH is not configured, validation is silently skipped."""
        app.config['OVPN_TEMPLATE_PATH'] = None
        with app.app_context():
            validate_config_templates(app)  # must not raise

    def test_missing_directory_raises_runtime_error(self, app):
        """A configured but non-existent template path raises RuntimeError at startup."""
        app.config['OVPN_TEMPLATE_PATH'] = '/non/existent/path'
        with app.app_context():
            with pytest.raises(RuntimeError, match="Template validation failed"):
                validate_config_templates(app)

    def test_empty_directory_warns_but_does_not_raise(self, app, tmp_path):
        """An empty template directory logs a warning but does not raise."""
        app.config['OVPN_TEMPLATE_PATH'] = str(tmp_path)
        with app.app_context():
            validate_config_templates(app)  # must not raise

    def test_valid_template_passes(self, app, tmp_path):
        """A well-formed template that uses only known context variables passes validation."""
        (tmp_path / "999.default.ovpn").write_text(_VALID_TEMPLATE)
        app.config['OVPN_TEMPLATE_PATH'] = str(tmp_path)
        with app.app_context():
            validate_config_templates(app)  # must not raise

    def test_undefined_variable_raises_runtime_error(self, app, tmp_path):
        """A template referencing an undefined variable raises RuntimeError listing the file."""
        (tmp_path / "999.default.ovpn").write_text(
            "client\n{% if mystery_var %}do something{% endif %}\n"
        )
        app.config['OVPN_TEMPLATE_PATH'] = str(tmp_path)
        with app.app_context():
            with pytest.raises(RuntimeError, match="999.default.ovpn"):
                validate_config_templates(app)

    def test_multiple_failures_reported_together(self, app, tmp_path):
        """All failing templates are listed in a single RuntimeError, not just the first."""
        (tmp_path / "100.alpha.ovpn").write_text("{{ undefined_one }}")
        (tmp_path / "200.beta.ovpn").write_text("{{ undefined_two }}")
        app.config['OVPN_TEMPLATE_PATH'] = str(tmp_path)
        with app.app_context():
            with pytest.raises(RuntimeError) as exc_info:
                validate_config_templates(app)
        msg = str(exc_info.value)
        assert "100.alpha.ovpn" in msg
        assert "200.beta.ovpn" in msg
        assert "2 template(s)" in msg

    def test_valid_template_uses_cached_collection(self, app, tmp_path):
        """Validation uses the pre-loaded TEMPLATE_COLLECTION when already cached."""
        app.config['TEMPLATE_COLLECTION'] = [
            {
                'priority': 999,
                'group_name': 'default',
                'file_name': '999.default.ovpn',
                'content': _VALID_TEMPLATE,
            }
        ]
        app.config['OVPN_TEMPLATE_PATH'] = str(tmp_path)
        with app.app_context():
            validate_config_templates(app)  # must not raise


class TestFindBestTemplateMatchLazyLoad:
    """Cover line 153: lazy-load when TEMPLATE_COLLECTION is None but OVPN_TEMPLATE_PATH is set."""

    def test_lazy_loads_from_template_path(self, app, tmp_path):
        """Line 153: if template_path is set, load_config_templates is called."""
        tmpl_file = tmp_path / "1.default.ovpn"
        tmpl_file.write_text("client\nremote vpn.example.com 1194\n")

        app.config['OVPN_TEMPLATE_PATH'] = str(tmp_path)
        app.config['TEMPLATE_COLLECTION'] = None

        with app.app_context():
            _name, content = find_best_template_match(app, ['default'])

        assert 'client' in content


class TestRenderConfigTemplateSecurityViolation:
    """Cover lines 343-344: template rendering raises an 'unsafe' exception."""

    def test_security_violation_raises_value_error(self, app):
        """Lines 343-344: exception message containing 'unsafe' → ValueError."""
        with app.app_context():
            with pytest.raises(ValueError, match="unsafe operations"):
                # Patch Jinja2 Template.render to raise an exception flagged as unsafe
                with patch('app.utils.render_config_template.jinja2.Template.render',
                           side_effect=Exception("unsafe Jinja2 sandbox operation")):
                    render_config_template(app, "{{ x }}", x="ignored")