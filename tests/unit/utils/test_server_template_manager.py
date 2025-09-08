"""
Unit tests for ServerTemplateManager functionality.
"""

import os
import tempfile
import pytest
from flask import Flask
from app.utils.server_template_manager import ServerTemplateManager, create_server_template_manager


class TestServerTemplateManager:
    """Unit tests for server template manager."""

    @pytest.fixture
    def app(self):
        """Create a test Flask app."""
        app = Flask(__name__)
        app.config['TESTING'] = True
        return app

    @pytest.fixture
    def temp_template_dir(self):
        """Create a temporary directory with test templates."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create UDP template
            udp_template = """---
priority: 100
protocol: udp
port: 1194
output_filename: "server-{{ template_protocol }}-{{ template_port }}.ovpn"
description: "UDP server configuration"
---
# UDP Server Config
port {{ template_port }}
proto {{ template_protocol }}
# Template: {{ config_type }}
"""
            with open(os.path.join(temp_dir, '100-udp-1194.ovpn'), 'w') as f:
                f.write(udp_template)

            # Create TCP template
            tcp_template = """---
priority: 200
protocol: tcp
port: 443
output_filename: "server-{{ template_protocol }}-{{ template_port }}.ovpn"
description: "TCP server configuration"
---
# TCP Server Config
port {{ template_port }}
proto {{ template_protocol }}-server
# Template: {{ config_type }}
"""
            with open(os.path.join(temp_dir, '200-tcp-443.ovpn'), 'w') as f:
                f.write(tcp_template)

            # Create template without frontmatter
            plain_template = """# Plain server config
port 1195
proto udp
dev tun
"""
            with open(os.path.join(temp_dir, 'plain-server.ovpn'), 'w') as f:
                f.write(plain_template)
            
            # Create a non-.ovpn file that should be skipped
            with open(os.path.join(temp_dir, 'README.md'), 'w') as f:
                f.write('# This file should be skipped')

            yield temp_dir

    def test_create_server_template_manager(self, app):
        """Test factory function creates manager."""
        manager = create_server_template_manager(app)
        assert isinstance(manager, ServerTemplateManager)
        assert manager.app == app

    def test_load_server_templates_from_directory(self, app, temp_template_dir):
        """Test loading templates from directory."""
        with app.app_context():
            manager = ServerTemplateManager(app)
            templates = manager._load_server_templates(temp_template_dir)
            
            assert len(templates) == 3  # Two with frontmatter, one plain
            
            # Should be sorted by priority
            assert templates[0]['priority'] == 100  # UDP
            assert templates[1]['priority'] == 200  # TCP
            assert templates[2]['priority'] == 999  # Plain (default priority)

    def test_parse_template_with_frontmatter(self, app, temp_template_dir):
        """Test parsing template with YAML frontmatter."""
        with app.app_context():
            manager = ServerTemplateManager(app)
            file_path = os.path.join(temp_template_dir, '100-udp-1194.ovpn')
            
            template_data = manager._parse_template_file(file_path, '100-udp-1194.ovpn')
            
            assert template_data is not None
            assert template_data['filename'] == '100-udp-1194.ovpn'
            assert template_data['priority'] == 100
            assert template_data['protocol'] == 'udp'
            assert template_data['port'] == 1194
            assert template_data['output_filename'] == 'server-{{ template_protocol }}-{{ template_port }}.ovpn'
            assert template_data['description'] == 'UDP server configuration'
            assert '# UDP Server Config' in template_data['content']

    def test_parse_template_without_frontmatter(self, app, temp_template_dir):
        """Test parsing template without YAML frontmatter uses defaults."""
        with app.app_context():
            manager = ServerTemplateManager(app)
            file_path = os.path.join(temp_template_dir, 'plain-server.ovpn')
            
            template_data = manager._parse_template_file(file_path, 'plain-server.ovpn')
            
            assert template_data is not None
            assert template_data['filename'] == 'plain-server.ovpn'
            assert template_data['priority'] == 999  # Default priority
            assert template_data['protocol'] == 'udp'  # Default protocol
            assert template_data['port'] == '1194'  # Default port
            assert template_data['content'] == '# Plain server config\nport 1195\nproto udp\ndev tun\n'

    def test_find_template_for_config_exact_match(self, app, temp_template_dir):
        """Test finding template with exact protocol/port match."""
        with app.app_context():
            app.config['SERVER_TEMPLATES_DIR'] = temp_template_dir
            manager = ServerTemplateManager(app)
            
            # Find UDP 1194 template
            template = manager.find_template_for_config('udp', '1194')
            assert template is not None
            assert template['protocol'] == 'udp'
            assert template['port'] == 1194
            
            # Find TCP 443 template
            template = manager.find_template_for_config('tcp', '443')
            assert template is not None
            assert template['protocol'] == 'tcp'
            assert template['port'] == 443

    def test_find_template_for_config_protocol_match(self, app, temp_template_dir):
        """Test finding template with protocol match when exact port not found."""
        with app.app_context():
            app.config['SERVER_TEMPLATES_DIR'] = temp_template_dir
            manager = ServerTemplateManager(app)
            
            # Find UDP template with different port
            template = manager.find_template_for_config('udp', '9999')
            assert template is not None
            assert template['protocol'] == 'udp'
            # Should find the UDP template even though port doesn't match

    def test_find_template_for_config_fallback(self, app, temp_template_dir):
        """Test fallback to first template when no match found."""
        with app.app_context():
            app.config['SERVER_TEMPLATES_DIR'] = temp_template_dir
            manager = ServerTemplateManager(app)
            
            # Find template for protocol that doesn't exist
            template = manager.find_template_for_config('sctp', '9999')
            assert template is not None
            # Should return first template (lowest priority)
            assert template['priority'] == 100

    def test_render_server_config(self, app, temp_template_dir):
        """Test rendering server configuration with enhanced context."""
        with app.app_context():
            app.config['SERVER_TEMPLATES_DIR'] = temp_template_dir
            manager = ServerTemplateManager(app)
            
            template = manager.find_template_for_config('udp', '1194')
            context = {
                'hostname': 'test-server',
                'template_port': '1194'
            }
            
            rendered = manager.render_server_config(template, context)
            
            assert 'port 1194' in rendered
            assert 'proto udp' in rendered
            assert 'Template: udp-1194' in rendered

    def test_get_output_filename(self, app, temp_template_dir):
        """Test getting output filename with Jinja2 processing."""
        with app.app_context():
            app.config['SERVER_TEMPLATES_DIR'] = temp_template_dir
            manager = ServerTemplateManager(app)
            
            template = manager.find_template_for_config('udp', '1194')
            context = {
                'template_protocol': 'udp',
                'template_port': '1194'
            }
            
            filename = manager.get_output_filename(template, context)
            assert filename == 'server-udp-1194.ovpn'

    def test_get_server_templates_no_config(self, app):
        """Test getting templates when SERVER_TEMPLATES_DIR not configured."""
        with app.app_context():
            manager = ServerTemplateManager(app)
            templates = manager.get_server_templates()
            assert templates == []

    def test_get_server_templates_caching(self, app, temp_template_dir):
        """Test that templates are cached after first load."""
        with app.app_context():
            app.config['SERVER_TEMPLATES_DIR'] = temp_template_dir
            manager = ServerTemplateManager(app)
            
            # First call loads templates
            templates1 = manager.get_server_templates()
            
            # Second call should return cached templates
            templates2 = manager.get_server_templates()
            
            assert templates1 is templates2  # Same object reference

    def test_load_server_templates_invalid_directory(self, app):
        """Test loading templates from non-existent directory."""
        with app.app_context():
            manager = ServerTemplateManager(app)
            
            with pytest.raises(FileNotFoundError, match="Server template path.*not found"):
                manager._load_server_templates('/nonexistent/path')

    def test_parse_template_invalid_yaml(self, app):
        """Test parsing template with invalid YAML frontmatter."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.ovpn', delete=False) as f:
            f.write("""---
invalid: yaml: syntax: error
---
# Server config
""")
            f.flush()
            
            try:
                with app.app_context():
                    manager = ServerTemplateManager(app)
                    template_data = manager._parse_template_file(f.name, 'invalid.ovpn')
                    
                    # Should handle invalid YAML gracefully
                    assert template_data is not None
                    assert template_data['priority'] == 999  # Default
                    assert '# Server config' in template_data['content']
            finally:
                os.unlink(f.name)

    def test_parse_template_malformed_frontmatter(self, app):
        """Test parsing template with malformed frontmatter."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.ovpn', delete=False) as f:
            f.write("""---
priority: 100
# Missing closing ---
# Server config
""")
            f.flush()
            
            try:
                with app.app_context():
                    manager = ServerTemplateManager(app)
                    template_data = manager._parse_template_file(f.name, 'malformed.ovpn')
                    
                    # Should handle malformed frontmatter gracefully
                    assert template_data is not None
                    # This actually parses as valid YAML until EOF, so priority should be 100
                    assert template_data['priority'] == 100  # From YAML content
                    # But the content should include everything after the ---
                    assert '# Server config' in template_data['content']
            finally:
                os.unlink(f.name)

    def test_parse_template_invalid_metadata_type(self, app):
        """Test parsing template with non-dict YAML metadata."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.ovpn', delete=False) as f:
            f.write("""---
- item1
- item2
---
# Server config with list metadata
""")
            f.flush()
            
            try:
                with app.app_context():
                    manager = ServerTemplateManager(app)
                    template_data = manager._parse_template_file(f.name, 'list-metadata.ovpn')
                    
                    # Should handle non-dict metadata gracefully
                    assert template_data is not None
                    assert template_data['priority'] == 999  # Default priority
                    assert '# Server config with list metadata' in template_data['content']
            finally:
                os.unlink(f.name)

    def test_get_server_templates_empty_directory(self, app):
        """Test getting templates from empty directory."""
        with tempfile.TemporaryDirectory() as temp_dir:
            with app.app_context():
                app.config['SERVER_TEMPLATES_DIR'] = temp_dir
                manager = ServerTemplateManager(app)
                templates = manager.get_server_templates()
                assert templates == []

    def test_find_template_for_config_no_templates(self, app):
        """Test finding template when no templates are available."""
        with tempfile.TemporaryDirectory() as temp_dir:
            with app.app_context():
                app.config['SERVER_TEMPLATES_DIR'] = temp_dir
                manager = ServerTemplateManager(app)
                template = manager.find_template_for_config('udp', '1194')
                assert template is None

    def test_parse_template_exception_handling(self, app):
        """Test template parsing exception handling."""
        with app.app_context():
            manager = ServerTemplateManager(app)
            # Try to parse a non-existent file
            template_data = manager._parse_template_file('/nonexistent/file.ovpn', 'nonexistent.ovpn')
            assert template_data is None

    def test_parse_template_truly_malformed_frontmatter(self, app):
        """Test parsing template with truly malformed frontmatter (only one ---)."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.ovpn', delete=False) as f:
            f.write("""---
priority: 100
# This frontmatter never closes properly
# Server config starts here
port 1194
proto udp
""")
            f.flush()
            
            try:
                with app.app_context():
                    manager = ServerTemplateManager(app)
                    template_data = manager._parse_template_file(f.name, 'malformed2.ovpn')
                    
                    # Should handle truly malformed frontmatter by treating as no frontmatter
                    assert template_data is not None
                    assert template_data['priority'] == 999  # Default priority
                    # Content should include the entire file since frontmatter parsing failed
                    assert 'priority: 100' in template_data['content']
                    assert 'port 1194' in template_data['content']
            finally:
                os.unlink(f.name)