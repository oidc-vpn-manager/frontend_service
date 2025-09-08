import os
import jinja2
import yaml
from flask import Flask, current_app
from app.utils.tracing import trace
from typing import Dict, List, Optional


class ServerTemplateManager:
    """Manages server configuration templates with enhanced features."""
    
    def __init__(self, app: Flask):
        trace(
            current_app,
            'utils.server_template_manager.ServerTemplateManager.__init__',
            {
                'self': 'SELF',
                'app': 'FLASK'
            }
        )
        self.app = app
        self._templates_cache = None
    
    def _load_server_templates(self, template_path: str) -> List[Dict]:
        """
        Loads server templates from a directory structure.
        Templates can include metadata in YAML frontmatter.
        """
        trace(
            current_app,
            'utils.server_template_manager.ServerTemplateManager._load_server_templates',
            {
                'self': 'SELF',
                'template_path': template_path
            }
        )
        if not os.path.isdir(template_path):
            raise FileNotFoundError(f"ERROR: Server template path '{template_path}' not found or not a directory.")
        
        loaded_templates = []
        self.app.logger.info(f"Loading server templates from {template_path}")
        
        for filename in os.listdir(template_path):
            if not filename.endswith('.ovpn'):
                self.app.logger.debug(f'Skipping {filename} as it does not end .ovpn.')
                continue
            
            file_path = os.path.join(template_path, filename)
            template_data = self._parse_template_file(file_path, filename)
            if template_data:
                loaded_templates.append(template_data)
                self.app.logger.debug(f'Loaded server template {filename}')
        
        return sorted(loaded_templates, key=lambda x: x['priority'])
    
    def _parse_template_file(self, file_path: str, filename: str) -> Optional[Dict]:
        """
        Parses a template file that may contain YAML frontmatter.
        
        Format:
        ---
        priority: 100
        protocol: udp
        port: 1194
        output_filename: "server-udp-1194.ovpn"
        description: "UDP server configuration"
        ---
        # OpenVPN config content here
        """
        trace(
            current_app,
            'utils.server_template_manager.ServerTemplateManager._parse_template_file',
            {
                'self': 'SELF',
                'file_path': file_path,
                'filename': filename
            }
        )
        try:
            with open(file_path, 'r') as f:
                content = f.read()
            
            # Check for YAML frontmatter
            if content.startswith('---\n'):
                parts = content.split('---\n', 2)
                if len(parts) >= 3:
                    # Has frontmatter
                    yaml_content = parts[1]
                    template_content = parts[2].strip()
                    
                    try:
                        metadata = yaml.safe_load(yaml_content)
                        if not isinstance(metadata, dict):
                            metadata = {}
                    except yaml.YAMLError as e:
                        self.app.logger.warning(f"Invalid YAML frontmatter in {filename}: {e}")
                        metadata = {}
                else:
                    # Malformed frontmatter
                    metadata = {}
                    template_content = content
            else:
                # No frontmatter, use defaults
                metadata = {}
                template_content = content
            
            # Extract defaults from filename if not in metadata
            base_name = filename.replace('.ovpn', '')
            parts = base_name.split('-')
            
            # Set defaults
            template_data = {
                'filename': filename,
                'priority': metadata.get('priority', 999),
                'protocol': metadata.get('protocol', parts[-2] if len(parts) >= 2 and parts[-2] in ['udp', 'tcp'] else 'udp'),
                'port': metadata.get('port', parts[-1] if len(parts) >= 1 and parts[-1].isdigit() else '1194'),
                'output_filename': metadata.get('output_filename', f"server-{metadata.get('protocol', 'udp')}-{metadata.get('port', '1194')}.ovpn"),
                'description': metadata.get('description', f"Server configuration for {filename}"),
                'content': template_content,
                'metadata': metadata
            }
            
            return template_data
            
        except Exception as e:
            self.app.logger.error(f"Error parsing template file {filename}: {e}")
            return None
    
    def get_server_templates(self) -> List[Dict]:
        """Gets all server templates, loading them if necessary."""
        trace(
            current_app,
            'utils.server_template_manager.ServerTemplateManager.get_server_templates',
            {
                'self': 'SELF'
            }
        )
        if self._templates_cache is None:
            SERVER_TEMPLATES_DIR = self.app.config.get('SERVER_TEMPLATES_DIR')
            if SERVER_TEMPLATES_DIR:
                self._templates_cache = self._load_server_templates(SERVER_TEMPLATES_DIR)
            else:
                # Fallback to regular templates if server templates not configured
                self.app.logger.warning("SERVER_TEMPLATES_DIR not configured, falling back to regular templates")
                self._templates_cache = []
        
        return self._templates_cache
    
    def find_template_for_config(self, protocol: str, port: str) -> Optional[Dict]:
        """
        Finds the best template for a specific protocol/port combination.
        """
        trace(
            current_app,
            'utils.server_template_manager.ServerTemplateManager.find_template_for_config',
            {
                'self': 'SELF',
                'protocol': protocol,
                'port': port
            }
        )
        templates = self.get_server_templates()
        
        # First, try to find exact match
        for template in templates:
            if (template['protocol'].lower() == protocol.lower() and 
                str(template['port']) == str(port)):
                return template
        
        # Then try protocol match with any port
        for template in templates:
            if template['protocol'].lower() == protocol.lower():
                return template
        
        # Finally, return first template as fallback
        if templates:
            return templates[0]
        
        return None
    
    def render_server_config(self, template_data: Dict, context: Dict) -> str:
        """
        Renders a server configuration template with the given context.
        Adds template-specific variables to the context.
        """
        trace(
            current_app,
            'utils.server_template_manager.ServerTemplateManager.render_server_config',
            {
                'self': 'SELF',
                'template_data': template_data,
                'context': context
            }
        )
        # Add template-specific context
        enhanced_context = context.copy()
        enhanced_context.update({
            'config_type': f"{template_data['protocol']}-{template_data['port']}",
            'template_protocol': template_data['protocol'],
            'template_port': template_data['port'],
            'output_filename': template_data['output_filename'],
            'template_metadata': template_data.get('metadata', {})
        })
        
        # Render the template
        jinja_template = jinja2.Template(template_data['content'])
        rendered_config = jinja_template.render(**enhanced_context)
        
        self.app.logger.debug(f"Rendered {template_data['protocol']}-{template_data['port']} config")
        return rendered_config
    
    def get_output_filename(self, template_data: Dict, context: Dict) -> str:
        """
        Gets the output filename for a template, processing any Jinja2 variables.
        """
        trace(
            current_app,
            'utils.server_template_manager.ServerTemplateManager.get_output_filename',
            {
                'self': 'SELF',
                'template_data': template_data,
                'context': context
            }
        )
        filename_template = jinja2.Template(template_data['output_filename'])
        return filename_template.render(**context)


def create_server_template_manager(app: Flask) -> ServerTemplateManager:
    """Factory function to create a ServerTemplateManager instance."""
    trace(
        current_app,
        'utils.server_template_manager.create_server_template_manager',
        {
            'app': 'FLASK'
        }
    )
    return ServerTemplateManager(app)