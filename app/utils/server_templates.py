"""
Utility functions for managing server template sets.
"""

import os
import glob
from flask import current_app
from app.utils.tracing import trace

def get_template_set_choices():
    """
    Get template set choices for form fields.
    
    Returns a list of (value, label) tuples suitable for SelectField.
    """
    trace(
        current_app,
        'utils.server_templates.get_template_set_choices'
    )
    template_sets = {}
    
    # Get the server templates directory from config or default
    templates_dir = current_app.config.get('SERVER_TEMPLATES_DIR')
    if not templates_dir:
        current_app.logger.warning(f'Server templates directory is not defined.')
        templates_dir = 'settings/server_templates'  # Use default fallback
    
    # Make it absolute if it's relative
    if not os.path.isabs(templates_dir):
        templates_dir = os.path.join(current_app.root_path, templates_dir)
    
    if not os.path.exists(templates_dir):
        current_app.logger.warning(f"Server templates directory not found: {templates_dir}")
        return template_sets
    
    # Find all .ovpn files in the directory
    pattern = os.path.join(templates_dir, '*.ovpn')
    template_files = glob.glob(pattern)
    
    for file_path in template_files:
        filename = os.path.basename(file_path)
        
        # Parse filename format: "TemplateName.Priority.ovpn"
        parts = filename.split('.')
        if len(parts) >= 3 and parts[-1] == 'ovpn':
            template_name = parts[0]
            try:
                priority = int(parts[1])
            except ValueError:
                current_app.logger.warning(f"Invalid priority in template filename: {filename}")
                continue
            
            if template_name not in template_sets:
                template_sets[template_name] = []
            
            template_sets[template_name].append({
                'file_path': file_path,
                'filename': filename,
                'priority': priority
            })
        else:
            current_app.logger.warning(f"Template file doesn't follow naming convention: {filename}")
    
    # Sort templates within each set by priority
    for template_name in template_sets:
        template_sets[template_name].sort(key=lambda x: x['priority'])
    
    current_app.logger.info(f"Discovered template sets: {list(template_sets.keys())}")
    
    choices = []
    
    for template_name, templates in template_sets.items():
        template_count = len(templates)
        label = f"{template_name} ({template_count} template{'s' if template_count != 1 else ''})"
        choices.append((template_name, label))
    
    # Sort alphabetically by template name
    choices.sort(key=lambda x: x[0])
    
    return choices