import os
import jinja2
from flask import Flask
from app.utils.tracing import trace

def load_config_templates(app: Flask, template_path) -> list:
    """
    This function parses a directory, looking for files which match a specific filename structure
    which is 000.groupname.ovpn (or in other words, priority, groupname and .ovpn). This is
    returned, so it can be added to the list of templates to render and return to users later.
    """
    trace(
        app,
        'utils.render_config_template.load_config_templates',
        {
            'app': 'FLASK',
            'template_path': template_path
        }
    )
    # Corrected check for whether the templates have already been loaded
    if app.config.get('TEMPLATE_COLLECTION') is None:
        app.logger.info(f"Loading OVPN templates from {template_path}")
        if not os.path.isdir(template_path):
            raise FileNotFoundError(f"ERROR: OVPN template path '{template_path}' not found or not a directory.")
        
        loaded_templates = []
        for filename in os.listdir(template_path):
            if not filename.endswith(".ovpn"):
                app.logger.debug(f'Skipping {filename} as it does not end .ovpn.')
                continue
            
            parts = filename.split('.', 2)
            if len(parts) >= 3 and parts[0].isdigit():
                priority = int(parts[0])
                group_name = parts[1]
                with open(os.path.join(template_path, filename), 'r') as f:
                    content = f.read()
                loaded_templates.append({
                    "priority": priority,
                    "group_name": group_name,
                    "file_name": filename,
                    "content": content
                })
                app.logger.debug(f'Imported {filename} with {priority} priority for {group_name} group.')
            else:
                app.logger.debug(f'Skipping {filename} as it does not have the right format filename.')
        app.config['TEMPLATE_COLLECTION'] = sorted(loaded_templates, key=lambda x: x['priority'])
    
    return app.config.get('TEMPLATE_COLLECTION', [])

def find_best_template_match(app: Flask, user_group_memberships, template_collection: list[str] = None) -> tuple:
    """
    Finds the best template for a user based on their group memberships.
    Handles lazy-loading and caching of templates in the app config.
    """
    trace(
        app,
        'utils.render_config_template.find_best_template_match',
        {
            'app': 'FLASK',
            'user_group_memberships': user_group_memberships,
            'template_collection': template_collection
        }
    )
    if template_collection is None:
        template_collection = app.config.get('TEMPLATE_COLLECTION')

    if template_collection is None:
        template_path = app.config.get('OVPN_TEMPLATE_PATH')
        if template_path:
            template_collection = load_config_templates(app, template_path)
        else:
            template_collection = []
            app.config['TEMPLATE_COLLECTION'] = template_collection

    lower_user_group_memberships = {groupname.lower() for groupname in (user_group_memberships or [])}

    default_template = {}
    for template in template_collection:
        if template['group_name'].lower() == 'default':
            default_template = template
    selected_template = default_template
    for template in template_collection:
        if template['group_name'].lower() in lower_user_group_memberships:
            selected_template = template
            break
    
    if not selected_template:
        raise ValueError("No matching template found and no default is available.")

    template_name = selected_template['file_name']
    template_content = selected_template['content']

    return template_name, template_content

def render_config_template(app: Flask, template_string, **kargs):
    """Renders a Jinja2 template string with the given context."""
    trace(
        app,
        'utils.render_config_template.find_best_template_match',
        {
            'app': 'FLASK',
            'template_string': template_string,
            'kargs': kargs
        }
    )
    final_template = jinja2.Template(template_string)
    rendered_template = final_template.render(**kargs)

    app.logger.debug('Rendered output is:')
    app.logger.debug(rendered_template)

    return rendered_template