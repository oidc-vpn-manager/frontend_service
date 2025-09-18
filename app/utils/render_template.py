from flask import render_template as parent_render_template, current_app, session
from app.utils.tracing import trace

def render_template(template, **kargs):
    trace(current_app, 'utils.render_template.render_template', {'template': template, 'kargs': kargs})
    admin_url_base = current_app.config.get('ADMIN_URL_BASE', '')
    user_url_base = current_app.config.get('USER_URL_BASE', '')
    roles = []
    if 'user' in session:
        user = session.get('user', {})
        if user and user != {} and isinstance(user, dict):
            roles.append('user')
            if user.get('is_auditor', False):
                roles.append('auditor')
            if user.get('is_system_admin', False):
                roles.append('system_admin')
            if user.get('is_admin', False):
                roles.append('service_admin')
    
    return parent_render_template(template, current_app=current_app, admin_url_base=admin_url_base, user_url_base=user_url_base, roles=roles, **kargs)
