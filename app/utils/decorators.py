"""
Defines reusable decorators for authentication and authorization.
"""

from functools import wraps
from flask import request, abort, current_app, session, redirect, url_for, jsonify
from app.utils.tracing import trace
from app.models.presharedkey import PreSharedKey


def psk_required(f):
    """
    Decorator to protect routes with Pre-Shared Key (PSK) authentication.
    Expects 'Authorization: Bearer <key>' header.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        trace(current_app, 'utils.decorators.psk_required.decorated_function')
        # 1. Check for Authorization header
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify(error="Authorization header is missing or invalid."), 401
        
        # 2. Extract the key
        sent_key = auth_header.split('Bearer ')[1]
        
        # 3. Find the key in the database by searching through all PSKs
        psk_object = None
        for candidate_psk in PreSharedKey.query.filter_by(is_enabled=True).all():
            if candidate_psk.is_valid() and candidate_psk.verify_key(sent_key):
                psk_object = candidate_psk
                break
        
        if not psk_object:
            return jsonify(error="Unauthorized: Invalid or expired key."), 401
        
        # Pass the validated psk_object to the route if needed
        return f(psk_object=psk_object, *args, **kwargs)

    return decorated_function

def login_required(f):
    """
    Decorator to ensure a user is logged in.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        trace(current_app, 'utils.decorators.login_required.decorated_function')
        # Ensure user is logged in
        if 'user' not in session or not session.get('user'):
            session['next_url'] = request.path
            return redirect(url_for('auth.login'))
        
        return f(*args, **kwargs)

    return decorated_function

def admin_required(f):
    """
    Decorator to ensure a user is in the configured OIDC admin group.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        trace(current_app, 'utils.decorators.admin_required.decorated_function')
        # First, ensure user is logged in
        if 'user' not in session or not session.get('user'):
            # Store the intended destination URL for post-auth redirect
            session['next_url'] = request.url
            current_app.logger.info(f"Storing destination URL for admin-required post-auth redirect: {request.url}")
            return redirect(url_for('auth.login'))

        # Check for admin group membership
        user = session.get('user', {})
        user_groups = user.get('groups', [])
        admin_group = current_app.config.get('OIDC_ADMIN_GROUP')

        current_app.logger.debug('Checking if admin is required')
        current_app.logger.debug(f'User groups are: {user_groups}')
        current_app.logger.debug(f'Admin group is: {admin_group}')

        if not admin_group or admin_group not in user_groups:
            current_app.logger.warning(f"Unauthorized access attempt by user {user.get('sub', 'unknown')} for {request.url}")
            abort(403)  # Forbidden
        
        return f(*args, **kwargs)

    return decorated_function


def auditor_or_service_admin_required(f):
    """
    Decorator to ensure a user has auditor or service administrator privileges.
    This allows access to Certificate Transparency log viewing.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        trace(current_app, 'utils.decorators.auditor_or_service_admin_required.decorated_function')
        # First, ensure user is logged in
        if 'user' not in session or not session.get('user'):
            # Store the intended destination URL for post-auth redirect
            session['next_url'] = request.url
            current_app.logger.info(f"Storing destination URL for auditor-or-service-admin-required post-auth redirect: {request.url}")
            return redirect(url_for('auth.login'))

        # Check for auditor, service admin, or admin role
        user = session.get('user', {})
        is_auditor = user.get('is_auditor', False)
        is_system_admin = user.get('is_system_admin', False)  
        is_admin = user.get('is_admin', False)
        
        if not (is_auditor or is_system_admin or is_admin):
            current_app.logger.warning(f"Unauthorized access attempt by user {user.get('sub', 'unknown')} for {request.url}")
            abort(403)
        
        return f(*args, **kwargs)
    
    return decorated_function


def admin_service_only(f):
    """
    Decorator for routes that should only be available on admin service.
    If ADMIN_URL_BASE is configured (user service deployment),
    returns 403 Forbidden.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        trace(current_app, 'utils.decorators.admin_service_only.decorated_function')
        
        # If ADMIN_URL_BASE is configured, this deployment is user-focused
        # and should not serve admin routes
        admin_url_base = current_app.config.get('ADMIN_URL_BASE')
        if admin_url_base:
            current_app.logger.warning(f"Admin route accessed on user service: {request.path}")
            abort(403)  # Forbidden - admin routes not available on user service
        
        return f(*args, **kwargs)
    
    return decorated_function


def user_service_only(f):
    """
    Decorator for routes that should only be available on user service.
    If USER_URL_BASE is configured (admin service deployment),
    returns 301 redirect to user service.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        trace(current_app, 'utils.decorators.user_service_only.decorated_function')
        
        # If USER_URL_BASE is configured, this deployment is admin-focused
        # and should redirect user routes to user service
        user_url_base = current_app.config.get('USER_URL_BASE')
        if user_url_base:
            redirect_url = f"{user_url_base.rstrip('/')}{request.path}"
            if request.query_string:
                redirect_url += f"?{request.query_string.decode()}"
            current_app.logger.info(f"Redirecting user route to user service: {redirect_url}")
            return redirect(redirect_url, code=301)
        
        return f(*args, **kwargs)
    
    return decorated_function


def admin_service_only_api(f):
    """
    Decorator for API routes that should only be available on admin service.
    Returns 403 Forbidden when accessed on user service (no bounce page for APIs).
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        trace(current_app, 'utils.decorators.admin_service_only_api.decorated_function')
        
        # If ADMIN_URL_BASE is configured, this deployment is user-focused
        # and should not serve admin API routes
        admin_url_base = current_app.config.get('ADMIN_URL_BASE')
        if admin_url_base:
            current_app.logger.warning(f"Admin API route accessed on user service: {request.path}")
            abort(403)  # Forbidden - admin APIs not available on user service
        
        return f(*args, **kwargs)
    
    return decorated_function


def user_service_only_api(f):
    """
    Decorator for API routes that should only be available on user service.
    Returns 301 redirect when accessed on admin service (no bounce page for APIs).
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        trace(current_app, 'utils.decorators.user_service_only_api.decorated_function')
        
        # If USER_URL_BASE is configured, this deployment is admin-focused
        # and should redirect user API routes to user service
        user_url_base = current_app.config.get('USER_URL_BASE')
        if user_url_base:
            redirect_url = f"{user_url_base.rstrip('/')}{request.path}"
            if request.query_string:
                redirect_url += f"?{request.query_string.decode()}"
            current_app.logger.info(f"User API route redirected to user service: {redirect_url}")
            return redirect(redirect_url, code=301)
        
        return f(*args, **kwargs)
    
    return decorated_function


def redirect_admin_to_admin_service(f):
    """
    Decorator for routes that admin users should access on admin service.
    If ADMIN_URL_BASE is configured and user has admin privileges,
    redirects to admin service via bounce page.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        trace(current_app, 'utils.decorators.redirect_admin_to_admin_service.decorated_function')
        
        # Only redirect if ADMIN_URL_BASE is configured (service separation enabled)
        admin_url_base = current_app.config.get('ADMIN_URL_BASE')
        if not admin_url_base:
            return f(*args, **kwargs)  # No separation configured, proceed normally
        
        # Check if user is logged in and has admin privileges
        user = session.get('user', {})
        is_admin = user.get('is_admin', False)
        is_system_admin = user.get('is_system_admin', False)
        is_auditor = user.get('is_auditor', False)
        
        if is_admin or is_system_admin or is_auditor:
            # Redirect admin user to admin service
            redirect_url = f"{admin_url_base.rstrip('/')}{request.path}"
            if request.query_string:
                redirect_url += f"?{request.query_string.decode()}"
            return redirect(redirect_url)
        
        return f(*args, **kwargs)
    
    return decorated_function