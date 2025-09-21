"""
Defines reusable decorators for authentication and authorization.
"""

from functools import wraps
from flask import request, abort, current_app, session, redirect, url_for, jsonify
from app.utils.tracing import trace
from app.utils.security_logging import security_logger
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
            security_logger.log_api_authentication_failure(
                endpoint=request.path,
                auth_method="psk",
                failure_reason="Missing or invalid Authorization header"
            )
            return jsonify(error="Authorization header is missing or invalid."), 401
        
        # 2. Extract the key
        sent_key = auth_header.split('Bearer ')[1]
        
        # 3. Find the key in the database by searching through all PSKs
        # Use constant-time approach to prevent timing attacks during PSK enumeration
        psk_object = None
        valid_psks = PreSharedKey.query.filter_by(is_enabled=True).all()

        for candidate_psk in valid_psks:
            # Always call verify_key to maintain constant timing regardless of validity
            is_valid_psk = candidate_psk.is_valid()
            key_matches = candidate_psk.verify_key(sent_key)

            # Use constant-time logic to avoid early termination timing leaks
            if is_valid_psk and key_matches and psk_object is None:
                psk_object = candidate_psk
                # Continue the loop to maintain constant timing
        
        if not psk_object:
            security_logger.log_api_authentication_failure(
                endpoint=request.path,
                auth_method="psk",
                failure_reason="Invalid or expired PSK"
            )
            return jsonify(error="Unauthorized: Invalid or expired key."), 401
        
        # Pass the validated psk_object to the route if needed
        return f(psk_object=psk_object, *args, **kwargs)

    return decorated_function

def login_required(f):
    """
    Decorator to ensure a user is logged in with valid session data.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        trace(current_app, 'utils.decorators.login_required.decorated_function')
        # Ensure user is logged in with proper session structure
        user = session.get('user')
        if (not user or
            not isinstance(user, dict) or
            not user.get('sub')):
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
        # First, ensure user is logged in with proper session structure
        user = session.get('user')
        if (not user or
            not isinstance(user, dict) or
            not user.get('sub')):
            # Store the intended destination URL for post-auth redirect
            session['next_url'] = request.url
            current_app.logger.info(f"Storing destination URL for admin-required post-auth redirect: {request.url}")
            return redirect(url_for('auth.login'))

        # Check for admin group membership
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
            redirect_url = f"{user_url_base.rstrip('/')}{request.path}{'?' + request.query_string.decode() if request.query_string else ''}"
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
    If ADMIN_URL_BASE is configured, redirects to admin service via bounce page.
    Note: This assumes admin_required decorator has already validated user permissions.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        trace(current_app, 'utils.decorators.redirect_admin_to_admin_service.decorated_function')
        
        # Only redirect if ADMIN_URL_BASE is configured (service separation enabled)
        admin_url_base = current_app.config.get('ADMIN_URL_BASE')
        if not admin_url_base:
            return f(*args, **kwargs)  # No separation configured, proceed normally
        
        # Redirect to admin service (admin_required decorator already validated permissions)
        redirect_url = f"{admin_url_base.rstrip('/')}{request.path}{'?' + request.query_string.decode() if request.query_string else ''}"
        return redirect(redirect_url)
    
    return decorated_function


def redirect_user_to_user_service(f):
    """
    Decorator for routes that should be accessed on user service.
    If USER_URL_BASE is configured, redirects to user service via bounce page.
    Note: This assumes login_required decorator has already validated user authentication.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        trace(current_app, 'utils.decorators.redirect_user_to_user_service.decorated_function')
        
        # Only redirect if USER_URL_BASE is configured (service separation enabled)
        user_url_base = current_app.config.get('USER_URL_BASE')
        if not user_url_base:
            return f(*args, **kwargs)  # No separation configured, proceed normally
        
        # Redirect to user service (login_required decorator already validated authentication)
        target_url = f"{user_url_base.rstrip('/')}{request.path}{'?' + request.query_string.decode() if request.query_string else ''}"
        return redirect(url_for('root.bounce_to_user', target_url=target_url))

    return decorated_function


def service_admin_required(f):
    """
    Decorator to ensure a user has service administrator privileges.
    This allows access to certificate management and bulk operations.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        trace(current_app, 'utils.decorators.service_admin_required.decorated_function')
        # First, ensure user is logged in
        if 'user' not in session or not session.get('user'):
            # Store the intended destination URL for post-auth redirect
            session['next_url'] = request.url
            current_app.logger.info(f"Storing destination URL for service-admin-required post-auth redirect: {request.url}")
            return redirect(url_for('auth.login'))

        # Check for service admin or admin role
        user = session.get('user', {})
        is_system_admin = user.get('is_system_admin', False)
        is_admin = user.get('is_admin', False)

        if not (is_system_admin or is_admin):
            current_app.logger.warning(f"Unauthorized access attempt by user {user.get('sub', 'unknown')} for {request.url}")
            abort(403)

        return f(*args, **kwargs)

    return decorated_function


def service_admin_or_auditor_required(f):
    """
    Decorator to ensure a user has service administrator or auditor privileges.
    This allows access to certificate listing and querying operations.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        trace(current_app, 'utils.decorators.service_admin_or_auditor_required.decorated_function')
        # First, ensure user is logged in
        if 'user' not in session or not session.get('user'):
            # Store the intended destination URL for post-auth redirect
            session['next_url'] = request.url
            current_app.logger.info(f"Storing destination URL for service-admin-or-auditor-required post-auth redirect: {request.url}")
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