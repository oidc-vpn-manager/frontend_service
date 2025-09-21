"""
Handles OIDC authentication flows (login, callback, logout).
"""

from flask import Blueprint, redirect, url_for, session, current_app, request
from app.utils.tracing import trace
from app.utils.security_logging import security_logger
from urllib.parse import urlencode
from app.extensions import oauth

bp = Blueprint('auth', __name__, url_prefix='/auth')

@bp.route('/login')
def login():
    """
    Redirects the user to the OIDC provider to start the login process.
    Supports CLI workflow via cli_port and optionset parameters.
    Preserves intended destination URL via 'next' parameter.
    """
    trace(current_app, 'routes.auth.login')
    
    # Check for CLI workflow parameters with validation
    from app.utils.input_validation import validate_port_number, validate_alphanumeric_with_special, InputValidationError

    cli_port = request.args.get('cli_port')
    optionset = request.args.get('optionset', '')

    if cli_port:
        try:
            # Validate CLI port
            validated_port = validate_port_number(cli_port)

            # Validate optionset (allow alphanumeric, dash, underscore, comma for multiple options)
            validated_optionset = validate_alphanumeric_with_special(optionset, max_length=100, allowed_chars="-_,")

            # Store validated CLI parameters in session
            session['cli_port'] = validated_port
            session['cli_optionset'] = validated_optionset
            current_app.logger.info(f"CLI workflow initiated: port={validated_port}, optionset={validated_optionset}")
        except (InputValidationError, ValueError) as e:
            current_app.logger.warning(f"Invalid CLI parameters: {e}")
            # Continue without CLI params but don't store invalid data
            pass
    
    # Store intended destination URL (next parameter, session, or referer) with validation
    next_url = request.args.get('next')

    # Check if login_required decorator already stored a destination URL
    if not next_url and 'next_url' in session:
        next_url = session['next_url']
        current_app.logger.info(f"Using destination URL from login_required: {next_url}")

    if not next_url:
        # If no explicit next parameter, check if we came from a specific page
        next_url = request.referrer

    # Validate next_url to prevent open redirect attacks
    # Note: Flask provides built-in protection against URL corruption and malformed URLs
    if next_url:
        if next_url.startswith('/'):
            # Relative URL is safe - limit length for security
            next_url = next_url[:500]
        elif next_url.startswith(request.url_root):
            # Same domain URL is safe
            pass
        else:
            # External URL - reject for security
            current_app.logger.warning(f"Rejected external redirect URL: {next_url}")
            next_url = None

    if next_url and (next_url.startswith('/') or next_url.startswith(request.url_root)):
        # Only store safe URLs from same origin
        session['next_url'] = next_url
        current_app.logger.info(f"Storing destination URL for post-auth redirect: {next_url}")
    elif 'next_url' in session:
        # Clear potentially unsafe or external URLs
        session.pop('next_url', None)
    
    redirect_uri = url_for('auth.callback', _external=True)
    return oauth.oidc.authorize_redirect(redirect_uri)

@bp.route('/callback')
def callback():
    """
    Handles the callback from the OIDC provider after successful login.
    It exchanges the authorization code for a token and stores user info in the session.
    """
    trace(current_app, 'routes.auth.callback')

    try:
        token = oauth.oidc.authorize_access_token()
        # Get userinfo from the userinfo endpoint (this includes groups)
        userinfo = oauth.oidc.userinfo(token=token)
        session['user'] = userinfo

        # Assign role flags based on OIDC group memberships
        user_groups = userinfo.get('groups', [])
        if isinstance(user_groups, str):
            # Handle both comma-separated strings and single group strings
            if ',' in user_groups:
                user_groups = [group.strip() for group in user_groups.split(',')]
            else:
                user_groups = [user_groups]

        session['user']['is_admin'] = current_app.config['OIDC_ADMIN_GROUP'] in user_groups
        session['user']['is_auditor'] = current_app.config['OIDC_AUDITOR_GROUP'] in user_groups
        session['user']['is_system_admin'] = current_app.config['OIDC_SYSTEM_ADMIN_GROUP'] in user_groups

        # Store the ID token for the logout flow
        session['id_token_jwt'] = token.get('id_token')
        current_app.logger.info(f"Login from {session['user']}")

        # Log successful authentication
        user_id = userinfo.get('sub', '')
        security_logger.log_authentication_attempt(
            user_id=user_id,
            success=True,
            method="oidc"
        )

        # Check if this is a CLI workflow
        cli_port = session.get('cli_port')
        if cli_port:
            # CLI workflow - generate download token and redirect to localhost
            from app.models import DownloadToken
            from app.extensions import db
            import uuid

            # Create download token
            download_token = DownloadToken(
                token=str(uuid.uuid4()),
                user=session['user']['sub'],
                cn=session['user'].get('email', session['user']['sub']),
                requester_ip=request.remote_addr,
                user_agent_string=request.user_agent.string,
                detected_os=request.user_agent.platform,
                optionset_used=session.get('cli_optionset', '')
            )
            db.session.add(download_token)
            db.session.commit()

            # Clean up CLI session data
            cli_optionset = session.pop('cli_optionset', '')
            session.pop('cli_port', None)

            # Redirect to CLI callback
            callback_url = f"http://localhost:{cli_port}?token={download_token.token}"
            current_app.logger.info(f"CLI workflow: redirecting to {callback_url}")
            return redirect(callback_url)
    
        # Check for stored destination URL from pre-auth
        next_url = session.pop('next_url', None)
        if next_url:
            current_app.logger.info(f"Redirecting to stored destination: {next_url}")
            return redirect(next_url)

        return redirect(url_for('root.index'))

    except Exception as e:
        # Log authentication failure
        current_app.logger.error(f"Authentication callback failed: {str(e)}")
        security_logger.log_authentication_attempt(
            user_id="unknown",
            success=False,
            method="oidc",
            failure_reason=str(e)
        )
        # Redirect to login page or error page
        return redirect(url_for('auth.login'))

@bp.route('/logout')
def logout():
    """
    Logs the user out by clearing the local session and redirecting to the
    OIDC provider's end-session endpoint for single sign-out.
    """
    trace(current_app, 'routes.auth.logout')

    # Log logout before clearing session
    user_id = ""
    if 'user' in session:
        user_id = session['user'].get('sub', '')
        security_logger.log_logout(user_id)

    id_token = session.get('id_token_jwt')
    session.clear()

    if not current_app.config.get('OIDC_DISABLE_IDP_LOGOUT_FLOW', False):
        # Get the logout endpoint from the OIDC server's metadata
        logout_endpoint = oauth.oidc.server_metadata.get('end_session_endpoint')
        
        # If the OIDC provider supports a logout endpoint, redirect the user there.
        if logout_endpoint and id_token:
            # The provider needs to know where to send the user back to after logout
            post_logout_redirect_uri = url_for('root.index', _external=True)
            
            logout_url_params = {
                'id_token_hint': id_token,
                'post_logout_redirect_uri': post_logout_redirect_uri
            }
            logout_url = f"{logout_endpoint}?{urlencode(logout_url_params)}"
            return redirect(logout_url)

    # Fallback to just logging out locally if OIDC logout isn't possible
    return redirect(url_for('root.index'))