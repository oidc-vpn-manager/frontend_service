"""
WEB_AUTH endpoint for OpenVPN Connect profile provisioning.

Implements the OpenVPN 3 WEB_AUTH protocol used by the OpenVPN Connect
application to automatically provision VPN profiles without manual import.

Flow:
  1. OpenVPN Connect sends HEAD /openvpn-api/profile to discover WEB_AUTH support.
     - If a VPN-Session-Token header is present and the associated certificate has
       not expired, the response omits Ovpn-WebAuth (profile still fresh).
     - Otherwise, Ovpn-WebAuth: <SITE_NAME>,external is returned, signalling that
       the client must re-authenticate.

  2. OpenVPN Connect opens GET /openvpn-api/profile in the user's external browser.
     - Unauthenticated: device metadata is stashed in the session and the user is
       redirected to the OIDC login flow.  /auth/callback returns them here via
       the next_url mechanism.
     - Authenticated: a one-time DownloadToken is created (with the user's OIDC
       groups for template selection) and the browser is redirected to:
         openvpn://import-profile/https://<host>/download?token=<uuid>

  3. The OS intercepts the openvpn:// URL and passes it to OpenVPN Connect.
     OpenVPN Connect fetches GET /download?token=<uuid>, which generates the
     certificate, selects the template using the stored groups, and returns the
     .ovpn profile.  That endpoint also returns a VPN-Session-Token header (the
     token UUID) which OpenVPN Connect stores for future freshness checks (step 1).

Security considerations:
  - HEAD freshness checks are stateless: token UUID possession is the capability
    credential.  No user identity check is performed; the UUID space is large
    enough that guessing is infeasible.
  - Device metadata (deviceID, deviceModel, etc.) is stored for audit only and
    is never rendered in HTML, preventing XSS from untrusted values.
  - The openvpn:// redirect URL contains only the token UUID — no PII.
  - Group normalisation (list / comma-string / bare string) mirrors the logic in
    app/routes/auth.py so all OIDC provider formats are handled consistently.
"""

import json
import uuid
from datetime import datetime, timezone

from flask import Blueprint, Response, current_app, redirect, request, session, url_for

from app.extensions import db
from app.models import DownloadToken
from app.utils.decorators import user_service_only
from app.utils.tracing import trace

bp = Blueprint('openvpn_api', __name__)

# Device parameter keys forwarded by OpenVPN Connect; stored for audit logging.
_DEVICE_PARAMS = ('deviceID', 'deviceModel', 'deviceOS', 'appVersion')


def _is_profile_fresh(session_token: str) -> bool:
    """
    Determine whether a previously-issued profile is still within its validity period.

    Looks up the DownloadToken by UUID, verifies it has been collected (profile
    was actually downloaded), and checks that the stored certificate expiry is in
    the future.

    Args:
        session_token (str): The VPN-Session-Token value from the request header.
            This is the UUID of the DownloadToken created during the WEB_AUTH flow.

    Returns:
        bool: True if the profile is fresh and re-authentication is not needed,
              False if the token is unknown, uncollected, or the cert has expired.

    Security:
        Any exception during lookup (e.g. DB error, unexpected token format) is
        treated as 'not fresh', forcing re-authentication rather than failing open.

    Example:
        >>> _is_profile_fresh('550e8400-e29b-41d4-a716-446655440000')
        True  # if the associated cert_expiry is in the future
    """
    try:
        token_obj = DownloadToken.query.filter_by(
            token=session_token, collected=True
        ).first()
        if token_obj is None:
            return False
        if token_obj.cert_expiry is None:
            return False
        expiry = token_obj.cert_expiry
        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=timezone.utc)
        return datetime.now(timezone.utc) < expiry
    except Exception:
        return False


def _normalise_groups(raw_groups) -> list:
    """
    Normalise OIDC group memberships to a Python list of strings.

    OIDC providers return groups in several formats:
      - A Python list:               ['engineering', 'vpn-users']
      - A comma-separated string:    'engineering,vpn-users'
      - A bare string (one group):   'engineering'
      - Missing / None / empty list: []

    Args:
        raw_groups: The 'groups' value from the OIDC userinfo dict.

    Returns:
        list[str]: Normalised list of group name strings.

    Example:
        >>> _normalise_groups('engineering,vpn-users')
        ['engineering', 'vpn-users']
        >>> _normalise_groups(['engineering'])
        ['engineering']
        >>> _normalise_groups(None)
        []
    """
    if not raw_groups:
        return []
    if isinstance(raw_groups, list):
        return raw_groups
    if isinstance(raw_groups, str):
        if ',' in raw_groups:
            return [g.strip() for g in raw_groups.split(',')]
        return [raw_groups]
    return []


@bp.route('/openvpn-api/profile', methods=['HEAD', 'GET'])
@user_service_only
def webauth_profile():
    """
    WEB_AUTH endpoint for OpenVPN Connect profile discovery and provisioning.

    HEAD — discovery / freshness check:
        Returns 200 with Ovpn-WebAuth: <SITE_NAME>,external unless a valid
        VPN-Session-Token is supplied whose associated certificate has not expired,
        in which case the header is omitted (profile is still fresh).

    GET (unauthenticated):
        Stashes OpenVPN Connect device metadata in the session and redirects to
        the OIDC login flow.  The OIDC callback returns here via next_url.

    GET (authenticated):
        Creates a DownloadToken (with user's OIDC groups for template selection),
        then redirects to openvpn://import-profile/<download_url> so the OS hands
        the URL to OpenVPN Connect, which then fetches the profile.

    Args:
        None (reads from Flask request context and session).

    Returns:
        HEAD: flask.Response with status 200; conditionally includes Ovpn-WebAuth header.
        GET (unauth): 302 redirect to /auth/login.
        GET (auth): 302 redirect to openvpn://import-profile/… URL.

    Security:
        - Device params are stored verbatim for audit; values are never rendered.
        - The openvpn:// URL contains only the token UUID — no user PII.
        - Group normalisation handles all OIDC provider formats safely.
        - Unauthenticated sessions with malformed 'user' dicts are rejected.

    Example:
        >>> # Discovery (OpenVPN Connect initial probe)
        >>> HEAD /openvpn-api/profile
        >>> # → 200  Ovpn-WebAuth: VPN Service,external

        >>> # Freshness check (subsequent probe with stored token)
        >>> HEAD /openvpn-api/profile  VPN-Session-Token: <uuid>
        >>> # → 200  (no Ovpn-WebAuth if cert still valid)

        >>> # Profile provisioning (browser opened by OpenVPN Connect)
        >>> GET /openvpn-api/profile
        >>> # → 302 openvpn://import-profile/https://host/download?token=<uuid>
    """
    trace(current_app, 'routes.openvpn_api.webauth_profile')

    site_name = current_app.config.get('SITE_NAME', 'VPN Service')

    # ------------------------------------------------------------------
    # HEAD — discovery and freshness check
    # ------------------------------------------------------------------
    if request.method == 'HEAD':
        session_token = request.headers.get('VPN-Session-Token')
        if session_token and _is_profile_fresh(session_token):
            # Profile is valid — no re-auth needed; omit Ovpn-WebAuth
            return Response('', status=200)

        # No token, unknown token, or expired cert — signal re-auth required
        response = Response('', status=200)
        response.headers['Ovpn-WebAuth'] = f'{site_name},external'
        return response

    # ------------------------------------------------------------------
    # GET — profile provisioning
    # ------------------------------------------------------------------
    user = session.get('user')
    if not user or not isinstance(user, dict) or not user.get('sub'):
        # Unauthenticated — stash device metadata for audit and start OIDC flow
        device_params = {
            k: request.args.get(k)
            for k in _DEVICE_PARAMS
            if request.args.get(k) is not None
        }
        if device_params:
            session['webauth_device_params'] = device_params

        session['next_url'] = '/openvpn-api/profile'
        return redirect(url_for('auth.login'))

    # Authenticated — create a one-time download token and redirect via openvpn://
    user_groups = _normalise_groups(user.get('groups'))

    token = DownloadToken(
        user=user['sub'],
        cn=user.get('email', user['sub']),
        requester_ip=request.remote_addr,
        user_agent_string=request.user_agent.string,
        detected_os=request.user_agent.platform,
        optionset_used='',
        user_groups=json.dumps(user_groups),
    )
    token.token = str(uuid.uuid4())
    db.session.add(token)
    db.session.commit()

    download_url = url_for('download.download_profile', token=token.token, _external=True)
    openvpn_url = f'openvpn://import-profile/{download_url}'
    current_app.logger.info(
        f"WEB_AUTH: created token for {user['sub']}, redirecting to openvpn://"
    )
    return redirect(openvpn_url)
