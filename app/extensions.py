from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from authlib.integrations.flask_client import FlaskOAuth2App, OAuth
from authlib.integrations.requests_client import OAuth2Session
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
from flask_session import Session
from flask_wtf.csrf import CSRFProtect

db = SQLAlchemy()
migrate = Migrate()
limiter = Limiter(key_func=get_remote_address)
talisman = Talisman()
sess = Session()
csrf = CSRFProtect()

# User-Agent for the server-side requests Authlib makes to the identity
# provider (discovery, JWKS, token exchange, userinfo).
#
# Security considerations:
#   - A CDN or WAF in front of the identity provider may refuse generic
#     library user agents (python-requests, curl, ...), which breaks the token
#     exchange after a successful browser login. Naming the service keeps the
#     back-channel distinguishable from scanners and identifies the caller in
#     the provider's logs.
#   - Authlib's default ("Authlib/<version> (+https://authlib.org/)") discloses
#     the library and its exact version to anyone observing outbound traffic;
#     this value names only the service.
OIDC_USER_AGENT = "oidc-vpn-manager-frontend/1"


class ServiceUserAgentSession(OAuth2Session):
    """
    Authlib requests session that always names this service in User-Agent.

    Purpose:
        Authlib applies ``user_agent=`` only to the session behind
        ``_get_oauth_client()`` (token exchange, userinfo). It fetches the
        discovery document (``load_server_metadata``) and the JWKS
        (``fetch_jwk_set``) through a fresh ``client_cls(**client_kwargs)``
        session, which would otherwise send the ``python-requests`` default.
        Setting the header here covers every back-channel request. The
        discovery fetch happens on the first login after each restart, so a
        WAF refusing library user agents would otherwise break login whenever
        a pod starts.

    Args:
        *args: Passed through to ``OAuth2Session``.
        **kwargs: Passed through to ``OAuth2Session``.

    Example:
        >>> ServiceUserAgentSession().headers["User-Agent"]
        'oidc-vpn-manager-frontend/1'
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.headers["User-Agent"] = OIDC_USER_AGENT


class ServiceOAuth2App(FlaskOAuth2App):
    """Flask OAuth2/OIDC client whose every session is a ``ServiceUserAgentSession``."""

    client_cls = ServiceUserAgentSession


class ServiceOAuth(OAuth):
    """
    Authlib Flask registry that builds ``ServiceOAuth2App`` clients.

    Example:
        >>> client = ServiceOAuth(Flask(__name__)).register(name="oidc", client_id="x")
        >>> client.client_cls is ServiceUserAgentSession
        True
    """

    oauth2_client_cls = ServiceOAuth2App


oauth = ServiceOAuth()

def init_extensions(app: Flask):
    app.config['SESSION_SQLALCHEMY'] = db

    db.init_app(app)
    migrate.init_app(app, db)
    if 'sessions' not in db.metadata.tables:
        sess.init_app(app)
    limiter.init_app(app)
    
    # Configure Talisman security headers
    # Only force HTTPS when explicitly configured for production deployment
    # (not just when ENVIRONMENT='production' since tests also use that)
    force_https = app.config.get('FORCE_HTTPS', True)
    content_security_policy = {
        'default-src': "'self'",
        'script-src': "'self'",
        'style-src': "'self' 'unsafe-inline'",
        'img-src': "'self' data:",
        'font-src': "'self'",
        'connect-src': "'self'",
        'frame-src': "'none'",
        'frame-ancestors': "'none'",
        'object-src': "'none'",
        'base-uri': "'self'",
        'form-action': "'self'"
    }
    talisman.init_app(app, force_https=force_https, session_cookie_secure=force_https, content_security_policy=content_security_policy)
    
    csrf.init_app(app)
    oauth.init_app(app)

    client_kwargs = {'scope': app.config.get("OIDC_SCOPES", "openid email profile groups")}
    if app.config.get("OIDC_REQUIRE_PKCE", False):
        client_kwargs['code_challenge_method'] = 'S256'

    oauth.register(
        name='oidc',
        server_metadata_url=app.config["OIDC_DISCOVERY_URL"],
        client_id=app.config["OIDC_CLIENT_ID"],
        client_secret=app.config["OIDC_CLIENT_SECRET"],
        user_agent=OIDC_USER_AGENT,
        client_kwargs=client_kwargs
    )