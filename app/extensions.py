from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from authlib.integrations.flask_client import OAuth
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
from flask_session import Session
from flask_wtf.csrf import CSRFProtect

db = SQLAlchemy()
migrate = Migrate()
oauth = OAuth()
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