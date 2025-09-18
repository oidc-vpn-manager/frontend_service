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
    force_https = app.config.get('FORCE_HTTPS', False)
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
    talisman.init_app(app, force_https=force_https, content_security_policy=content_security_policy)
    
    csrf.init_app(app)
    oauth.init_app(app)
    oauth.register(
        name='oidc',
        server_metadata_url=app.config["OIDC_DISCOVERY_URL"],
        client_id=app.config["OIDC_CLIENT_ID"],
        client_secret=app.config["OIDC_CLIENT_SECRET"],
        client_kwargs={'scope': 'openid email profile groups'}
    )