import os
import tempfile
import atexit
import shutil
from flask import Flask
from werkzeug.middleware.proxy_fix import ProxyFix
from typing import Optional

# Global registry to track temporary instance directories for cleanup
_temp_instance_dirs = set()

def _cleanup_temp_dirs():
    """Cleanup temporary instance directories on process exit"""
    for temp_dir in list(_temp_instance_dirs):
        try:
            if os.path.exists(temp_dir):
                shutil.rmtree(temp_dir)
            _temp_instance_dirs.discard(temp_dir)
        except Exception:  # pragma: no cover
            # Ignore cleanup errors to avoid issues during shutdown
            pass

# Register cleanup function to run on process exit
atexit.register(_cleanup_temp_dirs)

def cleanup_temp_instance_dirs():
    """Manually cleanup temporary instance directories (useful for tests)"""
    _cleanup_temp_dirs()

def create_app(config_name: Optional[str] = None):
    if config_name is None:
        config_name = os.environ.get('ENVIRONMENT', 'production')

    # Use temporary directory for instance path to avoid creating app/instance files
    # This ensures database files are created in temporary locations and cleaned up
    instance_path = tempfile.mkdtemp(prefix='flask_instance_')
    _temp_instance_dirs.add(instance_path)
    
    app = Flask(
        __name__,
        instance_path=instance_path,
        instance_relative_config=True,
        static_folder='./assets'
    )
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
    if config_name == 'production':
        from app.config import Config
        config_obj = Config()
    else:
        from app.config import DevelopmentConfig
        config_obj = DevelopmentConfig()
    
    app.config.from_object(config_obj)

    from app.extensions import init_extensions
    init_extensions(app)

    # Add CSRF token to template context
    @app.context_processor
    def inject_csrf_token():
        from flask_wtf.csrf import generate_csrf
        return dict(csrf_token=generate_csrf())

    from app.routes import load_routes
    load_routes(app)

    from app.commands import init_commands
    init_commands(app)

    # Add security headers
    @app.after_request
    def add_security_headers(response):
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        response.headers['X-Permitted-Cross-Domain-Policies'] = 'none'
        # Remove server version information
        response.headers.pop('Server', None)
        return response

    return app

def develop_app():
    config_name = os.environ.get('FLASK_CONFIG', 'development') # pragma: no cover
    app = create_app(config_name) # pragma: no cover

    return app # pragma: no cover