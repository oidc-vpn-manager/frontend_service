from flask import Flask, request, redirect, url_for, current_app
from app.utils import render_template
from flask_swagger_ui import get_swaggerui_blueprint

def load_routes(app: Flask):
    @app.errorhandler(400)
    def bad_request(e):
        return render_template('status/400.html', error_description=e.description), 400

    @app.errorhandler(403)
    def forbidden(e):
        # Check if this is an admin route being accessed on user service
        admin_url_base = current_app.config.get('ADMIN_URL_BASE')
        if admin_url_base and request.path.startswith('/admin/'):
            # Redirect admin routes to bounce page with target URL
            target_url = admin_url_base.rstrip('/') + request.path
            if request.query_string:
                target_url += '?' + request.query_string.decode('utf-8')
            return redirect(url_for('root.bounce_to_admin', target_url=target_url))
        
        return render_template('status/403.html'), 403
    
    @app.errorhandler(404)
    def page_not_found(e):
        return render_template('status/404.html'), 404
    
    @app.errorhandler(500)
    def internal_server_error(e):
        return render_template('status/500.html'), 500 # pragma: no coverage

    from .root import bp as root_bp
    app.register_blueprint(root_bp)

    from .auth import bp as auth_bp
    app.register_blueprint(auth_bp)

    SWAGGER_URL = '/api/docs'
    API_URL = '/assets/swagger/v1.yaml'
    swaggerui_blueprint = get_swaggerui_blueprint(
        SWAGGER_URL,
        API_URL,
        config={'app_name': f"{app.config.get('SITE_NAME')} API"}
    )
    app.register_blueprint(swaggerui_blueprint)

    from .api import bp as api_bp
    app.register_blueprint(api_bp)

    from .profile import bp as profile_bp
    app.register_blueprint(profile_bp)
    
    from .admin import bp as admin_bp
    app.register_blueprint(admin_bp)
    
    from .health import bp as health_bp
    app.register_blueprint(health_bp)
    
    from .crl import bp as crl_bp
    app.register_blueprint(crl_bp)
    
    from .certificates import bp as certificates_bp
    app.register_blueprint(certificates_bp)
    
    from .download import bp as download_bp
    app.register_blueprint(download_bp)
    
    # Register test-only routes in development environments
    import os
    if (app.config.get('ENVIRONMENT') == 'development' or 
        app.config.get('FLASK_ENV') == 'development' or 
        os.environ.get('FLASK_ENV') == 'development'):
        from .test_auth import bp as test_auth_bp
        app.register_blueprint(test_auth_bp)