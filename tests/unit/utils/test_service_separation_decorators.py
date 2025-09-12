"""
Tests for service separation decorators.
"""

import pytest
from unittest.mock import patch, MagicMock
from flask import Flask, Blueprint, url_for, request, session
from app.utils.decorators import (
    admin_service_only,
    user_service_only,
    admin_service_only_api,
    user_service_only_api,
    redirect_admin_to_admin_service
)


@pytest.fixture
def test_app():
    """Create test Flask app with service separation decorators."""
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'test-secret'
    app.config['TESTING'] = True
    
    # Create test blueprint
    bp = Blueprint('test_sep', __name__)
    
    @bp.route('/admin-only')
    @admin_service_only
    def admin_only_route():
        return 'admin content'
    
    @bp.route('/user-only')  
    @user_service_only
    def user_only_route():
        return 'user content'
    
    @bp.route('/redirect-admin')
    @redirect_admin_to_admin_service
    def redirect_admin_route():
        return 'shared content'
    
    @bp.route('/api-admin-only')
    @admin_service_only_api
    def api_admin_only_route():
        return 'api admin content'
    
    @bp.route('/api-user-only')  
    @user_service_only_api
    def api_user_only_route():
        return 'api user content'
    
    app.register_blueprint(bp)
    
    with app.app_context():
        yield app


class TestAdminServiceOnly:
    """Test admin_service_only decorator."""
    
    def test_admin_route_allowed_when_no_user_url_base(self, test_app):
        """Admin routes work normally when USER_URL_BASE not configured."""
        with test_app.test_client() as client:
            # No USER_URL_BASE configured - should allow access
            response = client.get('/admin-only')
            assert response.status_code == 200
            assert response.data == b'admin content'
    
    def test_admin_route_forbidden_when_admin_url_base_configured(self, test_app):
        """Admin routes return 403 when ADMIN_URL_BASE configured (user service)."""
        test_app.config['ADMIN_URL_BASE'] = 'http://admin.example.com'
        
        with test_app.test_client() as client:
            response = client.get('/admin-only')
            assert response.status_code == 403
    
    def test_admin_route_logs_warning_on_user_service(self, test_app, caplog):
        """Admin route access on user service logs warning."""
        test_app.config['ADMIN_URL_BASE'] = 'http://admin.example.com'
        
        with test_app.test_client() as client:
            response = client.get('/admin-only')
            assert response.status_code == 403
            assert 'Admin route accessed on user service: /admin-only' in caplog.text


class TestUserServiceOnly:
    """Test user_service_only decorator."""
    
    def test_user_route_allowed_when_no_admin_url_base(self, test_app):
        """User routes work normally when ADMIN_URL_BASE not configured.""" 
        with test_app.test_client() as client:
            response = client.get('/user-only')
            assert response.status_code == 200
            assert response.data == b'user content'
    
    def test_user_route_redirects_when_user_url_base_configured(self, test_app):
        """User routes redirect when USER_URL_BASE configured (admin service)."""
        test_app.config['USER_URL_BASE'] = 'http://user.example.com'
        
        with test_app.test_client() as client:
            response = client.get('/user-only')
            assert response.status_code == 301
            assert response.headers['Location'] == 'http://user.example.com/user-only'
    




class TestServiceSeparationIntegration:
    """Integration tests for service separation behavior."""
    
    def test_full_user_service_deployment_scenario(self, test_app):
        """Test complete user service deployment configuration."""
        # Configure as user service (points to admin service)
        test_app.config['ADMIN_URL_BASE'] = 'http://admin.vpn.example.com'
        
        with test_app.test_client() as client:
            # User routes should work
            response = client.get('/user-only')
            assert response.status_code == 200
            
            # Admin routes should be forbidden
            response = client.get('/admin-only')
            assert response.status_code == 403
            
            # Admin users should be redirected to admin service
            with client.session_transaction() as sess:
                sess['user'] = {'sub': 'admin123', 'is_admin': True, 'is_system_admin': False, 'is_auditor': False}
            
            response = client.get('/redirect-admin')
            assert response.status_code == 302
    
    def test_full_admin_service_deployment_scenario(self, test_app):
        """Test complete admin service deployment configuration."""
        # Configure as admin service (points to user service)  
        test_app.config['USER_URL_BASE'] = 'http://vpn.example.com'
        
        with test_app.test_client() as client:
            # Admin routes should work
            response = client.get('/admin-only')
            assert response.status_code == 200
            assert response.data == b'admin content'
            
            # User routes should redirect to user service
            response = client.get('/user-only')
            assert response.status_code == 301
            assert response.headers['Location'] == 'http://vpn.example.com/user-only'
    
    def test_no_separation_deployment_scenario(self, test_app):
        """Test deployment with no service separation (current behavior)."""
        # No separation URLs configured
        
        with test_app.test_client() as client:
            # All routes should work normally
            response = client.get('/admin-only')
            assert response.status_code == 200
            
            response = client.get('/user-only')
            assert response.status_code == 200
            
            # No redirects for admin users
            with client.session_transaction() as sess:
                sess['user'] = {'sub': 'admin123', 'is_admin': True, 'is_system_admin': False, 'is_auditor': False}
            
            response = client.get('/redirect-admin')
            assert response.status_code == 200

class TestAPIServiceSeparationDecorators:
    """Test API-specific service separation decorators."""
    
    def test_api_admin_service_only_allowed_when_no_admin_url_base(self, test_app):
        """API admin routes work normally when ADMIN_URL_BASE not configured."""
        with test_app.test_client() as client:
            response = client.get("/api-admin-only")
            assert response.status_code == 200
            assert response.data == b"api admin content"
    
    def test_api_admin_service_only_forbidden_when_admin_url_base_configured(self, test_app):
        """API admin routes return 403 when ADMIN_URL_BASE configured (user service)."""
        test_app.config["ADMIN_URL_BASE"] = "http://admin.example.com"
        
        with test_app.test_client() as client:
            response = client.get("/api-admin-only")
            assert response.status_code == 403
    
    def test_api_user_service_only_allowed_when_no_user_url_base(self, test_app):
        """API user routes work normally when USER_URL_BASE not configured."""
        with test_app.test_client() as client:
            response = client.get("/api-user-only")
            assert response.status_code == 200
            assert response.data == b"api user content"
    
    def test_api_user_service_only_redirects_when_user_url_base_configured(self, test_app):
        """API user routes redirect when USER_URL_BASE configured (admin service)."""
        test_app.config["USER_URL_BASE"] = "http://user.example.com"
        
        with test_app.test_client() as client:
            response = client.get("/api-user-only")
            assert response.status_code == 301
            assert response.headers["Location"] == "http://user.example.com/api-user-only"
    
    def test_api_user_service_only_redirects_with_query_string(self, test_app):
        """API user routes redirect preserves query parameters."""
        test_app.config["USER_URL_BASE"] = "http://user.example.com"
        
        with test_app.test_client() as client:
            response = client.get("/api-user-only?param=value&other=test")
            assert response.status_code == 301
            assert response.headers["Location"] == "http://user.example.com/api-user-only?param=value&other=test"

