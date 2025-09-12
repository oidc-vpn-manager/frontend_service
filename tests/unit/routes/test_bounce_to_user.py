"""
Test for bounce-to-user page - TDD approach.

This test implements the bounce-to-user functionality for admin-to-user transitions
in service separation deployments.
"""

import pytest
from unittest.mock import patch
from flask import url_for


@pytest.fixture
def app_with_bounce_route(app):
    """Add bounce route registration to test app."""
    from app.routes.root import bounce_to_user
    
    # Register bounce route manually  
    app.add_url_rule('/bounce-to-user', 'bounce_to_user', bounce_to_user, methods=['GET'])
    
    return app


class TestBounceToUser:
    """Test bounce-to-user functionality."""

    def test_bounce_to_user_no_user_url_base(self, client, app_with_bounce_route):
        """Test bounce when no USER_URL_BASE configured - redirects to home."""
        with client.session_transaction() as session:
            session['user'] = {'sub': 'user123', 'email': 'user@example.com'}
        
        response = client.get('/bounce-to-user')
        assert response.status_code == 302
        assert response.headers['Location'] == '/'
    
    @patch('app.routes.root.render_template')
    def test_bounce_to_user_no_target_url(self, mock_render, client, app_with_bounce_route):
        """Test bounce when no target_url specified - uses user base."""
        app_with_bounce_route.config['USER_URL_BASE'] = 'https://user.example.com'
        mock_render.return_value = 'bounce page'
        
        with client.session_transaction() as session:
            session['user'] = {'sub': 'user123', 'email': 'user@example.com'}
        
        response = client.get('/bounce-to-user')
        assert response.status_code == 200
        
        # Verify template called with user base URL
        mock_render.assert_called_once_with(
            'bounce_to_user.html',
            user_url='https://user.example.com',
            site_name='VPN Service'
        )
    
    @patch('app.routes.root.render_template')
    def test_bounce_to_user_valid_target_url(self, mock_render, client, app_with_bounce_route):
        """Test bounce with valid target URL."""
        app_with_bounce_route.config['USER_URL_BASE'] = 'https://user.example.com'
        mock_render.return_value = 'bounce page'
        
        with client.session_transaction() as session:
            session['user'] = {'sub': 'user123', 'email': 'user@example.com'}
        
        response = client.get('/bounce-to-user?target_url=https://user.example.com/profile')
        assert response.status_code == 200
        
        # Verify template called with target URL
        mock_render.assert_called_once_with(
            'bounce_to_user.html',
            user_url='https://user.example.com/profile',
            site_name='VPN Service'
        )
    
    @patch('app.routes.root.render_template')
    def test_bounce_to_user_invalid_target_url(self, mock_render, client, app_with_bounce_route):
        """Test bounce with invalid target URL - falls back to user base."""
        app_with_bounce_route.config['USER_URL_BASE'] = 'https://user.example.com'
        mock_render.return_value = 'bounce page'
        
        with client.session_transaction() as session:
            session['user'] = {'sub': 'user123', 'email': 'user@example.com'}
        
        response = client.get('/bounce-to-user?target_url=https://malicious.example.com/attack')
        assert response.status_code == 200
        
        # Verify template called with user base URL (security fallback)
        mock_render.assert_called_once_with(
            'bounce_to_user.html',
            user_url='https://user.example.com',
            site_name='VPN Service'
        )

    def test_bounce_to_user_login_required(self, client, app_with_bounce_route):
        """Test bounce route requires authentication."""
        response = client.get('/bounce-to-user')
        # Should redirect to login
        assert response.status_code == 302
        assert '/auth/login' in response.headers['Location']


class TestRedirectUserToUserServiceDecorator:
    """Test decorator for redirecting regular users to user service."""

    def test_redirect_user_to_user_service_decorator_exists(self):
        """Test that the redirect_user_to_user_service decorator is available."""
        # This test will initially fail until we implement the decorator
        from app.utils.decorators import redirect_user_to_user_service
        assert callable(redirect_user_to_user_service)

    def test_non_admin_user_redirects_to_bounce_page(self, app_with_bounce_route):
        """Test that non-admin users get redirected to bounce page when on admin service."""
        from app.utils.decorators import redirect_user_to_user_service
        
        # Set up service separation
        app_with_bounce_route.config['USER_URL_BASE'] = 'https://user.example.com'
        
        # Create a test route with the decorator
        @redirect_user_to_user_service
        def test_route():
            return 'admin content'
        
        app_with_bounce_route.add_url_rule('/test-redirect', 'test_redirect', test_route)
        
        with app_with_bounce_route.test_client() as client:
            # Set up non-admin user session
            with client.session_transaction() as session:
                session['user'] = {'sub': 'user123', 'is_admin': False}
            
            response = client.get('/test-redirect')
            assert response.status_code == 302
            # Should redirect to bounce-to-user page
            assert '/bounce-to-user' in response.headers['Location']
            assert 'target_url=https://user.example.com/test-redirect' in response.headers['Location']


    def test_no_user_url_base_no_redirect(self, app_with_bounce_route):
        """Test that no redirect happens when USER_URL_BASE not configured."""
        from app.utils.decorators import redirect_user_to_user_service
        
        # No USER_URL_BASE configured
        
        # Create a test route with the decorator
        @redirect_user_to_user_service
        def test_route():
            return 'normal content'
        
        app_with_bounce_route.add_url_rule('/test-no-config', 'test_no_config', test_route)
        
        with app_with_bounce_route.test_client() as client:
            # Set up regular user session
            with client.session_transaction() as session:
                session['user'] = {'sub': 'user123', 'is_admin': False}
            
            response = client.get('/test-no-config')
            assert response.status_code == 200
            assert response.data == b'normal content'