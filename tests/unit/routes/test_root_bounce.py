"""
Tests for root bounce routes coverage.
"""

import pytest
from unittest.mock import patch


@pytest.fixture
def app_with_bounce_route(app):
    """Add bounce route registration to test app."""
    from app.routes.root import bounce_to_admin
    
    # Register bounce route manually  
    app.add_url_rule('/bounce-to-admin', 'bounce_to_admin', bounce_to_admin, methods=['GET'])
    
    return app


class TestBounceToAdmin:
    """Test bounce_to_admin route coverage."""
    
    def test_bounce_to_admin_no_admin_url_base(self, client, app_with_bounce_route):
        """Test bounce when no ADMIN_URL_BASE configured - redirects to home."""
        with client.session_transaction() as session:
            session['user'] = {'sub': 'user123', 'email': 'user@example.com'}
        
        response = client.get('/bounce-to-admin')
        assert response.status_code == 302
        assert response.headers['Location'] == '/'
    
    @patch('app.routes.root.render_template')
    def test_bounce_to_admin_no_target_url(self, mock_render, client, app_with_bounce_route):
        """Test bounce when no target_url specified - uses admin base."""
        app_with_bounce_route.config['ADMIN_URL_BASE'] = 'https://admin.example.com'
        mock_render.return_value = 'bounce page'
        
        with client.session_transaction() as session:
            session['user'] = {'sub': 'user123', 'email': 'user@example.com'}
        
        response = client.get('/bounce-to-admin')
        assert response.status_code == 200
        
        # Verify template called with admin base URL
        mock_render.assert_called_once_with(
            'bounce_to_admin.html',
            admin_url='https://admin.example.com',
            site_name='VPN Service'
        )
    
    @patch('app.routes.root.render_template')
    def test_bounce_to_admin_valid_target_url(self, mock_render, client, app_with_bounce_route):
        """Test bounce with valid target URL."""
        app_with_bounce_route.config['ADMIN_URL_BASE'] = 'https://admin.example.com'
        mock_render.return_value = 'bounce page'
        
        with client.session_transaction() as session:
            session['user'] = {'sub': 'user123', 'email': 'user@example.com'}
        
        response = client.get('/bounce-to-admin?target_url=https://admin.example.com/certificates')
        assert response.status_code == 200
        
        # Verify template called with target URL
        mock_render.assert_called_once_with(
            'bounce_to_admin.html',
            admin_url='https://admin.example.com/certificates',
            site_name='VPN Service'
        )
    
    @patch('app.routes.root.render_template')
    def test_bounce_to_admin_invalid_target_url(self, mock_render, client, app_with_bounce_route):
        """Test bounce with invalid target URL - falls back to admin base."""
        app_with_bounce_route.config['ADMIN_URL_BASE'] = 'https://admin.example.com'
        mock_render.return_value = 'bounce page'
        
        with client.session_transaction() as session:
            session['user'] = {'sub': 'user123', 'email': 'user@example.com'}
        
        response = client.get('/bounce-to-admin?target_url=https://malicious.example.com/attack')
        assert response.status_code == 200
        
        # Verify template called with admin base URL (security fallback)
        mock_render.assert_called_once_with(
            'bounce_to_admin.html',
            admin_url='https://admin.example.com',
            site_name='VPN Service'
        )