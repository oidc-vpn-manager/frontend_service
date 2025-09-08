"""
Unit tests for health route.
"""

import pytest
from flask import Flask
from unittest.mock import patch, MagicMock
from app.routes.health import bp as health_bp


class TestHealthRoute:
    """Test suite for health endpoint."""

    @patch('app.routes.health.db')
    def test_health_endpoint_returns_ok(self, mock_db, app):
        """Test that health endpoint returns 200 OK with correct JSON."""
        # Mock successful database connection
        mock_session = MagicMock()
        mock_db.session = mock_session
        mock_session.execute.return_value = None  # Successful execution
        
        with app.test_client() as client:
            response = client.get('/health')
            
            assert response.status_code == 200
            assert response.is_json
            data = response.get_json()
            assert data['status'] == 'healthy'
            assert data['service'] == 'frontend'
            assert data['database'] == 'connected'

    @patch('app.routes.health.db')
    def test_health_endpoint_content_type(self, mock_db, app):
        """Test that health endpoint returns correct content type."""
        # Mock successful database connection
        mock_session = MagicMock()
        mock_db.session = mock_session
        mock_session.execute.return_value = None
        
        with app.test_client() as client:
            response = client.get('/health')
            
            assert response.content_type == 'application/json'

    def test_health_endpoint_method_not_allowed(self, app):
        """Test that health endpoint only accepts GET requests."""
        with app.test_client() as client:
            response = client.post('/health')
            assert response.status_code == 405  # Method Not Allowed

    @patch('app.routes.health.db')
    def test_health_endpoint_database_error(self, mock_db, app):
        """Test that health endpoint returns 503 when database is unavailable."""
        # Mock database connection failure
        mock_session = MagicMock()
        mock_db.session = mock_session
        mock_session.execute.side_effect = Exception("Database connection failed")
        
        with app.test_client() as client:
            response = client.get('/health')
            
            assert response.status_code == 503
            assert response.is_json
            data = response.get_json()
            assert data['status'] == 'unhealthy'
            assert data['database'] == 'disconnected'

