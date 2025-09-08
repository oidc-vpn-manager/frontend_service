"""
Unit tests for the application factory.
"""

import pytest
from flask import Flask
from unittest.mock import MagicMock

from app import create_app

@pytest.fixture
def mock_dependencies(monkeypatch):
    """Mocks dependencies of the create_app factory."""
    mock_init_extensions = MagicMock()
    mock_load_routes = MagicMock()
    
    # Set required security keys for configuration
    monkeypatch.setenv('FLASK_SECRET_KEY', 'test-secret-key-for-unit-tests-only')
    monkeypatch.setenv('FERNET_ENCRYPTION_KEY', 'test-encryption-key-for-unit-tests-only')
    
    # Patch the functions in the modules where they are defined
    monkeypatch.setattr('app.extensions.init_extensions', mock_init_extensions)
    monkeypatch.setattr('app.routes.load_routes', mock_load_routes)
    
    return mock_init_extensions, mock_load_routes

def test_create_app_production(mock_dependencies):
    """
    Tests that create_app loads the production config and initializes dependencies.
    """
    # Arrange
    mock_init_extensions, mock_load_routes = mock_dependencies
    
    # Act
    app = create_app()

    # Assert
    assert isinstance(app, Flask)
    assert app.config['DEBUG'] is False
    assert app.config['TESTING'] is False
    
    mock_init_extensions.assert_called_once_with(app)
    mock_load_routes.assert_called_once_with(app)

def test_create_app_development(mock_dependencies):
    """
    Tests that create_app loads the development config by default.
    """
    # Arrange
    mock_init_extensions, mock_load_routes = mock_dependencies
    app = create_app(config_name='develop')

    # Assert
    assert isinstance(app, Flask)
    assert app.config['DEBUG'] is True
    assert app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] is True
    
    mock_init_extensions.assert_called_once_with(app)
    mock_load_routes.assert_called_once_with(app)