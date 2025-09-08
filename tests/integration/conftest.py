"""
Fixtures for integration tests.
"""

import pytest

import os, sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app
from app.app import cleanup_temp_instance_dirs
from app.extensions import db

@pytest.fixture(scope='function')
def app():
    """
    Creates a new application instance for a test module.
    Using 'development' config which uses an in-memory SQLite DB.
    """
    # Set test keys for secure configuration
    os.environ['FLASK_SECRET_KEY'] = 'test-secret-key-for-integration-tests-only'
    os.environ['FERNET_ENCRYPTION_KEY'] = 'YenxIAHqvrO7OHbNXvzAxEhthHCaitvnV9CALkQvvCc='
    
    app = create_app('development')
    app.config.update({
        "TESTING": True,
        "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
        "WTF_CSRF_ENABLED": False,
    })

    with app.app_context():
        db.create_all()

    yield app

    with app.app_context():
        db.session.remove()
        db.drop_all()
    # Clean up temporary instance directories
    cleanup_temp_instance_dirs()

@pytest.fixture(scope='function')
def client(app):
    """A test client for the app."""
    return app.test_client()