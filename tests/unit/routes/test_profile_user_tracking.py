"""
Unit tests for user tracking in profile certificate generation.

These tests verify that the profile route correctly passes user_id 
when requesting certificate signatures.
"""

import pytest
from flask import Flask, session
from unittest.mock import MagicMock, patch

from app.routes.profile import bp as profile_blueprint  
from app.routes.auth import bp as auth_blueprint
from app.extensions import db
from app.models import DownloadToken # Needed for db.create_all

@pytest.fixture
def app():
    """Provides a test app with the necessary config and extensions."""
    app = Flask(__name__)
    app.config.update({
        "TESTING": True,
        "SECRET_KEY": "test-secret",
        "WTF_CSRF_ENABLED": False,
        "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
        "SQLALCHEMY_TRACK_MODIFICATIONS": False
    })
    
    # Initialize the database with this app instance
    db.init_app(app)
    
    app.register_blueprint(profile_blueprint)
    app.register_blueprint(auth_blueprint)
    
    # Create the database tables needed for the test
    with app.app_context():
        db.create_all()

    return app
