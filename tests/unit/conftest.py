"""
Fixtures for unit tests.
"""

import pytest
import os, sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app
from app.app import cleanup_temp_instance_dirs


@pytest.fixture(scope='function')
def app():
    """
    Creates a test Flask application instance for unit tests.
    Uses development config for isolated testing.
    """
    # Set test keys for secure configuration
    os.environ['FLASK_SECRET_KEY'] = 'test-secret-key-for-unit-tests-only'
    os.environ['FERNET_ENCRYPTION_KEY'] = 'YenxIAHqvrO7OHbNXvzAxEhthHCaitvnV9CALkQvvCc='
    
    app = create_app('development')
    app.config.update({
        "TESTING": True,
        "WTF_CSRF_ENABLED": False,
    })

    yield app
    # Clean up temporary instance directories
    cleanup_temp_instance_dirs()