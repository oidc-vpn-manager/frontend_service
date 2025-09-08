"""
Test tracing utility functions.
"""

import pytest
import logging
from flask import Flask
from app.utils.tracing import trace


@pytest.fixture
def app():
    """Create test Flask app with tracing enabled."""
    app = Flask(__name__)
    app.config.update({
        "TESTING": True,
        "TRACE": True  # Enable tracing
    })
    # Set logger level to DEBUG to capture debug messages
    app.logger.setLevel(logging.DEBUG)
    return app


def test_trace_with_variables(app, caplog):
    """Test tracing function with variables provided."""
    with caplog.at_level(logging.DEBUG):
        with app.app_context():
            test_variables = {'user_id': 'test123', 'action': 'login'}
            trace(app, 'test.function', test_variables)
            
            # Check that debug message was logged with variables
            assert 'test.function({' in caplog.text
            assert 'user_id' in caplog.text
            assert 'test123' in caplog.text


def test_trace_without_variables(app, caplog):
    """Test tracing function without variables (line 8)."""
    with caplog.at_level(logging.DEBUG):
        with app.app_context():
            trace(app, 'test.function.no_vars')
            
            # Check that debug message was logged without variables
            assert 'test.function.no_vars()' in caplog.text


def test_trace_disabled(caplog):
    """Test tracing function when TRACE is disabled."""
    app = Flask(__name__)
    app.config.update({
        "TESTING": True,
        "TRACE": False  # Disable tracing
    })
    app.logger.setLevel(logging.DEBUG)
    
    with caplog.at_level(logging.DEBUG):
        with app.app_context():
            trace(app, 'test.function', {'test': 'data'})
            
            # Should not log anything when tracing is disabled
            assert 'test.function' not in caplog.text


def test_trace_empty_variables_dict(app, caplog):
    """Test tracing function with empty variables dict."""
    with caplog.at_level(logging.DEBUG):
        with app.app_context():
            trace(app, 'test.empty.vars', {})
            
            # Should trigger the else branch (line 8) even with empty dict
            assert 'test.empty.vars()' in caplog.text