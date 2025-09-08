"""
Unit tests for the custom render_template wrapper.
"""

import sys
import pytest
import logging
from flask import Flask
from unittest.mock import MagicMock

# We still import the function to call it in the test
from app.utils import render_template

def test_render_template_wrapper(monkeypatch, caplog):
    """
    Tests that the render_template wrapper logs the call and
    invokes the parent render_template with the correct context.
    """
    # Arrange
    app = Flask(__name__)
    app.config['TESTING'] = True
    app.config['TRACE'] = True  # Enable tracing for the test
    
    # Get the actual module object from Python's system cache.
    render_template_module = sys.modules['app.utils.render_template']

    # Patch the parent Flask render_template function within that module's namespace
    mock_parent_render = MagicMock(return_value="mocked html")
    monkeypatch.setattr(
        render_template_module,
        'parent_render_template',
        mock_parent_render
    )
    
    # Set the logger to capture DEBUG level messages for the test
    caplog.set_level(logging.DEBUG)
    
    with app.app_context():
        # Need to create a request context to access session
        with app.test_request_context():
            # Act
            template_name = 'test.html'
            context_args = {'foo': 'bar'}
            render_template(template_name, **context_args)

        # Assert
        # 1. Check that the logger was called with trace format
        expected_trace = f"utils.render_template.render_template({{'template': '{template_name}', 'kargs': {context_args}}})"
        assert expected_trace in caplog.text
        
        # 2. Check that the parent function was called
        mock_parent_render.assert_called_once()
        
        # 3. Verify the arguments passed to the parent function
        call_args, call_kwargs = mock_parent_render.call_args
        assert call_args[0] == template_name
        assert call_kwargs['foo'] == 'bar'
        assert 'current_app' in call_kwargs