"""
Unit tests for logging configuration functionality.

These tests verify the JSON formatter, logging filters, and configuration setup.
"""

import pytest
import json
import logging
import sys
from unittest.mock import patch, MagicMock
from app.utils.logging_config import (
    JSONFormatter, SecurityEventFilter, ApplicationEventFilter,
    AccessLogFilter, setup_logging, add_request_id_middleware
)


class TestJSONFormatterEdgeCases:
    """Test JSONFormatter edge cases and error handling."""

    def test_format_outside_request_context(self):
        """Test JSONFormatter outside of request context (line 66)."""
        formatter = JSONFormatter()
        logger = logging.getLogger('test')

        record = logger.makeRecord(
            name='test_logger',
            level=logging.INFO,
            fn='test.py',
            lno=42,
            msg='Test message outside request context',
            args=(),
            exc_info=None
        )

        # Should not raise an exception even outside request context
        formatted = formatter.format(record)
        log_data = json.loads(formatted)

        # Basic structure should still be present
        assert log_data['level'] == 'INFO'
        assert log_data['message'] == 'Test message outside request context'
        assert log_data['service'] == 'openvpn-manager-frontend'
        # Request context fields should not be present
        assert 'request_context' not in log_data

    def test_format_with_exception_outside_app_context(self):
        """Test JSONFormatter with exception outside application context."""
        formatter = JSONFormatter()
        logger = logging.getLogger('test')

        # Create an exception to log
        try:
            raise ValueError("Test exception for logging")
        except ValueError:
            exc_info = sys.exc_info()

        record = logger.makeRecord(
            name='test_logger',
            level=logging.ERROR,
            fn='test.py',
            lno=42,
            msg='Error with exception outside app context',
            args=(),
            exc_info=exc_info
        )

        # Format outside Flask application context - Flask handles this gracefully
        formatted = formatter.format(record)
        log_data = json.loads(formatted)

        # Should still format successfully
        assert log_data['level'] == 'ERROR'
        assert log_data['message'] == 'Error with exception outside app context'
        # Exception info should be present but without traceback (since no Flask context)
        assert 'exception' in log_data
        assert log_data['exception']['type'] == 'ValueError'
        assert log_data['exception']['message'] == 'Test exception for logging'
        assert log_data['exception']['traceback'] is None  # No traceback outside app context

    def test_format_with_malformed_exc_info(self):
        """Test JSONFormatter with malformed exception info (lines 77-79)."""
        formatter = JSONFormatter()
        logger = logging.getLogger('test')

        record = logger.makeRecord(
            name='test_logger',
            level=logging.ERROR,
            fn='test.py',
            lno=42,
            msg='Error with malformed exc_info',
            args=(),
            exc_info=None
        )

        # Set malformed exc_info that will trigger the AttributeError/TypeError handler
        # Use an object that doesn't have __name__ attribute to trigger AttributeError
        malformed_exc_type = "not_an_exception_type"
        record.exc_info = (malformed_exc_type, Exception("test"), None)

        formatted = formatter.format(record)
        log_data = json.loads(formatted)

        # Should handle malformed exc_info gracefully
        assert 'exception' in log_data
        assert log_data['exception']['type'] == 'UnknownException'
        assert log_data['exception']['message'] == 'Exception information not available'
        assert log_data['exception']['traceback'] is None

    def test_format_with_invalid_exc_info_none_tuple(self):
        """Test JSONFormatter with (None, None, None) exc_info."""
        formatter = JSONFormatter()
        logger = logging.getLogger('test')

        record = logger.makeRecord(
            name='test_logger',
            level=logging.ERROR,
            fn='test.py',
            lno=42,
            msg='Error with None exc_info',
            args=(),
            exc_info=(None, None, None)
        )

        formatted = formatter.format(record)
        log_data = json.loads(formatted)

        # Should not include exception info for (None, None, None)
        assert 'exception' not in log_data


class TestLoggingFilters:
    """Test logging filter classes."""

    def test_security_event_filter(self):
        """Test SecurityEventFilter allows only security events."""
        filter_obj = SecurityEventFilter()

        # Create mock records
        security_record = MagicMock()
        security_record.name = 'security_events'

        other_record = MagicMock()
        other_record.name = 'app.routes'

        # Security events should pass
        assert filter_obj.filter(security_record) is True

        # Other events should not pass
        assert filter_obj.filter(other_record) is False

    def test_application_event_filter(self):
        """Test ApplicationEventFilter excludes security and gunicorn events."""
        filter_obj = ApplicationEventFilter()

        # Create mock records
        app_record = MagicMock()
        app_record.name = 'app.routes'

        security_record = MagicMock()
        security_record.name = 'security_events'

        gunicorn_record = MagicMock()
        gunicorn_record.name = 'gunicorn.access'

        # App events should pass
        assert filter_obj.filter(app_record) is True

        # Security events should not pass
        assert filter_obj.filter(security_record) is False

        # Gunicorn events should not pass
        assert filter_obj.filter(gunicorn_record) is False

    def test_access_log_filter(self):
        """Test AccessLogFilter allows only gunicorn.access events (line 115)."""
        filter_obj = AccessLogFilter()

        # Create mock records
        access_record = MagicMock()
        access_record.name = 'gunicorn.access'

        other_record = MagicMock()
        other_record.name = 'app.routes'

        gunicorn_error_record = MagicMock()
        gunicorn_error_record.name = 'gunicorn.error'

        # Access logs should pass
        assert filter_obj.filter(access_record) is True

        # Other logs should not pass
        assert filter_obj.filter(other_record) is False
        assert filter_obj.filter(gunicorn_error_record) is False


class TestLoggingSetup:
    """Test logging setup and configuration."""

    @patch('app.utils.logging_config.logging.config.dictConfig')
    def test_setup_logging_development_mode(self, mock_dict_config):
        """Test setup_logging with development configuration."""
        app_config = {
            'ENVIRONMENT': 'development'
        }

        setup_logging(app_config)

        # Verify dictConfig was called
        mock_dict_config.assert_called_once()
        config = mock_dict_config.call_args[0][0]

        # Check development-specific settings
        assert 'console' in config['handlers']
        assert config['handlers']['console']['level'] == 'DEBUG'

        # Check that console handler is added to loggers in development
        assert 'console' in config['loggers']['flask.app']['handlers']
        assert 'console' in config['loggers']['app']['handlers']

    @patch('app.utils.logging_config.logging.config.dictConfig')
    def test_setup_logging_production_mode(self, mock_dict_config):
        """Test setup_logging with production configuration."""
        app_config = {
            'ENVIRONMENT': 'production'
        }

        setup_logging(app_config)

        mock_dict_config.assert_called_once()
        config = mock_dict_config.call_args[0][0]

        # In production, application events should be WARNING level
        assert config['handlers']['application_events']['level'] == 'WARNING'
        assert config['loggers']['flask.app']['level'] == 'WARNING'

    @patch('app.utils.logging_config.logging.config.dictConfig')
    def test_setup_logging_no_config(self, mock_dict_config):
        """Test setup_logging with no app config."""
        setup_logging()

        mock_dict_config.assert_called_once()
        config = mock_dict_config.call_args[0][0]

        # Should default to INFO level
        assert config['handlers']['application_events']['level'] == 'INFO'


class TestRequestIdMiddleware:
    """Test request ID middleware functionality."""

    def test_add_request_id_middleware(self):
        """Test that request ID middleware is properly added to Flask app."""
        mock_app = MagicMock()

        add_request_id_middleware(mock_app)

        # Verify before_request and after_request were called
        mock_app.before_request.assert_called_once()
        mock_app.after_request.assert_called_once()

    def test_request_id_generation_and_response_header(self):
        """Test request ID generation and response header setting."""
        from flask import Flask, g

        app = Flask(__name__)
        add_request_id_middleware(app)

        @app.route('/test')
        def test_route():
            # Request ID should be available in g
            assert hasattr(g, 'request_id')
            assert g.request_id is not None
            return 'test'

        with app.test_client() as client:
            response = client.get('/test')

            # Response should include X-Request-ID header
            assert 'X-Request-ID' in response.headers
            assert response.headers['X-Request-ID'] is not None




if __name__ == '__main__':
    pytest.main([__file__])