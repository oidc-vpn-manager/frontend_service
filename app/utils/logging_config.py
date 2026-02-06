"""
Logging Configuration for OpenVPN Manager Frontend

This module configures structured JSON logging for the application, with separate
loggers for security events, application events, and access logs. All logs are
formatted for SIEM compatibility.
"""

import logging
import logging.config
import json
import sys
from datetime import datetime, timezone
from typing import Dict, Any
from flask import request, g, session


class JSONFormatter(logging.Formatter):
    """
    Custom formatter that outputs logs in JSON format suitable for SIEM ingestion.
    """

    def format(self, record):
        """Format log record as JSON."""

        # Base log structure
        log_entry = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
            'service': 'oidc-vpn-manager-frontend',
            'version': '1.0',
        }

        # Add thread/process info
        if hasattr(record, 'process') and record.process:
            log_entry['process_id'] = record.process
        if hasattr(record, 'thread') and record.thread:
            log_entry['thread_id'] = record.thread

        # Add request context if available
        try:
            if request:
                log_entry['request_context'] = {
                    'method': request.method,
                    'path': request.path,
                    'remote_addr': request.remote_addr,
                    'user_agent': request.headers.get('User-Agent', ''),
                }

                # Add request ID if available
                if hasattr(g, 'request_id'):
                    log_entry['request_id'] = g.request_id

                # Add user info if available in session
                if session and 'user' in session:
                    user_info = session['user']
                    log_entry['user_context'] = {
                        'user_id': user_info.get('sub', ''),
                        'user_email': user_info.get('email', ''),
                        'user_groups': user_info.get('groups', []),
                    }
        except RuntimeError: # pragma: no cover
            ## PRAGMA-NO-COVER Exception; JS 2025-09-15 Outside request context is expected behavior
            pass

        # Add exception info if present
        if record.exc_info and record.exc_info != (None, None, None):
            try:
                exc_type, exc_value, exc_traceback = record.exc_info

                # Only include stack traces in development environments
                # Note: Flask provides built-in protection for accessing current_app outside application context
                include_traceback = False
                from flask import current_app
                if current_app and current_app.config.get('ENVIRONMENT') == 'development':
                    include_traceback = True

                log_entry['exception'] = {
                    'type': exc_type.__name__ if exc_type else None,
                    'message': str(exc_value) if exc_value else None,
                    'traceback': self.formatException(record.exc_info) if (exc_traceback and include_traceback) else None
                }
            except (AttributeError, TypeError):
                # Handle cases where exc_info is not a proper tuple
                log_entry['exception'] = {
                    'type': 'UnknownException',
                    'message': 'Exception information not available',
                    'traceback': None
                }

        # Add custom fields from the log record
        for key, value in record.__dict__.items():
            if key not in ['name', 'msg', 'args', 'levelname', 'levelno', 'pathname',
                          'filename', 'module', 'lineno', 'funcName', 'created',
                          'msecs', 'relativeCreated', 'thread', 'threadName',
                          'processName', 'process', 'exc_info', 'exc_text',
                          'stack_info', 'getMessage']:
                log_entry[key] = value

        return json.dumps(log_entry, default=str)


class SecurityEventFilter(logging.Filter):
    """Filter that only allows security events through."""

    def filter(self, record):
        return record.name == 'security_events'


class ApplicationEventFilter(logging.Filter):
    """Filter that allows application events but excludes security events."""

    def filter(self, record):
        return record.name != 'security_events' and not record.name.startswith('gunicorn')


class AccessLogFilter(logging.Filter):
    """Filter for access logs."""

    def filter(self, record):
        return record.name.startswith('gunicorn.access')


def setup_logging(app_config: Dict[str, Any] = None) -> None:
    """
    Set up structured logging configuration.

    Args:
        app_config: Flask app configuration dict
    """

    # Determine log level from config
    log_level = 'INFO'
    if app_config:
        if app_config.get('ENVIRONMENT') == 'development':
            log_level = 'DEBUG'
        elif app_config.get('ENVIRONMENT') == 'production':
            log_level = 'WARNING'

    # Logging configuration
    config = {
        'version': 1,
        'disable_existing_loggers': False,
        'formatters': {
            'json': {
                '()': JSONFormatter,
            },
            'simple': {
                'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            }
        },
        'filters': {
            'security_events': {
                '()': SecurityEventFilter,
            },
            'application_events': {
                '()': ApplicationEventFilter,
            },
            'access_logs': {
                '()': AccessLogFilter,
            }
        },
        'handlers': {
            'security_events': {
                'class': 'logging.StreamHandler',
                'stream': sys.stdout,
                'formatter': 'json',
                'filters': ['security_events'],
                'level': 'INFO',
            },
            'application_events': {
                'class': 'logging.StreamHandler',
                'stream': sys.stdout,
                'formatter': 'json',
                'filters': ['application_events'],
                'level': log_level,
            },
            'access_logs': {
                'class': 'logging.StreamHandler',
                'stream': sys.stdout,
                'formatter': 'json',
                'filters': ['access_logs'],
                'level': 'INFO',
            },
            'console': {
                'class': 'logging.StreamHandler',
                'stream': sys.stdout,
                'formatter': 'simple',
                'level': 'ERROR',  # Only show errors on console in non-dev
            }
        },
        'loggers': {
            'security_events': {
                'handlers': ['security_events'],
                'level': 'INFO',
                'propagate': False,
            },
            'flask.app': {
                'handlers': ['application_events'],
                'level': log_level,
                'propagate': False,
            },
            'gunicorn.access': {
                'handlers': ['access_logs'],
                'level': 'INFO',
                'propagate': False,
            },
            'gunicorn.error': {
                'handlers': ['application_events'],
                'level': 'INFO',
                'propagate': False,
            },
            'app': {
                'handlers': ['application_events'],
                'level': log_level,
                'propagate': False,
            },
            'werkzeug': {
                'handlers': ['application_events'],
                'level': 'WARNING',  # Reduce werkzeug noise
                'propagate': False,
            }
        },
        'root': {
            'handlers': ['console'],
            'level': 'ERROR',
        }
    }

    # In development, also log to console with simple format
    if app_config and app_config.get('ENVIRONMENT') == 'development':
        config['handlers']['console']['level'] = 'DEBUG'
        config['loggers']['flask.app']['handlers'].append('console')
        config['loggers']['app']['handlers'].append('console')

    logging.config.dictConfig(config)


def add_request_id_middleware(app):
    """
    Add middleware to generate and track request IDs for correlation.
    """
    import uuid

    @app.before_request
    def before_request():
        g.request_id = str(uuid.uuid4())

    @app.after_request
    def after_request(response):
        if hasattr(g, 'request_id'):
            response.headers['X-Request-ID'] = g.request_id
        return response


def configure_security_logging(app):
    """
    Configure security logging for the Flask application.

    Args:
        app: Flask application instance
    """

    # Set up logging configuration
    setup_logging(app.config)

    # Add request ID middleware
    add_request_id_middleware(app)

    # Log application startup
    from app.utils.security_logging import security_logger

    def log_startup():
        config_summary = {
            'environment': app.config.get('ENVIRONMENT', 'unknown'),
            'debug': app.config.get('DEBUG', False),
            'testing': app.config.get('TESTING', False),
            'force_https': app.config.get('FORCE_HTTPS', False),
        }

        security_logger.log_system_startup(
            version='1.0',
            config_details=config_summary
        )

    # Log startup immediately
    log_startup()

    # Log unhandled exceptions
    @app.errorhandler(500)
    def log_internal_error(error): # pragma: no cover
        ## PRAGMA-NO-COVER Exception; JS 2025-09-15 500 error handler requires application error to test

        # Only include detailed exception info in development
        if app.config.get('ENVIRONMENT') == 'development':
            app.logger.error(f"Internal server error: {error}", exc_info=True)
        else:
            # In production, log the error but without sensitive stack trace details
            app.logger.error(f"Internal server error occurred (error logged separately for security)")

        security_logger.log_system_error(
            error_type="internal_server_error",
            error_message=str(error),
            stack_trace=None
        )
        return "Internal Server Error", 500

    # Log 404 errors (potential scanning/probing)
    @app.errorhandler(404)
    def log_not_found(error): # pragma: no cover
        ## PRAGMA-NO-COVER Exception; JS 2025-09-15 404 error handler requires invalid URL to test
        # Log 404s as they might indicate scanning/probing
        if request and request.path and not request.path.startswith('/static/'):
            app.logger.warning(f"404 Not Found: {request.method} {request.path}")

            # Check for suspicious patterns
            suspicious_patterns = [
                'admin', 'wp-admin', 'phpmyadmin', '.env', 'config',
                'backup', 'api/v2', 'api/v3', '../', '.git',
                'shell', 'cmd', 'exec'
            ]

            if any(pattern in request.path.lower() for pattern in suspicious_patterns):
                security_logger.log_suspicious_api_activity(
                    endpoint=request.path,
                    activity_type="path_scanning",
                    details={
                        'method': request.method,
                        'suspicious_path': request.path,
                        'patterns_detected': [p for p in suspicious_patterns if p in request.path.lower()]
                    }
                )

        return "Not Found", 404

    app.logger.info("Security logging configured successfully")