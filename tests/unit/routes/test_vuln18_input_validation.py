"""
VULN-18: Unused input validation functions.

Two dead-code functions are removed from input_validation.py (superseded by
better alternatives), and sanitize_for_logging is wired into auth route log
calls to prevent log-injection via OIDC claims.
"""
import logging
import pytest
from flask import Flask
from unittest.mock import MagicMock, patch


class TestVuln18DeadCodeRemoval:
    """validate_certificate_fingerprint and validate_form_field must be removed.

    Both are superseded:
    - validate_certificate_fingerprint → validate_certificate_fingerprint_or_404/400
      in app.utils.validation (the callers already use those)
    - validate_form_field → WTForms validators used by form classes in this app
    """

    def test_validate_certificate_fingerprint_removed(self):
        """validate_certificate_fingerprint must not exist in input_validation."""
        import app.utils.input_validation as iv
        assert not hasattr(iv, 'validate_certificate_fingerprint'), (
            "validate_certificate_fingerprint still exists in input_validation.py; "
            "remove it — the codebase uses validate_certificate_fingerprint_or_404/400 "
            "from utils/validation.py instead."
        )

    def test_validate_form_field_removed(self):
        """validate_form_field must not exist in input_validation."""
        import app.utils.input_validation as iv
        assert not hasattr(iv, 'validate_form_field'), (
            "validate_form_field still exists in input_validation.py; "
            "remove it — form field validation is handled by WTForms validators."
        )


@pytest.fixture
def auth_app():
    """Minimal Flask app with auth and root blueprints for log-injection tests."""
    app = Flask(__name__)
    app.config['TESTING'] = True
    app.config['SECRET_KEY'] = 'test-secret-key-vuln18'
    app.config['OIDC_ADMIN_GROUP'] = 'admins'
    app.config['OIDC_AUDITOR_GROUP'] = 'auditors'
    app.config['OIDC_SYSTEM_ADMIN_GROUP'] = 'system-admins'

    from app.routes.auth import bp as auth_bp
    from app.routes.root import bp as root_bp
    app.register_blueprint(auth_bp)
    app.register_blueprint(root_bp)
    return app


@pytest.fixture
def mock_oauth_login(monkeypatch):
    """Minimal OAuth mock needed to reach the log call in auth.login."""
    mock_client = MagicMock()
    from flask import redirect as flask_redirect
    mock_client.oidc.authorize_redirect.return_value = flask_redirect('/mocked-oidc')
    monkeypatch.setattr('app.routes.auth.oauth', mock_client)
    return mock_client


class TestVuln18SanitizeForLogging:
    """sanitize_for_logging must sanitize next_url before it reaches log calls.

    Without sanitization a ?next= value containing CRLF is passed directly to
    current_app.logger.info(), which lets an attacker inject fake log lines.

    The URL /auth/login?next=/ok%0d%0aX-Injected:%20evil passes the existing
    startswith('/') check (it starts with '/') but the stored and logged value
    still contains raw CR+LF before the fix.
    """

    def test_login_next_url_crlf_stripped_from_log(self, auth_app, mock_oauth_login, caplog):
        """CRLF in ?next= must not appear verbatim in any log record."""
        crlf_next = '/profile\r\nX-Injected: evil-log-line'
        with caplog.at_level(logging.INFO):
            client = auth_app.test_client()
            # URL-encode the CRLF so it reaches the route handler
            import urllib.parse
            encoded = urllib.parse.quote(crlf_next, safe='/')
            client.get(f'/auth/login?next={encoded}')

        for record in caplog.records:
            msg = record.getMessage()
            assert '\r' not in msg, f"CR found in log record: {msg!r}"
            assert '\n' not in msg, f"LF found in log record: {msg!r}"
