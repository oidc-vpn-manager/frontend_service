"""
VULN-05: Session Fixation — session ID must be regenerated on login.

Before fix: the OIDC callback writes user data into the existing pre-login
session without changing the session ID.  An attacker who planted a known
session cookie inherits the fully authenticated session.

After fix: the server-side session record for the old ID is deleted and a
new SID is generated before user data is written, so the old cookie becomes
useless after login.
"""
import pytest
from unittest.mock import MagicMock
from flask import redirect as flask_redirect


def _get_session_cookie_value(client, app):
    """Return the current session cookie value from the Werkzeug 3.x test client."""
    cookie_name = app.config.get('SESSION_COOKIE_NAME', 'session')
    cookie = client.get_cookie(cookie_name, domain='localhost')
    return cookie.value if cookie is not None else None


@pytest.fixture
def mock_oauth_vuln05(monkeypatch):
    """Minimal OAuth mock for the OIDC callback route."""
    mock_client = MagicMock()
    mock_client.oidc.authorize_redirect.return_value = flask_redirect('/mocked-oidc')
    mock_client.oidc.authorize_access_token.return_value = {'id_token': 'fake-jwt'}
    mock_client.oidc.userinfo.return_value = {
        'sub': 'user123',
        'email': 'user@example.com',
        'name': 'Test User',
        'groups': [],
    }
    monkeypatch.setattr('app.routes.auth.oauth', mock_client)
    return mock_client


class TestVuln05SessionFixation:
    """Session cookie value must differ before and after a successful OIDC login."""

    def test_session_id_regenerated_after_login(self, app, mock_oauth_vuln05):
        """The session cookie must change when the OIDC callback authenticates a user.

        Before fix: the same SID is reused → cookie_before == cookie_after.
        After fix:  the old SID is invalidated → cookie_before != cookie_after.
        """
        client = app.test_client()

        # Establish a pre-auth session by visiting the login page with a next= param.
        # This stores next_url in the session, creating a server-side session record.
        client.get('/auth/login?next=/profile')

        cookie_before = _get_session_cookie_value(client, app)
        assert cookie_before is not None, "Expected a session cookie to be set during login"

        # Complete the OIDC callback (oauth mocked above)
        response = client.get('/auth/callback')
        assert response.status_code == 302

        cookie_after = _get_session_cookie_value(client, app)
        assert cookie_after is not None, "Expected a session cookie after login"

        assert cookie_before != cookie_after, (
            "Session cookie unchanged after OIDC login — session fixation vulnerability: "
            f"before={cookie_before!r}, after={cookie_after!r}"
        )


class TestVuln05SessionFixationServerSideBranch:
    """Cover auth.py:105-106 — server-side session interface SID rotation path."""

    def test_sid_rotation_with_server_side_session_interface(self, app, mock_oauth_vuln05):
        """Lines 105-106: _delete_session and _generate_sid called when session has .sid."""
        from flask.sessions import SecureCookieSession
        from unittest.mock import MagicMock

        delete_mock = MagicMock()
        generate_mock = MagicMock(return_value='new-generated-sid')

        class _SIDSession(SecureCookieSession):
            sid = 'old-sid-value'

        class _ServerSideInterface:
            sid_length = 32
            _delete_session = delete_mock
            _generate_sid = generate_mock

            def _get_store_id(self, sid):
                return f'store:{sid}'

            def open_session(self, _app, _request):
                return _SIDSession()

            def save_session(self, _app, _session, response):
                pass  # no-op for test

            def is_null_session(self, session):
                return False

        original_si = app.session_interface
        app.session_interface = _ServerSideInterface()
        try:
            client = app.test_client()
            response = client.get('/auth/callback')
            assert response.status_code == 302
            delete_mock.assert_called_once_with('store:old-sid-value')
            generate_mock.assert_called_once_with(32)
        finally:
            app.session_interface = original_si
