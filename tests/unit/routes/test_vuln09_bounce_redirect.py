"""
Tests for VULN-09: Bounce redirect subdomain bypass.

The current validation `target_url.startswith(admin_url_base.rstrip('/'))` is a
string prefix check only.  `https://vpnadmin.corp.dice.fm.evil.com` passes
because it starts with `https://vpnadmin.corp.dice.fm` — a different domain.

Fix: parse both URLs and compare scheme + netloc (+ path prefix) instead of
using a raw string prefix match.
"""
import os
import pytest
from unittest.mock import patch

from app import create_app
from app.extensions import db


@pytest.fixture
def app_with_admin_url():
    os.environ['FLASK_SECRET_KEY'] = 'test-secret-key-vuln09'
    os.environ['FERNET_ENCRYPTION_KEY'] = 'YenxIAHqvrO7OHbNXvzAxEhthHCaitvnV9CALkQvvCc='
    app = create_app('development')
    app.config.update({
        'TESTING': True,
        'WTF_CSRF_ENABLED': False,
        'ADMIN_URL_BASE': 'https://vpnadmin.corp.dice.fm',
        'USER_URL_BASE': 'https://vpnuser.corp.dice.fm',
    })
    with app.app_context():
        db.create_all()
    return app


@pytest.fixture
def logged_in_client(app_with_admin_url):
    client = app_with_admin_url.test_client()
    with client.session_transaction() as sess:
        sess['user'] = {
            'sub': 'user@example.com',
            'email': 'user@example.com',
            'groups': [],
        }
    return client


class TestVuln09BounceAdminSubdomainBypass:
    """VULN-09: Subdomain bypass on bounce-to-admin must be rejected.

    String prefix check allows https://vpnadmin.corp.dice.fm.evil.com because
    it starts with https://vpnadmin.corp.dice.fm.  The fix compares parsed URLs
    (scheme + netloc equality, then path prefix).
    """

    def test_subdomain_bypass_rejected(self, app_with_admin_url, logged_in_client):
        """https://vpnadmin.corp.dice.fm.evil.com must be rejected.

        Before fix: startswith passes → admin_url rendered as evil domain.
        After fix:  netloc differs → falls back to admin_url_base.
        """
        bypass_url = 'https://vpnadmin.corp.dice.fm.evil.com/steal-tokens'

        with patch('app.routes.root.render_template', return_value='bounce page') as mock_render:
            response = logged_in_client.get(
                f'/bounce-to-admin?target_url={bypass_url}'
            )

        assert response.status_code == 200
        # Must fall back to the legitimate admin URL, not the attacker's domain
        call_kwargs = mock_render.call_args[1]
        assert call_kwargs['admin_url'] == 'https://vpnadmin.corp.dice.fm'

    def test_valid_path_under_admin_base_accepted(self, app_with_admin_url, logged_in_client):
        """A path under the admin base URL must be accepted."""
        valid_url = 'https://vpnadmin.corp.dice.fm/certificates/bulk-revoke'

        with patch('app.routes.root.render_template', return_value='bounce page') as mock_render:
            response = logged_in_client.get(
                f'/bounce-to-admin?target_url={valid_url}'
            )

        assert response.status_code == 200
        call_kwargs = mock_render.call_args[1]
        assert call_kwargs['admin_url'] == valid_url

    def test_different_scheme_rejected(self, app_with_admin_url, logged_in_client):
        """http:// must be rejected when admin_url_base is https://."""
        http_url = 'http://vpnadmin.corp.dice.fm/path'

        with patch('app.routes.root.render_template', return_value='bounce page') as mock_render:
            response = logged_in_client.get(
                f'/bounce-to-admin?target_url={http_url}'
            )

        assert response.status_code == 200
        call_kwargs = mock_render.call_args[1]
        assert call_kwargs['admin_url'] == 'https://vpnadmin.corp.dice.fm'


class TestVuln09BounceUserSubdomainBypass:
    """VULN-09: Same subdomain bypass on bounce-to-user must be rejected."""

    def test_subdomain_bypass_rejected(self, app_with_admin_url, logged_in_client):
        """https://vpnuser.corp.dice.fm.evil.com must be rejected."""
        bypass_url = 'https://vpnuser.corp.dice.fm.evil.com/steal-tokens'

        with patch('app.routes.root.render_template', return_value='bounce page') as mock_render:
            response = logged_in_client.get(
                f'/bounce-to-user?target_url={bypass_url}'
            )

        assert response.status_code == 200
        call_kwargs = mock_render.call_args[1]
        assert call_kwargs['user_url'] == 'https://vpnuser.corp.dice.fm'

    def test_valid_path_under_user_base_accepted(self, app_with_admin_url, logged_in_client):
        """A path under the user base URL must be accepted."""
        valid_url = 'https://vpnuser.corp.dice.fm/profile/certificates'

        with patch('app.routes.root.render_template', return_value='bounce page') as mock_render:
            response = logged_in_client.get(
                f'/bounce-to-user?target_url={valid_url}'
            )

        assert response.status_code == 200
        call_kwargs = mock_render.call_args[1]
        assert call_kwargs['user_url'] == valid_url
