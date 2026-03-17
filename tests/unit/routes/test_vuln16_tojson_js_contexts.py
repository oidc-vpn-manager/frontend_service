"""
Tests for VULN-16: Absence of |tojson in JavaScript template string contexts.

In <script> tags, Jinja2 HTML autoescaping is wrong: it produces HTML entities
like &#39; (for ') which JS treats as 5 literal chars, not as '.
The fix is |tojson which produces proper JS/JSON encoding (\\u0027 for ').

Only the bounce templates have actual JS string literal contexts (setAttribute
call inside a <script> tag). The data-attribute templates use HTML attribute
context where Jinja2 autoescaping is correct.
"""
import os
import pytest

from app import create_app
from app.extensions import db


@pytest.fixture
def bounce_app():
    """Full app with ADMIN_URL_BASE and USER_URL_BASE containing a single quote."""
    os.environ['FLASK_SECRET_KEY'] = 'test-secret-key-vuln16'
    os.environ['FERNET_ENCRYPTION_KEY'] = 'YenxIAHqvrO7OHbNXvzAxEhthHCaitvnV9CALkQvvCc='
    app = create_app('development')
    app.config.update({
        'TESTING': True,
        'WTF_CSRF_ENABLED': False,
        # URLs that contain a single quote — the HTML-entity-in-JS injection test
        'ADMIN_URL_BASE': "https://vpnadmin.corp.example.com/'test'",
        'USER_URL_BASE': "https://vpnuser.corp.example.com/'test'",
    })
    with app.app_context():
        db.create_all()
    return app


@pytest.fixture
def bounce_client(bounce_app):
    client = bounce_app.test_client()
    with client.session_transaction() as sess:
        sess['user'] = {
            'sub': 'admin@example.com',
            'email': 'admin@example.com',
            'groups': ['vpn-admins'],
        }
    return client


class TestVuln16TojsonBounceAdminTemplate:
    """bounce_to_admin.html: admin_url must use |tojson in the <script> block.

    Without |tojson, Jinja2 HTML-escapes ' to &#39; inside a <script> tag.
    In a JavaScript context, &#39; is treated as 5 literal characters — not
    as a quote — producing the wrong runtime value for the URL.
    With |tojson, single quotes become \\u0027 which JS correctly interprets as '.
    """

    def test_admin_url_with_single_quote_uses_tojson(self, bounce_client):
        """Single quote in admin_url must appear as \\u0027 (not &#39;) in the script.

        Before fix: Jinja2 HTML-encodes ' to &#39; → wrong literal in JS.
        After fix:  |tojson encodes ' to \\u0027 → correct JS Unicode escape.
        """
        response = bounce_client.get('/bounce-to-admin')

        assert response.status_code == 200
        # With |tojson, ' becomes \\u0027 (a JS-interpretable Unicode escape)
        assert b'\\u0027' in response.data

    def test_admin_setAttribute_call_uses_json_encoding(self, bounce_client):
        """The setAttribute call in the script block must use JSON Unicode escapes.

        Before fix: setAttribute line contains &#39; (HTML entity, literal in JS).
        After fix:  setAttribute line contains \\u0027 (JSON escape, JS-interpretable).
        """
        response = bounce_client.get('/bounce-to-admin')

        assert response.status_code == 200
        # The setAttribute call must contain the JSON-encoded form
        assert b"setAttribute('data-target-url', \"https://vpnadmin.corp.example.com/\\u0027" in response.data


class TestVuln16TojsonBounceUserTemplate:
    """bounce_to_user.html: user_url must use |tojson in the <script> block."""

    def test_user_url_with_single_quote_uses_tojson(self, bounce_client):
        """Single quote in user_url must appear as \\u0027 (not &#39;) in the script."""
        response = bounce_client.get('/bounce-to-user')

        assert response.status_code == 200
        assert b'\\u0027' in response.data

    def test_user_setAttribute_call_uses_json_encoding(self, bounce_client):
        """The setAttribute call in the script block must use JSON Unicode escapes."""
        response = bounce_client.get('/bounce-to-user')

        assert response.status_code == 200
        assert b"setAttribute('data-target-url', \"https://vpnuser.corp.example.com/\\u0027" in response.data
