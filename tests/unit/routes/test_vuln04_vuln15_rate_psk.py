"""
VULN-04 + VULN-15: Rate limiting and Argon2 PSK hashing.

VULN-04: Flask-Limiter is initialized but no @limiter.limit() decorators exist.
  After fix: /api/v1/server/bundle, /api/v1/computer/bundle → 20/minute
             /auth/login, /auth/callback              → 30/minute
             /download, /download/<token>              → 20/minute

VULN-15: PSKs are stored as unsalted SHA-256 hashes.
  After fix: new PSKs use argon2id; legacy SHA-256 PSKs still verify and are
  transparently rehashed to argon2id on the first successful verify.
"""
import hashlib
import os
import pytest
from unittest.mock import MagicMock
from flask import redirect as flask_redirect

from app.models.presharedkey import PreSharedKey


@pytest.fixture
def rate_limited_app():
    """App with rate limiting ENABLED — used only for VULN-04 tests.

    The shared unit-test conftest disables rate limiting to prevent counter
    bleed-through between test functions.  These tests need it active.
    """
    os.environ['FLASK_SECRET_KEY'] = 'test-secret-key-for-unit-tests-only'
    os.environ['FERNET_ENCRYPTION_KEY'] = 'YenxIAHqvrO7OHbNXvzAxEhthHCaitvnV9CALkQvvCc='
    from app import create_app
    application = create_app('development')
    application.config.update({
        "TESTING": True,
        "WTF_CSRF_ENABLED": False,
        "RATELIMIT_ENABLED": True,
        "RATELIMIT_STORAGE_URI": "memory://",
    })
    # Re-initialize limiter so the cached `enabled=True` flag takes effect,
    # overriding any previous init_app calls from other fixtures that set False.
    from app.extensions import limiter
    limiter.init_app(application)
    return application


# ---------------------------------------------------------------------------
# VULN-04 helpers
# ---------------------------------------------------------------------------

def _count_to_limit(client, method, url, limit, **kwargs):
    """Send limit+1 requests; return list of status codes.

    If the route itself raises (e.g. DB not set up in the test environment)
    the request is counted as 500 — Flask-Limiter increments the counter
    before the route function runs, so the 429 still arrives at limit+1.
    """
    codes = []
    for _ in range(limit + 1):
        try:
            resp = getattr(client, method)(url, **kwargs)
            codes.append(resp.status_code)
        except Exception:
            codes.append(500)
    return codes


# ---------------------------------------------------------------------------
# VULN-04 tests
# ---------------------------------------------------------------------------

class TestVuln04RateLimiting:
    """Endpoints must return 429 after their per-minute limit is exceeded."""

    def test_server_bundle_rate_limited(self, rate_limited_app):
        """/api/v1/server/bundle must return 429 after 10 requests/hour."""
        client = rate_limited_app.test_client()
        codes = _count_to_limit(client, 'post', '/api/v1/server/bundle',
                                 limit=10, json={'psk': 'wrong'})
        assert 429 in codes, (
            f"Expected 429 after 10 requests to /api/v1/server/bundle; "
            f"got status codes: {set(codes)}"
        )

    def test_computer_bundle_rate_limited(self, rate_limited_app):
        """/api/v1/computer/bundle must return 429 after 10 requests/hour."""
        client = rate_limited_app.test_client()
        codes = _count_to_limit(client, 'post', '/api/v1/computer/bundle',
                                 limit=10, json={'psk': 'wrong'})
        assert 429 in codes, (
            f"Expected 429 after 10 requests to /api/v1/computer/bundle; "
            f"got status codes: {set(codes)}"
        )

    def test_auth_login_rate_limited(self, rate_limited_app, monkeypatch):
        """/auth/login must return 429 after 10 requests/minute."""
        mock_oauth = MagicMock()
        mock_oauth.oidc.authorize_redirect.return_value = flask_redirect('/mocked')
        monkeypatch.setattr('app.routes.auth.oauth', mock_oauth)

        client = rate_limited_app.test_client()
        codes = _count_to_limit(client, 'get', '/auth/login', limit=10)
        assert 429 in codes, (
            f"Expected 429 after 10 requests to /auth/login; "
            f"got status codes: {set(codes)}"
        )

    def test_download_rate_limited(self, rate_limited_app):
        """/download/<token> must return 429 after 5 requests/minute."""
        client = rate_limited_app.test_client()
        codes = _count_to_limit(client, 'get', '/download/no-such-token',
                                 limit=5)
        assert 429 in codes, (
            f"Expected 429 after 5 requests to /download/<token>; "
            f"got status codes: {set(codes)}"
        )


# ---------------------------------------------------------------------------
# VULN-15 tests
# ---------------------------------------------------------------------------

class TestVuln15ArgonPskHashing:
    """New PSKs must use argon2id; legacy SHA-256 PSKs must still verify and
    be transparently rehashed on the first successful verify."""

    def test_new_psk_uses_argon2id(self):
        """key_hash for a newly created PSK must begin with '$argon2id$'."""
        psk = PreSharedKey(description="test-server", psk_type="server",
                           key="my-secret-psk-value")
        assert psk.key_hash.startswith('$argon2id$'), (
            f"Expected argon2id hash; got: {psk.key_hash[:30]}..."
        )

    def test_new_psk_verifies_correct_key(self):
        """verify_key must return True for the matching key, False otherwise."""
        psk = PreSharedKey(description="test", key="correct-key")
        assert psk.verify_key("correct-key")
        assert not psk.verify_key("wrong-key")

    def test_legacy_sha256_psk_still_verifies(self, app):
        """A PSK stored with the old SHA-256 hash must still pass verify_key."""
        with app.app_context():
            psk = PreSharedKey(description="legacy-test", psk_type="server",
                               key="placeholder")
            psk.key_hash = hashlib.sha256("legacy-key".encode()).hexdigest()
            assert psk.verify_key("legacy-key"), (
                "Legacy SHA-256 PSK must still verify after the argon2 migration"
            )

    def test_sha256_psk_transparently_rehashed_on_verify(self, app):
        """verify_key on a SHA-256 PSK must update key_hash to argon2id in place."""
        with app.app_context():
            psk = PreSharedKey(description="rehash-test", psk_type="server",
                               key="placeholder")
            psk.key_hash = hashlib.sha256("rehash-me".encode()).hexdigest()
            assert len(psk.key_hash) == 64, "Pre-condition: should be SHA-256"

            psk.verify_key("rehash-me")

            assert psk.key_hash.startswith('$argon2id$'), (
                f"After verify_key on SHA-256 PSK, hash should be argon2id; "
                f"got: {psk.key_hash[:30]}..."
            )
