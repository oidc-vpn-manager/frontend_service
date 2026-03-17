"""
VULN-03: CSRF on privileged API endpoints → API token system.

All /api/* service-admin endpoints previously accepted OIDC session cookies
with csrf.exempt(bp), making them vulnerable to CSRF attacks from an admin's
browser.  The fix replaces session auth with API token auth (Authorization:
Bearer <token>).  Session cookies are no longer accepted on these endpoints.
"""
import os
import uuid
import pytest
from datetime import datetime, timezone, timedelta

from app import create_app
from app.extensions import db


@pytest.fixture
def app():
    os.environ["FLASK_SECRET_KEY"] = "test-secret-key-for-vuln03-tests"
    os.environ["FERNET_ENCRYPTION_KEY"] = "YenxIAHqvrO7OHbNXvzAxEhthHCaitvnV9CALkQvvCc="
    application = create_app("development")
    application.config.update({
        "TESTING": True,
        "WTF_CSRF_ENABLED": False,
        "RATELIMIT_ENABLED": False,
        "ADMIN_URL_BASE": "",  # admin service endpoints available
    })
    from app.extensions import limiter
    limiter.init_app(application)
    with application.app_context():
        db.create_all()
    yield application
    with application.app_context():
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):
    return app.test_client()


def _make_token(app, description="test-token", expires_days=1):
    """Create a valid ApiToken, return (plaintext_key, token_obj)."""
    from app.models.apitoken import ApiToken
    plaintext = str(uuid.uuid4())
    with app.app_context():
        tok = ApiToken.create(
            plaintext_key=plaintext,
            description=description,
            created_by="admin@example.com",
            expires_at=datetime.now(timezone.utc) + timedelta(days=expires_days),
        )
        db.session.add(tok)
        db.session.commit()
        token_id = tok.id
    return plaintext, token_id


# ---------------------------------------------------------------------------
# Auth behaviour tests
# ---------------------------------------------------------------------------

class TestApiTokenAuthBehaviour:
    """The /api/* endpoints must require a valid API token, not a session."""

    def test_no_auth_returns_401(self, client):
        """GET /api/certificates without any auth must return 401, not 302."""
        response = client.get("/api/certificates")
        assert response.status_code == 401

    def test_session_auth_returns_401(self, client):
        """An authenticated admin session must NOT grant access (CSRF fix)."""
        with client.session_transaction() as sess:
            sess["user"] = {
                "sub": "admin@example.com",
                "is_admin": True,
                "is_system_admin": True,
                "is_auditor": True,
            }
        response = client.get("/api/certificates")
        assert response.status_code == 401, (
            "Session auth must not be accepted on API endpoints after VULN-03 fix"
        )

    def test_invalid_bearer_token_returns_401(self, client):
        response = client.get(
            "/api/certificates",
            headers={"Authorization": "Bearer totally-invalid-token"},
        )
        assert response.status_code == 401

    def test_valid_bearer_token_passes_auth(self, app, client):
        """A valid, unexpired, non-revoked token must pass the auth check."""
        plaintext, _ = _make_token(app)
        response = client.get(
            "/api/certificates",
            headers={"Authorization": f"Bearer {plaintext}"},
        )
        # CT service unavailable in unit tests → 503 is fine; 401 is not
        assert response.status_code != 401, (
            f"Valid token must not be rejected; got {response.status_code}"
        )

    def test_expired_token_returns_401(self, app, client):
        from app.models.apitoken import ApiToken
        plaintext = str(uuid.uuid4())
        with app.app_context():
            tok = ApiToken.create(
                plaintext_key=plaintext,
                description="expired",
                created_by="admin@example.com",
                expires_at=datetime.now(timezone.utc) - timedelta(seconds=1),
            )
            db.session.add(tok)
            db.session.commit()
        response = client.get(
            "/api/certificates",
            headers={"Authorization": f"Bearer {plaintext}"},
        )
        assert response.status_code == 401

    def test_revoked_token_returns_401(self, app, client):
        from app.models.apitoken import ApiToken
        plaintext, token_id = _make_token(app)
        with app.app_context():
            tok = db.session.get(ApiToken, token_id)
            tok.is_revoked = True
            db.session.commit()
        response = client.get(
            "/api/certificates",
            headers={"Authorization": f"Bearer {plaintext}"},
        )
        assert response.status_code == 401


# ---------------------------------------------------------------------------
# ApiToken model tests
# ---------------------------------------------------------------------------

class TestApiTokenModel:
    """Unit tests for the ApiToken model."""

    def test_create_hashes_key(self, app):
        from app.models.apitoken import ApiToken
        plaintext = "my-secret-api-key"
        with app.app_context():
            tok = ApiToken.create(
                plaintext_key=plaintext,
                description="test",
                created_by="admin@example.com",
                expires_at=datetime.now(timezone.utc) + timedelta(days=1),
            )
            assert tok.token_hash != plaintext
            assert tok.token_hash.startswith("$argon2id$")

    def test_verify_correct_key(self, app):
        from app.models.apitoken import ApiToken
        plaintext = "correct-key"
        with app.app_context():
            tok = ApiToken.create(
                plaintext_key=plaintext,
                description="test",
                created_by="admin@example.com",
                expires_at=datetime.now(timezone.utc) + timedelta(days=1),
            )
            assert tok.verify_key(plaintext) is True
            assert tok.verify_key("wrong-key") is False

    def test_is_valid_unexpired_active(self, app):
        from app.models.apitoken import ApiToken
        with app.app_context():
            tok = ApiToken.create(
                plaintext_key="k",
                description="t",
                created_by="a",
                expires_at=datetime.now(timezone.utc) + timedelta(days=1),
            )
            assert tok.is_valid() is True

    def test_is_valid_expired(self, app):
        from app.models.apitoken import ApiToken
        with app.app_context():
            tok = ApiToken.create(
                plaintext_key="k",
                description="t",
                created_by="a",
                expires_at=datetime.now(timezone.utc) - timedelta(seconds=1),
            )
            assert tok.is_valid() is False

    def test_is_valid_revoked(self, app):
        from app.models.apitoken import ApiToken
        with app.app_context():
            tok = ApiToken.create(
                plaintext_key="k",
                description="t",
                created_by="a",
                expires_at=datetime.now(timezone.utc) + timedelta(days=1),
            )
            tok.is_revoked = True
            assert tok.is_valid() is False

    def test_revoke_sets_is_revoked(self, app):
        """Cover apitoken.py:62 — revoke() sets is_revoked to True."""
        from app.models.apitoken import ApiToken
        with app.app_context():
            tok = ApiToken.create(
                plaintext_key="plaintext",
                description="test",
                created_by="admin",
                expires_at=datetime.now(timezone.utc) + timedelta(days=1),
            )
            assert not tok.is_revoked  # None or False before commit
            tok.revoke()
            assert tok.is_revoked is True
