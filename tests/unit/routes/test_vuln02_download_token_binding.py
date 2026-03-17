"""
VULN-02: Download token user binding.

A download token is generated for a specific authenticated user (stored as
download_token.user = session['user']['sub']).  Any *other* authenticated user
who knows the token UUID must not be able to redeem it — the download route
must return 403.

Unauthenticated requests (no session) are permitted; the token UUID provides
~128 bits of entropy and is additionally protected by:
  - 5/minute IP-based rate limiting (VULN-04)
  - single-use enforcement (download_token.collected flag)
"""
import pytest
from app.models.downloadtoken import DownloadToken
from app.extensions import db


@pytest.fixture
def app(app):
    """Extend the shared unit-test app fixture with a real in-memory DB schema."""
    with app.app_context():
        db.create_all()
    yield app
    with app.app_context():
        db.session.remove()
        db.drop_all()


class TestVuln02DownloadTokenBinding:
    """Authenticated users can only redeem tokens that belong to them."""

    def _create_token(self, app, user_sub, user_email="owner@example.com"):
        """Insert a fresh DownloadToken into the DB and return its UUID."""
        with app.app_context():
            token = DownloadToken(user=user_sub, cn=user_email)
            db.session.add(token)
            db.session.commit()
            return token.token

    def test_cross_user_token_rejected(self, app):
        """Authenticated user B must receive 403 when using user A's token."""
        token_id = self._create_token(app, user_sub="user-a@example.com")

        with app.test_client() as client:
            with client.session_transaction() as sess:
                sess["user"] = {
                    "sub": "user-b@example.com",
                    "email": "user-b@example.com",
                    "groups": ["users"],
                }
            response = client.get(f"/download/{token_id}")
            assert response.status_code == 403, (
                f"Expected 403 for cross-user token access, got {response.status_code}"
            )

    def test_owner_can_initiate_redemption(self, app):
        """Token owner does not get a 403 (signing service may fail — 500 is fine)."""
        token_id = self._create_token(app, user_sub="user-a@example.com")

        with app.test_client() as client:
            with client.session_transaction() as sess:
                sess["user"] = {
                    "sub": "user-a@example.com",
                    "email": "user-a@example.com",
                    "groups": ["users"],
                }
            response = client.get(f"/download/{token_id}")
            # Signing service unavailable in unit tests → 500 expected;
            # what matters is that ownership check passes (not 403).
            assert response.status_code != 403, (
                "Token owner must not be blocked by the ownership check"
            )

    def test_no_session_cli_or_webauth_allowed(self, app):
        """Unauthenticated request (CLI/WEB_AUTH, no session) is not blocked."""
        token_id = self._create_token(app, user_sub="user-a@example.com")

        with app.test_client() as client:
            # No session — simulates the headless CLI / OpenVPN Connect WEB_AUTH flow.
            # Protection is provided by the token entropy, rate limiting, and
            # single-use enforcement rather than session ownership.
            response = client.get(f"/download/{token_id}")
            assert response.status_code != 403, (
                "No-session request must not be blocked by the ownership check"
            )
