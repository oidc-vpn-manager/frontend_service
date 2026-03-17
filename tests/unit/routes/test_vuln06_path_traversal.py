"""
Tests for VULN-06: Path traversal via email parameter into CT service URL.

The email/user_id path parameter in the bulk-revoke endpoint is interpolated
directly into the CT service URL:
  f"{self.base_url}/users/{user_id}/revoke-certificates"

An attacker with service-admin role can send user_id = "a@b.com%2F..%2Fadmin"
which, after URL decoding and HTTP path resolution, reaches a different CT
endpoint than intended.

Fix — two parts:
1. Route level: validate email format with validate_email() — returns 400 for
   any value that is not a valid email address (e.g. one containing ../).
2. CT client level: URL-encode user_id with urllib.parse.quote(user_id, safe='')
   so that / and . are percent-encoded before the URL is constructed.
"""
import os
import pytest
from unittest.mock import MagicMock, patch

from app import create_app
from app.extensions import db


@pytest.fixture
def service_admin_app():
    os.environ['FLASK_SECRET_KEY'] = 'test-secret-key-vuln06'
    os.environ['FERNET_ENCRYPTION_KEY'] = 'YenxIAHqvrO7OHbNXvzAxEhthHCaitvnV9CALkQvvCc='
    app = create_app('development')
    app.config.update({
        'TESTING': True,
        'WTF_CSRF_ENABLED': False,
        'ADMIN_URL_BASE': '',
    })
    with app.app_context():
        db.create_all()
    return app


@pytest.fixture
def service_admin_client(service_admin_app):
    client = service_admin_app.test_client()
    with client.session_transaction() as sess:
        sess['user'] = {
            'sub': 'admin@example.com',
            'email': 'admin@example.com',
            'is_system_admin': True,
            'is_admin': False,
            'is_auditor': False,
        }
    return client


class TestVuln06PathTraversalRouteValidation:
    """Route-level: invalid email format must be rejected with 400."""

    def test_invalid_email_rejected_with_400(self, service_admin_client):
        """An invalid email (no TLD, dots as last label, etc.) must return 400.

        Before fix: validate_email not called → malformed email reaches CT client.
        After fix:  validate_email raises InputValidationError → 400 returned.

        Note: Flask's string-converter route variable does not permit raw '/'
        (it returns 404), so the primary defence is validate_email rejecting
        values that are not RFC-5321-conformant email addresses.
        """
        # 'user@nodotdomain' has no TLD — does not match the email regex
        with patch('app.routes.api.service_admin.get_certtransparency_client') as mock_get_client:
            response = service_admin_client.post(
                '/api/certificates/user/user@nodotdomain/revoke',
                json={'reason': 'key_compromise'},
            )

        # Must be 400 — not reaching the CT client at all
        assert response.status_code == 400
        mock_get_client.assert_not_called()

    def test_valid_email_passes_through(self, service_admin_client):
        """A properly formed email must still reach the CT client (200 path)."""
        mock_client = MagicMock()
        mock_client.bulk_revoke_user_certificates.return_value = {
            'revoked_count': 1,
            'revoked_fingerprints': [],
        }

        with patch('app.routes.api.service_admin.get_certtransparency_client',
                   return_value=mock_client):
            response = service_admin_client.post(
                '/api/certificates/user/legit@example.com/revoke',
                json={'reason': 'key_compromise'},
            )

        assert response.status_code == 200
        mock_client.bulk_revoke_user_certificates.assert_called_once()


class TestVuln06PathTraversalCtClientEncoding:
    """CT client level: user_id must be URL-encoded before URL construction."""

    def test_slash_in_user_id_is_percent_encoded(self):
        """user_id containing '/' must be %-encoded in the CT service URL.

        Before fix: url = .../users/a@b.com/../admin@corp.com/revoke-...
        After fix:  url = .../users/a%40b.com%2F..%2Fadmin%40corp.com/revoke-...
        """
        os.environ['FLASK_SECRET_KEY'] = 'test-secret-key-vuln06-ct'
        os.environ['FERNET_ENCRYPTION_KEY'] = 'YenxIAHqvrO7OHbNXvzAxEhthHCaitvnV9CALkQvvCc='
        app = create_app('development')
        app.config.update({'TESTING': True})

        with app.app_context():
            from app.utils.certtransparency_client import CertTransparencyClient

            client = CertTransparencyClient.__new__(CertTransparencyClient)
            client.base_url = 'https://ct.internal'
            client.timeout = 5
            client.tls_verify = True

            captured_url = []

            def fake_post(url, **kwargs):
                captured_url.append(url)
                resp = MagicMock()
                resp.raise_for_status.return_value = None
                resp.json.return_value = {'revoked_count': 0}
                return resp

            with patch('requests.post', side_effect=fake_post):
                client.bulk_revoke_user_certificates(
                    user_id='a@b.com/../admin@corp.com',
                    reason='key_compromise',
                    revoked_by='admin@example.com',
                )

        assert captured_url, "No URL was captured"
        url = captured_url[0]
        # The traversal characters must be percent-encoded in the URL
        assert '/../' not in url, f"Path traversal not encoded: {url}"
        assert '%2F' in url or '%2f' in url, f"Slash not encoded: {url}"
