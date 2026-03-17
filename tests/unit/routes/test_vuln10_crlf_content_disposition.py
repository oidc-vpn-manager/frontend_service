"""
Tests for VULN-10: CRLF injection in Content-Disposition headers.

PSK descriptions (and the user email local-part) are embedded unquoted in
Content-Disposition headers.  A CRLF (\\r\\n) in a description would inject
extra HTTP response headers.

Fix:
- Strip \\r and \\n from the value
- Strip " to avoid breaking the quoted filename
- Quote the filename: filename="..."

Three endpoints are affected:
- POST /         (user profile — email local-part)
- GET/POST /v1/server/bundle   (server bundle — PSK description)
- GET/POST /v1/computer/bundle (computer bundle — PSK description)
"""
import os
import pytest
from unittest.mock import MagicMock, patch

from app import create_app
from app.extensions import db
from app.models.presharedkey import PreSharedKey


@pytest.fixture
def app():
    os.environ['FLASK_SECRET_KEY'] = 'test-secret-key-vuln10'
    os.environ['FERNET_ENCRYPTION_KEY'] = 'YenxIAHqvrO7OHbNXvzAxEhthHCaitvnV9CALkQvvCc='
    application = create_app('development')
    application.config.update({
        'TESTING': True,
        'WTF_CSRF_ENABLED': False,
        'ADMIN_URL_BASE': '',
        'OPENVPN_TLS_CRYPT_KEY': (
            '-----BEGIN OpenVPN Static key V1-----\n'
            'test-key-data\n'
            '-----END OpenVPN Static key V1-----'
        ),
        'ROOT_CA_CERTIFICATE': '-----BEGIN CERTIFICATE-----\ntest-root-ca\n-----END CERTIFICATE-----',
        'INTERMEDIATE_CA_CERTIFICATE': '-----BEGIN CERTIFICATE-----\ntest-int-ca\n-----END CERTIFICATE-----',
        'TEMPLATE_COLLECTION': [{
            'priority': 1,
            'group_name': 'default',
            'file_name': 'default.ovpn',
            'content': 'client\n{{ device_cert_pem }}',
        }],
        'OVPN_OPTIONS': {},
    })
    with application.app_context():
        db.create_all()
    return application


class TestVuln10UserProfileCrlf:
    """POST / — user profile download filename must not contain CRLF."""

    def test_email_localpart_crlf_stripped_from_content_disposition(self, app, monkeypatch):
        """CRLF in the email local-part must not appear in Content-Disposition.

        Before fix: filename={email_part}\\r\\nX-Injected: header → header injection.
        After fix:  \\r and \\n are stripped; filename is quoted.
        """
        mock_key = MagicMock()
        mock_key.private_bytes.return_value = b'-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----'
        mock_csr = MagicMock()
        mock_csr.subject.get_attributes_for_oid.return_value = [MagicMock(value='evil\r\nX-Injected: pwned@example.com')]
        mock_csr.public_bytes.return_value = b'-----BEGIN CERTIFICATE REQUEST-----\ncsr\n-----END CERTIFICATE REQUEST-----'

        with app.app_context():
            monkeypatch.setattr('app.routes.root.generate_key_and_csr', MagicMock(return_value=(mock_key, mock_csr)))
            monkeypatch.setattr('app.routes.root.request_signed_certificate', MagicMock(
                return_value='-----BEGIN CERTIFICATE-----\ncert\n-----END CERTIFICATE-----'
            ))
            monkeypatch.setattr('app.routes.root.process_tls_crypt_key', MagicMock(return_value=('v1', 'tls-key')))
            monkeypatch.setattr('app.routes.root.find_best_template_match', MagicMock(
                return_value=('default.ovpn', 'client\n{{ device_cert_pem }}')
            ))
            monkeypatch.setattr('app.routes.root.render_config_template', MagicMock(return_value='# config'))
            monkeypatch.setattr('app.routes.root.db', MagicMock())
            monkeypatch.setattr('app.routes.root.DownloadToken', MagicMock)

            client = app.test_client()
            with client.session_transaction() as sess:
                sess['user'] = {
                    'sub': 'evil\r\nX-Injected: pwned@example.com',
                    'email': 'evil\r\nX-Injected: pwned@example.com',
                    'groups': 'default',
                }
            response = client.post('/', data={'submit': 'Generate Profile'})

        assert response.status_code == 200
        content_disposition = response.headers.get('Content-Disposition', '')
        assert '\r' not in content_disposition
        assert '\n' not in content_disposition


class TestVuln10ServerBundleCrlf:
    """GET/POST /v1/server/bundle — server bundle Content-Disposition must not contain CRLF."""

    def _create_server_psk(self, app, description):
        """Helper: create a server PSK with the given description and return its key."""
        with app.app_context():
            raw_key = 'test-server-psk-key-vuln10-server'
            psk = PreSharedKey(
                key=raw_key,
                description=description,
                template_set='Default',
                psk_type='server',
            )
            db.session.add(psk)
            db.session.commit()
            return raw_key

    def test_crlf_in_description_stripped_from_content_disposition(self, app, monkeypatch):
        """CRLF in PSK description must not appear in the server bundle Content-Disposition.

        Before fix: filename=openvpn-server-evil\\r\\nX-Injected: hdr.tar.gz → injection.
        After fix:  \\r and \\n stripped, filename quoted.
        """
        description = 'evil\r\nX-Injected: pwned'
        raw_key = self._create_server_psk(app, description)

        mock_key = MagicMock()
        mock_key.private_bytes.return_value = b'-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----'
        mock_csr = MagicMock()
        mock_csr.public_bytes.return_value = b'-----BEGIN CERTIFICATE REQUEST-----\ncsr\n-----END CERTIFICATE REQUEST-----'

        with app.app_context():
            monkeypatch.setattr('app.routes.api.v1.generate_key_and_csr', MagicMock(return_value=(mock_key, mock_csr)))
            monkeypatch.setattr('app.routes.api.v1.request_signed_certificate', MagicMock(
                return_value='-----BEGIN CERTIFICATE-----\ncert\n-----END CERTIFICATE-----'
            ))
            monkeypatch.setattr('app.routes.api.v1.process_tls_crypt_key', MagicMock(return_value=('v1', 'tls-key')))
            monkeypatch.setattr('app.routes.api.v1.find_best_template_match', MagicMock(
                return_value=('server.ovpn', 'server-config')
            ))
            monkeypatch.setattr('app.routes.api.v1.render_config_template', MagicMock(return_value='# server config'))
            # Mock the server templates directory listing
            monkeypatch.setattr('os.listdir', MagicMock(return_value=[]))

            client = app.test_client()
            response = client.post(
                '/api/v1/server/bundle',
                headers={'Authorization': f'Bearer {raw_key}'}
            )

        # Before fix: Werkzeug raises ValueError for CRLF in headers → 500
        # After fix:  CRLF stripped → 200 with clean Content-Disposition
        assert response.status_code == 200
        content_disposition = response.headers.get('Content-Disposition', '')
        assert '\r' not in content_disposition
        assert '\n' not in content_disposition


class TestVuln10ComputerBundleCrlf:
    """GET/POST /v1/computer/bundle — computer bundle Content-Disposition must not contain CRLF."""

    def _create_computer_psk(self, app, description):
        raw_key = 'test-computer-psk-key-vuln10-computer'
        with app.app_context():
            psk = PreSharedKey(
                key=raw_key,
                description=description,
                template_set='Default',
                psk_type='computer',
            )
            db.session.add(psk)
            db.session.commit()
            return raw_key

    def test_crlf_in_description_stripped_from_content_disposition(self, app, monkeypatch):
        """CRLF in PSK description must not appear in the computer bundle Content-Disposition.

        Before fix: filename=computer-evil\\r\\nX-Injected: hdr.ovpn → injection.
        After fix:  \\r and \\n stripped, filename quoted.
        """
        description = 'evil\r\nX-Injected: pwned'
        raw_key = self._create_computer_psk(app, description)

        mock_key = MagicMock()
        mock_key.private_bytes.return_value = b'-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----'
        mock_csr = MagicMock()
        mock_csr.public_bytes.return_value = b'-----BEGIN CERTIFICATE REQUEST-----\ncsr\n-----END CERTIFICATE REQUEST-----'

        with app.app_context():
            monkeypatch.setattr('app.routes.api.v1.generate_key_and_csr', MagicMock(return_value=(mock_key, mock_csr)))
            monkeypatch.setattr('app.routes.api.v1.request_signed_certificate', MagicMock(
                return_value='-----BEGIN CERTIFICATE-----\ncert\n-----END CERTIFICATE-----'
            ))
            monkeypatch.setattr('app.routes.api.v1.process_tls_crypt_key', MagicMock(return_value=('v1', 'tls-key')))
            monkeypatch.setattr('app.routes.api.v1.find_best_template_match', MagicMock(
                return_value=('computer.ovpn', 'computer-config')
            ))
            monkeypatch.setattr('app.routes.api.v1.render_config_template', MagicMock(return_value='# computer config'))

            client = app.test_client()
            response = client.post(
                '/api/v1/computer/bundle',
                headers={'Authorization': f'Bearer {raw_key}'}
            )

        # Before fix: Werkzeug raises ValueError for CRLF in headers → 500
        # After fix:  CRLF stripped → 200 with clean Content-Disposition
        assert response.status_code == 200
        content_disposition = response.headers.get('Content-Disposition', '')
        assert '\r' not in content_disposition
        assert '\n' not in content_disposition
