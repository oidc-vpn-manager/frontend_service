"""
Tests for VULN-13: Missing Cache-Control: no-store on Credential Responses.

Three endpoints return private key material or plaintext PSKs without setting
Cache-Control: no-store. Without this header, intermediate proxies or the
browser cache may store the credential content on disk.

Fix: add Cache-Control: no-store (and Pragma: no-cache for HTTP/1.0) to:
  - POST /          (profile generation — contains private key)
  - POST /admin/psk/new  (PSK creation — shows plaintext PSK once)
  - POST /api/psks/computer  (computer PSK API — returns plaintext PSK)
"""
import os
import pytest
from unittest.mock import MagicMock, patch

from flask import Flask

from app.routes.root import bp as root_blueprint
from app.routes.auth import bp as auth_blueprint
from app.routes.admin import bp as admin_blueprint
from app.extensions import db
from app.models import PreSharedKey
from app import create_app


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def root_app():
    """Minimal Flask app with root + auth blueprints (mirrors test_root.py)."""
    app = Flask(__name__)
    app.config['TESTING'] = True
    app.config['SECRET_KEY'] = 'test-secret-vuln13'
    app.register_blueprint(root_blueprint)
    app.register_blueprint(auth_blueprint)
    return app


@pytest.fixture
def admin_app():
    """Minimal Flask app with admin + auth blueprints (mirrors test_admin_coverage.py)."""
    app = Flask(__name__)
    app.config.update({
        'TESTING': True,
        'SECRET_KEY': 'test-secret-vuln13-admin',
        'WTF_CSRF_ENABLED': False,
        'SQLALCHEMY_DATABASE_URI': 'sqlite:///:memory:',
        'SQLALCHEMY_TRACK_MODIFICATIONS': False,
        'OIDC_ADMIN_GROUP': 'admins',
    })
    db.init_app(app)
    app.register_blueprint(admin_blueprint)
    app.register_blueprint(auth_blueprint)
    with app.app_context():
        db.create_all()
    return app


@pytest.fixture
def service_admin_app():
    """Full app via create_app for service_admin API tests."""
    os.environ['FLASK_SECRET_KEY'] = 'test-secret-key-vuln13-service-admin'
    os.environ['FERNET_ENCRYPTION_KEY'] = 'YenxIAHqvrO7OHbNXvzAxEhthHCaitvnV9CALkQvvCc='
    app = create_app('development')
    app.config.update({
        'TESTING': True,
        'WTF_CSRF_ENABLED': False,
        'ADMIN_URL_BASE': '',
        'RATELIMIT_ENABLED': False,
    })
    from app.extensions import limiter
    limiter.init_app(app)
    with app.app_context():
        db.create_all()
    return app


@pytest.fixture
def service_admin_client(service_admin_app):
    """Test client authenticated via API token (VULN-03 fix)."""
    import uuid
    from datetime import datetime, timezone, timedelta
    from app.models.apitoken import ApiToken

    plaintext = str(uuid.uuid4())
    with service_admin_app.app_context():
        tok = ApiToken.create(
            plaintext_key=plaintext,
            description='vuln13-test-token',
            created_by='service-admin@example.com',
            expires_at=datetime.now(timezone.utc) + timedelta(days=1),
        )
        db.session.add(tok)
        db.session.commit()

    class _AuthClient:
        def __init__(self, client, token):
            self._c = client
            self._h = {'Authorization': f'Bearer {token}'}

        def _inject(self, kwargs):
            h = dict(self._h)
            h.update(kwargs.pop('headers', {}) or {})
            kwargs['headers'] = h
            return kwargs

        def get(self, *a, **kw):    return self._c.get(*a, **self._inject(kw))
        def post(self, *a, **kw):   return self._c.post(*a, **self._inject(kw))
        def put(self, *a, **kw):    return self._c.put(*a, **self._inject(kw))
        def delete(self, *a, **kw): return self._c.delete(*a, **self._inject(kw))

    return _AuthClient(service_admin_app.test_client(), plaintext)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestVuln13CacheControlOnCredentialResponses:
    """VULN-13: Credential responses must carry Cache-Control: no-store."""

    def test_profile_generation_has_cache_control_no_store(self, root_app, monkeypatch):
        """POST / (profile generation) response must set Cache-Control: no-store.

        The response contains the user's private key. Without no-store, the
        key may be written to the browser's disk cache or a proxy cache.
        """
        root_app.config.update({
            'WTF_CSRF_ENABLED': False,
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

        mock_key = MagicMock()
        mock_key.private_bytes.return_value = b'-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----'
        mock_csr = MagicMock()
        mock_csr.subject.get_attributes_for_oid.return_value = [MagicMock(value='user@example.com')]
        mock_csr.public_bytes.return_value = b'-----BEGIN CERTIFICATE REQUEST-----\ncsr\n-----END CERTIFICATE REQUEST-----'
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

        with root_app.test_client() as client:
            with client.session_transaction() as sess:
                sess['user'] = {
                    'sub': 'user@example.com',
                    'email': 'user@example.com',
                    'groups': 'default',
                }
            response = client.post('/', data={'submit': 'Generate Profile'})

        assert response.status_code == 200
        assert 'no-store' in response.headers.get('Cache-Control', '')
        assert response.headers.get('Pragma') == 'no-cache'

    def test_admin_psk_creation_has_cache_control_no_store(self, admin_app):
        """POST /admin/psk/new (PSK creation) response must set Cache-Control: no-store.

        The response displays the plaintext PSK exactly once. Without no-store,
        the PSK may be retained in the browser cache and retrieved later.
        """
        with patch('app.utils.server_templates.get_template_set_choices') as mock_choices, \
             patch('app.routes.admin.render_template', return_value='PSK Created Page'):
            mock_choices.return_value = [('default', 'Default')]

            with admin_app.test_client() as client:
                with client.session_transaction() as sess:
                    sess['user'] = {
                        'sub': 'admin@example.com',
                        'email': 'admin@example.com',
                        'groups': ['admins'],
                    }

                response = client.post('/admin/psk/new', data={
                    'description': 'VULN13 Test PSK',
                    'template_set': 'default',
                })

        assert response.status_code == 200
        assert 'no-store' in response.headers.get('Cache-Control', '')
        assert response.headers.get('Pragma') == 'no-cache'

    @patch('app.utils.security_logging.security_logger.log_psk_created')
    @patch('app.routes.api.service_admin.uuid.uuid4')
    def test_computer_psk_api_has_cache_control_no_store(self, mock_uuid, mock_log, service_admin_client):
        """POST /api/psks/computer response must set Cache-Control: no-store.

        The JSON response includes the plaintext PSK key. Without no-store,
        any proxy or browser cache may store the credential.
        """
        mock_uuid.return_value = 'vuln13-test-uuid'

        response = service_admin_client.post(
            '/api/psks/computer',
            json={'description': 'VULN13 Computer PSK'},
        )

        assert response.status_code == 201
        assert 'no-store' in response.headers.get('Cache-Control', '')
        assert response.headers.get('Pragma') == 'no-cache'
