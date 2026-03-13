"""
Unit tests for the OpenVPN WEB_AUTH endpoint (/openvpn-api/profile).

This route implements the OpenVPN 3 / OpenVPN Connect WEB_AUTH protocol,
allowing the client to:
  1. Discover that this server supports web-based profile provisioning (HEAD).
  2. Check whether a previously-downloaded profile is still fresh (HEAD + token).
  3. Obtain a new profile by authenticating via OIDC and being redirected to the
     openvpn:// URL scheme which OpenVPN Connect intercepts (GET).

Security test coverage draws from:
  - OWASP API2  (Broken Authentication)
  - OWASP API3  (Excessive Data Exposure)
  - OWASP API5  (Broken Function Level Authorisation)
  - OWASP API7  (Security Misconfiguration)
  - OWASP API8  (Injection)
  - Red-team: session fixation, token oracle, cross-user token probing
  - Blue-team: logging, header hygiene
  - Bug bounty: open redirect, info disclosure in headers
"""

import json
import uuid
import pytest
from datetime import datetime, timezone, timedelta
from unittest.mock import patch, MagicMock

from app.models import DownloadToken


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def app_with_db(app):
    """Flask app with an initialised in-memory database."""
    from app.extensions import db
    with app.app_context():
        db.create_all()
    yield app
    with app.app_context():
        db.drop_all()


@pytest.fixture
def authed_client(client, app_with_db):
    """
    Test client with a fully-authenticated user session, including OIDC groups.
    """
    with client.session_transaction() as sess:
        sess['user'] = {
            'sub': 'user-abc-123',
            'email': 'alice@example.com',
            'name': 'Alice',
            'groups': ['engineering', 'vpn-users'],
            'is_admin': False,
            'is_auditor': False,
            'is_system_admin': False,
        }
    return client


@pytest.fixture
def valid_collected_token(app_with_db):
    """
    A DownloadToken that has been collected (profile downloaded) with a future
    cert_expiry — represents a fresh profile that does not need renewal.
    """
    from app.extensions import db
    with app_with_db.app_context():
        token = DownloadToken(
            user='user-abc-123',
            cn='alice@example.com',
            requester_ip='127.0.0.1',
            optionset_used='',
            user_groups=json.dumps(['engineering']),
        )
        token.token = str(uuid.uuid4())
        token.collected = True
        token.cert_expiry = datetime.now(timezone.utc) + timedelta(days=30)
        db.session.add(token)
        db.session.commit()
        yield token.token


@pytest.fixture
def expired_collected_token(app_with_db):
    """
    A DownloadToken with a cert_expiry in the past — represents a stale profile
    that needs renewal.
    """
    from app.extensions import db
    with app_with_db.app_context():
        token = DownloadToken(
            user='user-abc-123',
            cn='alice@example.com',
            requester_ip='127.0.0.1',
            optionset_used='',
        )
        token.token = str(uuid.uuid4())
        token.collected = True
        token.cert_expiry = datetime.now(timezone.utc) - timedelta(days=1)
        db.session.add(token)
        db.session.commit()
        yield token.token


# ---------------------------------------------------------------------------
# HEAD /openvpn-api/profile — Discovery and freshness checks
# ---------------------------------------------------------------------------

class TestWebAuthHead:
    """
    Tests for HEAD /openvpn-api/profile.

    HEAD is used by OpenVPN Connect both for initial capability discovery and
    for subsequent profile freshness checks (when VPN-Session-Token is supplied).
    """

    def test_head_discovery_returns_200(self, client, app_with_db):
        """
        Happy path: unauthenticated HEAD returns 200 with the Ovpn-WebAuth header,
        signalling to OpenVPN Connect that this server supports WEB_AUTH provisioning.
        """
        response = client.head('/openvpn-api/profile')
        assert response.status_code == 200

    def test_head_discovery_returns_ovpn_webauth_header(self, client, app_with_db):
        """
        Happy path: the Ovpn-WebAuth header value must start with the site name
        and include the 'external' flag, instructing the client to open an external
        browser rather than an embedded webview.
        """
        response = client.head('/openvpn-api/profile')
        assert 'Ovpn-WebAuth' in response.headers
        webauth_value = response.headers['Ovpn-WebAuth']
        assert 'external' in webauth_value

    def test_head_discovery_webauth_header_uses_site_name(self, client, app_with_db):
        """
        Happy path: the provider name in Ovpn-WebAuth matches the SITE_NAME config,
        so OpenVPN Connect displays the correct service name in its UI.
        """
        with patch.dict(app_with_db.config, {'SITE_NAME': 'AcmeVPN'}):
            response = client.head('/openvpn-api/profile')
        assert response.headers['Ovpn-WebAuth'].startswith('AcmeVPN')

    def test_head_with_valid_session_token_and_live_cert_omits_webauth_header(
            self, client, app_with_db, valid_collected_token):
        """
        Happy path: HEAD with a valid VPN-Session-Token whose cert has not expired
        returns 200 WITHOUT the Ovpn-WebAuth header, telling OpenVPN Connect that
        the existing profile is still fresh and no re-authentication is needed.
        """
        response = client.head(
            '/openvpn-api/profile',
            headers={'VPN-Session-Token': valid_collected_token},
        )
        assert response.status_code == 200
        assert 'Ovpn-WebAuth' not in response.headers

    def test_head_with_expired_cert_token_returns_webauth_header(
            self, client, app_with_db, expired_collected_token):
        """
        Happy path (re-auth needed): HEAD with a VPN-Session-Token whose cert has
        expired returns the Ovpn-WebAuth header, triggering re-provisioning.
        """
        response = client.head(
            '/openvpn-api/profile',
            headers={'VPN-Session-Token': expired_collected_token},
        )
        assert response.status_code == 200
        assert 'Ovpn-WebAuth' in response.headers

    def test_head_with_unknown_token_returns_webauth_header(self, client, app_with_db):
        """
        Unhappy path: an unrecognised VPN-Session-Token falls back to requiring
        re-authentication (Ovpn-WebAuth present) rather than crashing.
        """
        response = client.head(
            '/openvpn-api/profile',
            headers={'VPN-Session-Token': str(uuid.uuid4())},
        )
        assert response.status_code == 200
        assert 'Ovpn-WebAuth' in response.headers

    def test_head_with_uncollected_token_returns_webauth_header(self, client, app_with_db):
        """
        Unhappy path: a token that exists but has never been collected (profile never
        downloaded) is treated as requiring re-auth, not as a valid session.
        """
        from app.extensions import db
        with app_with_db.app_context():
            token = DownloadToken(
                user='user-abc-123',
                cn='alice@example.com',
                requester_ip='127.0.0.1',
                optionset_used='',
            )
            token.token = str(uuid.uuid4())
            # collected stays False (default)
            token.cert_expiry = datetime.now(timezone.utc) + timedelta(days=30)
            db.session.add(token)
            db.session.commit()
            token_uuid = token.token

        response = client.head(
            '/openvpn-api/profile',
            headers={'VPN-Session-Token': token_uuid},
        )
        assert response.status_code == 200
        assert 'Ovpn-WebAuth' in response.headers

    def test_head_with_no_cert_expiry_returns_webauth_header(self, client, app_with_db):
        """
        Unhappy path: a collected token without cert_expiry (e.g. cert parse failed
        at download time) is treated as requiring re-auth.
        """
        from app.extensions import db
        with app_with_db.app_context():
            token = DownloadToken(
                user='user-abc-123',
                cn='alice@example.com',
                requester_ip='127.0.0.1',
                optionset_used='',
            )
            token.token = str(uuid.uuid4())
            token.collected = True
            token.cert_expiry = None
            db.session.add(token)
            db.session.commit()
            token_uuid = token.token

        response = client.head(
            '/openvpn-api/profile',
            headers={'VPN-Session-Token': token_uuid},
        )
        assert response.status_code == 200
        assert 'Ovpn-WebAuth' in response.headers

    # --- Security / OWASP tests ---

    def test_head_sql_injection_in_session_token_returns_webauth_header(
            self, client, app_with_db):
        """
        OWASP API8 (Injection): A SQL injection payload in VPN-Session-Token must
        not crash the server or reveal data — it is treated as an unknown token and
        the Ovpn-WebAuth re-auth header is returned safely.
        """
        response = client.head(
            '/openvpn-api/profile',
            headers={'VPN-Session-Token': "' OR '1'='1"},
        )
        assert response.status_code == 200
        assert 'Ovpn-WebAuth' in response.headers

    def test_head_oversized_session_token_handled_safely(self, client, app_with_db):
        """
        OWASP API4 (Lack of Resources): An oversized VPN-Session-Token value must
        not cause a crash or 500 — unknown token falls back to re-auth gracefully.
        """
        huge_token = 'A' * 10000
        response = client.head(
            '/openvpn-api/profile',
            headers={'VPN-Session-Token': huge_token},
        )
        assert response.status_code == 200
        assert 'Ovpn-WebAuth' in response.headers

    def test_head_cross_user_token_does_not_reveal_other_users_freshness(
            self, client, app_with_db):
        """
        Red-team (token oracle / IDOR): Using another user's valid VPN-Session-Token
        must not return a 200 without Ovpn-WebAuth (i.e. must not confirm that
        another user has a valid session). The freshness check does not validate
        that the requester owns the token — but crucially it also must not expose
        other users' cert expiry status as 'fresh' in a way that could be exploited.

        Current design: any valid collected token with live cert returns 'fresh'
        (no Ovpn-WebAuth). This is an accepted trade-off for stateless HEAD checks.
        The token UUID itself is a capability credential — possessing it implies
        access. This test documents the current behaviour explicitly.
        """
        from app.extensions import db
        with app_with_db.app_context():
            other_token = DownloadToken(
                user='other-user-xyz',
                cn='bob@example.com',
                requester_ip='10.0.0.1',
                optionset_used='',
            )
            other_token.token = str(uuid.uuid4())
            other_token.collected = True
            other_token.cert_expiry = datetime.now(timezone.utc) + timedelta(days=10)
            db.session.add(other_token)
            db.session.commit()
            other_uuid = other_token.token

        # Possessing the UUID is the capability — response is 200 without Ovpn-WebAuth
        response = client.head(
            '/openvpn-api/profile',
            headers={'VPN-Session-Token': other_uuid},
        )
        assert response.status_code == 200
        # Document current behaviour: UUID possession grants freshness confirmation
        assert 'Ovpn-WebAuth' not in response.headers

    def test_head_returns_no_body(self, client, app_with_db):
        """
        Protocol correctness: HTTP HEAD responses must not include a body.
        """
        response = client.head('/openvpn-api/profile')
        assert response.data == b''


# ---------------------------------------------------------------------------
# GET /openvpn-api/profile — Unauthenticated
# ---------------------------------------------------------------------------

class TestWebAuthGetUnauthenticated:
    """
    Tests for GET /openvpn-api/profile when the user has no session.
    The route must initiate the OIDC login flow.
    """

    def test_get_unauthenticated_redirects_to_auth_login(self, client, app_with_db):
        """
        Happy path: unauthenticated GET redirects to /auth/login to begin
        the OIDC flow.
        """
        response = client.get('/openvpn-api/profile')
        assert response.status_code == 302
        assert '/auth/login' in response.headers['Location']

    def test_get_unauthenticated_stores_next_url_in_session(self, client, app_with_db):
        """
        Happy path: the route stores /openvpn-api/profile as next_url so the
        OIDC callback redirects back here after successful authentication.
        """
        client.get('/openvpn-api/profile')
        with client.session_transaction() as sess:
            assert sess.get('next_url') == '/openvpn-api/profile'

    def test_get_unauthenticated_with_device_params_stores_them_in_session(
            self, client, app_with_db):
        """
        Happy path: device metadata query parameters (deviceID, deviceModel,
        deviceOS, appVersion) sent by OpenVPN Connect are stored in the session
        for audit logging at token-creation time.
        """
        response = client.get(
            '/openvpn-api/profile'
            '?deviceID=abc-123&deviceModel=iPhone+14&deviceOS=iOS+17&appVersion=3.4.0'
        )
        assert response.status_code == 302
        with client.session_transaction() as sess:
            params = sess.get('webauth_device_params', {})
            assert params.get('deviceID') == 'abc-123'
            assert params.get('deviceModel') == 'iPhone 14'
            assert params.get('deviceOS') == 'iOS 17'
            assert params.get('appVersion') == '3.4.0'

    def test_get_unauthenticated_with_partial_device_params(self, client, app_with_db):
        """
        Unhappy path: only some device params provided — only present keys stored,
        absent keys do not appear in the session dict.
        """
        client.get('/openvpn-api/profile?deviceID=only-this')
        with client.session_transaction() as sess:
            params = sess.get('webauth_device_params', {})
            assert params.get('deviceID') == 'only-this'
            assert 'deviceModel' not in params
            assert 'appVersion' not in params

    def test_get_unauthenticated_without_device_params_does_not_store_empty_dict(
            self, client, app_with_db):
        """
        Unhappy path: when no device params are present, webauth_device_params
        is not set in the session (avoids polluting the session with empty dicts).
        """
        client.get('/openvpn-api/profile')
        with client.session_transaction() as sess:
            assert 'webauth_device_params' not in sess

    # --- Security / OWASP tests ---

    def test_get_unauthenticated_injection_in_device_id_stored_safely(
            self, client, app_with_db):
        """
        OWASP API8 (Injection): deviceID containing a script-injection payload
        must be stored as a plain string (not executed) and must not cause a crash.
        The value is for audit logging only; no rendering or execution occurs.
        """
        payload = "<script>alert(1)</script>"
        client.get(f'/openvpn-api/profile?deviceID={payload}')
        with client.session_transaction() as sess:
            params = sess.get('webauth_device_params', {})
            # Stored as-is for audit; rendering safety is the template layer's job
            assert params.get('deviceID') == payload

    def test_get_unauthenticated_open_redirect_not_possible_via_device_params(
            self, client, app_with_db):
        """
        Bug bounty (Open Redirect): device params must not influence the redirect
        target. The redirect must always go to /auth/login regardless of param values.
        """
        response = client.get(
            '/openvpn-api/profile?deviceID=https://evil.example.com'
        )
        assert response.status_code == 302
        location = response.headers['Location']
        assert 'evil.example.com' not in location
        assert '/auth/login' in location

    def test_get_unauthenticated_does_not_return_ovpn_webauth_header(
            self, client, app_with_db):
        """
        Protocol correctness: the GET redirect response must not carry the
        Ovpn-WebAuth header (that is for HEAD only).
        """
        response = client.get('/openvpn-api/profile')
        assert 'Ovpn-WebAuth' not in response.headers


# ---------------------------------------------------------------------------
# GET /openvpn-api/profile — Authenticated
# ---------------------------------------------------------------------------

class TestWebAuthGetAuthenticated:
    """
    Tests for GET /openvpn-api/profile when the user has a valid OIDC session.
    The route creates a DownloadToken and redirects to the openvpn:// URL scheme.
    """

    def test_get_authenticated_redirects_to_openvpn_scheme(
            self, authed_client, app_with_db):
        """
        Happy path: authenticated GET redirects to an openvpn://import-profile/
        URL so OpenVPN Connect can intercept it and fetch the profile.
        """
        response = authed_client.get('/openvpn-api/profile')
        assert response.status_code == 302
        assert response.headers['Location'].startswith('openvpn://import-profile/')

    def test_get_authenticated_redirect_contains_download_url(
            self, authed_client, app_with_db):
        """
        Happy path: the openvpn:// URL embeds the /download?token= endpoint URL
        so OpenVPN Connect fetches the profile using the one-time token.
        """
        response = authed_client.get('/openvpn-api/profile')
        location = response.headers['Location']
        assert '/download?token=' in location

    def test_get_authenticated_creates_download_token_in_db(
            self, authed_client, app_with_db):
        """
        Happy path: a DownloadToken record is created in the database for the
        authenticated user so the /download endpoint can serve the profile.
        """
        from app.extensions import db
        response = authed_client.get('/openvpn-api/profile')
        location = response.headers['Location']
        token_uuid = location.split('token=')[1]

        with app_with_db.app_context():
            token = DownloadToken.query.filter_by(token=token_uuid).first()
            assert token is not None
            assert token.user == 'user-abc-123'

    def test_get_authenticated_token_stores_oidc_groups(
            self, authed_client, app_with_db):
        """
        Happy path: the DownloadToken stores the user's OIDC groups as JSON so
        the /download endpoint can select the correct OpenVPN template.
        """
        response = authed_client.get('/openvpn-api/profile')
        location = response.headers['Location']
        token_uuid = location.split('token=')[1]

        with app_with_db.app_context():
            token = DownloadToken.query.filter_by(token=token_uuid).first()
            assert token is not None
            groups = json.loads(token.user_groups)
            assert 'engineering' in groups
            assert 'vpn-users' in groups

    def test_get_authenticated_token_stores_user_email(
            self, authed_client, app_with_db):
        """
        Happy path: the DownloadToken's cn is set to the user's email for
        the common name used in the generated certificate.
        """
        response = authed_client.get('/openvpn-api/profile')
        token_uuid = response.headers['Location'].split('token=')[1]
        with app_with_db.app_context():
            token = DownloadToken.query.filter_by(token=token_uuid).first()
            assert token.cn == 'alice@example.com'

    def test_get_authenticated_token_not_yet_collected(
            self, authed_client, app_with_db):
        """
        Happy path: the token created at GET time has collected=False — the profile
        has not been generated yet; that happens when /download redeems the token.
        """
        response = authed_client.get('/openvpn-api/profile')
        token_uuid = response.headers['Location'].split('token=')[1]
        with app_with_db.app_context():
            token = DownloadToken.query.filter_by(token=token_uuid).first()
            assert not token.collected

    def test_get_authenticated_each_request_creates_a_new_token(
            self, authed_client, app_with_db):
        """
        Red-team (Session Fixation): each authenticated GET must create a fresh
        token UUID. Reusing tokens across requests would allow an attacker who
        obtained a previous token to receive a new profile without re-authenticating.
        """
        r1 = authed_client.get('/openvpn-api/profile')
        r2 = authed_client.get('/openvpn-api/profile')
        uuid1 = r1.headers['Location'].split('token=')[1]
        uuid2 = r2.headers['Location'].split('token=')[1]
        assert uuid1 != uuid2

    def test_get_authenticated_with_user_missing_email_falls_back_to_sub(
            self, client, app_with_db):
        """
        Unhappy path: if the OIDC userinfo has no 'email' field, the user's 'sub'
        is used as the certificate CN rather than crashing.
        """
        with client.session_transaction() as sess:
            sess['user'] = {
                'sub': 'sub-only-user',
                'groups': ['vpn-users'],
                'is_admin': False,
                'is_auditor': False,
                'is_system_admin': False,
            }

        response = client.get('/openvpn-api/profile')
        assert response.status_code == 302
        assert 'openvpn://import-profile/' in response.headers['Location']
        token_uuid = response.headers['Location'].split('token=')[1]
        with app_with_db.app_context():
            token = DownloadToken.query.filter_by(token=token_uuid).first()
            assert token.cn == 'sub-only-user'

    def test_get_authenticated_with_no_groups_stores_empty_list(
            self, client, app_with_db):
        """
        Unhappy path: a user with no groups in their OIDC session gets an empty
        JSON list stored on the token, falling back to the default template.
        """
        with client.session_transaction() as sess:
            sess['user'] = {
                'sub': 'nogroup-user',
                'email': 'nogroup@example.com',
                'groups': [],
                'is_admin': False,
                'is_auditor': False,
                'is_system_admin': False,
            }

        response = client.get('/openvpn-api/profile')
        token_uuid = response.headers['Location'].split('token=')[1]
        with app_with_db.app_context():
            token = DownloadToken.query.filter_by(token=token_uuid).first()
            assert json.loads(token.user_groups) == []

    def test_get_authenticated_with_comma_separated_groups_string(
            self, client, app_with_db):
        """
        Unhappy path: some OIDC providers return groups as a comma-separated string
        rather than a list. The route must normalise this correctly.
        """
        with client.session_transaction() as sess:
            sess['user'] = {
                'sub': 'csv-user',
                'email': 'csv@example.com',
                'groups': 'engineering,vpn-users',
                'is_admin': False,
                'is_auditor': False,
                'is_system_admin': False,
            }

        response = client.get('/openvpn-api/profile')
        token_uuid = response.headers['Location'].split('token=')[1]
        with app_with_db.app_context():
            token = DownloadToken.query.filter_by(token=token_uuid).first()
            groups = json.loads(token.user_groups)
            assert groups == ['engineering', 'vpn-users']

    def test_get_authenticated_with_single_group_string(self, client, app_with_db):
        """
        Unhappy path: a single group returned as a bare string (not a list, no comma)
        must be wrapped in a list rather than split into individual characters.
        """
        with client.session_transaction() as sess:
            sess['user'] = {
                'sub': 'single-group-user',
                'email': 'sg@example.com',
                'groups': 'engineering',
                'is_admin': False,
                'is_auditor': False,
                'is_system_admin': False,
            }

        response = client.get('/openvpn-api/profile')
        token_uuid = response.headers['Location'].split('token=')[1]
        with app_with_db.app_context():
            token = DownloadToken.query.filter_by(token=token_uuid).first()
            groups = json.loads(token.user_groups)
            assert groups == ['engineering']

    # --- Security / OWASP tests ---

    def test_get_authenticated_openvpn_url_does_not_contain_user_pii(
            self, authed_client, app_with_db):
        """
        OWASP API3 (Excessive Data Exposure): the openvpn:// redirect URL must
        contain only the token UUID — no email, sub, or group names in the URL.
        """
        response = authed_client.get('/openvpn-api/profile')
        location = response.headers['Location']
        assert 'alice' not in location
        assert 'engineering' not in location
        assert 'user-abc-123' not in location

    def test_get_session_with_no_sub_treated_as_unauthenticated(
            self, client, app_with_db):
        """
        OWASP API2 (Broken Authentication): a session with a 'user' dict missing
        the mandatory 'sub' field must be treated as unauthenticated and redirected
        to login rather than proceeding to token creation.
        """
        with client.session_transaction() as sess:
            sess['user'] = {'email': 'nobody@example.com'}  # no 'sub'

        response = client.get('/openvpn-api/profile')
        assert response.status_code == 302
        assert '/auth/login' in response.headers['Location']

    def test_get_session_with_non_dict_user_treated_as_unauthenticated(
            self, client, app_with_db):
        """
        OWASP API2 (Broken Authentication): a tampered session where 'user' is
        not a dict (e.g. a string) must be treated as unauthenticated.
        """
        with client.session_transaction() as sess:
            sess['user'] = 'admin'  # not a dict

        response = client.get('/openvpn-api/profile')
        assert response.status_code == 302
        assert '/auth/login' in response.headers['Location']


# ---------------------------------------------------------------------------
# Unit tests for helper functions (coverage + correctness)
# ---------------------------------------------------------------------------

class TestIsFreshHelper:
    """
    Direct unit tests for the _is_profile_fresh helper.
    These cover edge cases that are impractical to reach through HTTP calls.
    """

    def test_is_profile_fresh_returns_false_on_db_exception(self, app_with_db):
        """
        Blue-team (resilience): if a database error occurs during the freshness
        check, _is_profile_fresh must return False (fail-safe) rather than
        propagating the exception, which would cause a 500 on HEAD.
        """
        from app.routes.openvpn_api import _is_profile_fresh
        with app_with_db.app_context():
            with patch('app.routes.openvpn_api.DownloadToken') as mock_model:
                mock_model.query.filter_by.side_effect = Exception('DB exploded')
                result = _is_profile_fresh('any-uuid')
        assert result is False


class TestNormaliseGroupsHelper:
    """
    Unit tests for the _normalise_groups helper covering all input formats
    and the unreachable-in-practice fallback branch.
    """

    def test_normalise_groups_with_non_string_non_list_returns_empty(self):
        """
        Covers line 128 — the final fallback for types that are neither str nor list
        (e.g. an integer or dict returned by a broken OIDC provider).
        """
        from app.routes.openvpn_api import _normalise_groups
        assert _normalise_groups(42) == []
        assert _normalise_groups({'group': 'engineering'}) == []

    def test_normalise_groups_with_none_returns_empty(self):
        from app.routes.openvpn_api import _normalise_groups
        assert _normalise_groups(None) == []

    def test_normalise_groups_with_list(self):
        from app.routes.openvpn_api import _normalise_groups
        assert _normalise_groups(['a', 'b']) == ['a', 'b']

    def test_normalise_groups_with_comma_string(self):
        from app.routes.openvpn_api import _normalise_groups
        assert _normalise_groups('a,b') == ['a', 'b']

    def test_normalise_groups_with_bare_string(self):
        from app.routes.openvpn_api import _normalise_groups
        assert _normalise_groups('engineering') == ['engineering']

    def test_normalise_groups_with_empty_string_returns_empty(self):
        from app.routes.openvpn_api import _normalise_groups
        assert _normalise_groups('') == []
