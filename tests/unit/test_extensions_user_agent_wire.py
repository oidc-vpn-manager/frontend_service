"""
On-the-wire tests for the User-Agent on every OIDC back-channel request.

Authlib applies ``user_agent=`` only to the session behind
``_get_oauth_client()`` (token exchange, userinfo). It fetches the discovery
document (``load_server_metadata``) and the JWKS (``fetch_jwk_set``) through a
separate ``client_cls(**client_kwargs)`` session that sends the
``python-requests`` default instead. A CDN or WAF that refuses generic library
user agents therefore breaks login on the first request after every restart,
when the discovery document is not yet cached.

These tests use a real local HTTP server (pytest-httpserver) so they check the
header as received, not the arguments passed to a mock.
"""

import pytest
from flask import Flask

from app.extensions import OIDC_USER_AGENT, ServiceOAuth


@pytest.fixture
def oidc_client(httpserver):
    """
    A registered OIDC client whose identity provider is the local test server.

    Args:
        httpserver: pytest-httpserver fixture acting as the identity provider.

    Returns:
        The registered Authlib client, created from a fresh ``ServiceOAuth``
        registry so the shared application registry is not touched.
    """
    registry = ServiceOAuth(Flask(__name__))
    return registry.register(
        name='oidc',
        server_metadata_url=httpserver.url_for('/.well-known/openid-configuration'),
        client_id='client-id',
        client_secret='client-secret',
        user_agent=OIDC_USER_AGENT,
    )


def test_discovery_request_sends_the_service_user_agent(httpserver, oidc_client):
    """The discovery document fetch carries the service User-Agent."""
    httpserver.expect_request(
        '/.well-known/openid-configuration',
        headers={'User-Agent': OIDC_USER_AGENT},
    ).respond_with_json({'issuer': httpserver.url_for('/')})

    metadata = oidc_client.load_server_metadata()

    assert metadata['issuer'] == httpserver.url_for('/')
    httpserver.check_assertions()


def test_jwks_request_sends_the_service_user_agent(httpserver, oidc_client):
    """The JWKS fetch used to verify ID tokens carries the service User-Agent."""
    httpserver.expect_request(
        '/.well-known/openid-configuration',
        headers={'User-Agent': OIDC_USER_AGENT},
    ).respond_with_json({'jwks_uri': httpserver.url_for('/jwks')})
    httpserver.expect_request(
        '/jwks',
        headers={'User-Agent': OIDC_USER_AGENT},
    ).respond_with_json({'keys': []})

    jwk_set = oidc_client.fetch_jwk_set(force=True)

    assert jwk_set == {'keys': []}
    httpserver.check_assertions()


def test_discovery_fails_when_a_waf_refuses_the_library_user_agent(httpserver):
    """
    Not-happy path: a front-end that refuses generic library user agents.

    Models the Cloudflare rule on ``*.corp-ext``. A plain Authlib registry
    (the library default session) is refused with 403, while the service
    registry is served. This proves the test server really discriminates on
    the header, so the passing tests above are meaningful.
    """
    from authlib.integrations.flask_client import OAuth
    from requests.exceptions import HTTPError
    from werkzeug import Response

    def waf(request):
        if request.headers.get('User-Agent', '').startswith('python-requests'):
            return Response('blocked', status=403)
        return Response('{"issuer": "ok"}', status=200, content_type='application/json')

    httpserver.expect_request('/.well-known/openid-configuration').respond_with_handler(waf)
    url = httpserver.url_for('/.well-known/openid-configuration')

    plain = OAuth(Flask(__name__)).register(
        name='oidc', server_metadata_url=url, client_id='c', client_secret='s',
        user_agent=OIDC_USER_AGENT,
    )
    with pytest.raises(HTTPError):
        plain.load_server_metadata()

    service = ServiceOAuth(Flask(__name__)).register(
        name='oidc', server_metadata_url=url, client_id='c', client_secret='s',
        user_agent=OIDC_USER_AGENT,
    )
    assert service.load_server_metadata()['issuer'] == 'ok'
