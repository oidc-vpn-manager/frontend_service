"""
Unit tests for the User-Agent the OIDC client sends to the identity provider.

The back-channel requests Authlib makes (discovery, JWKS, token exchange,
userinfo) leave the server, not the browser. A CDN or WAF in front of the
identity provider may refuse generic library user agents, so the client names
this service explicitly instead of relying on Authlib's default.
"""

import re

from app.extensions import OIDC_USER_AGENT, oauth


def test_oidc_user_agent_names_the_service():
    """
    The configured User-Agent identifies this service and carries a version.

    Expected: ``oidc-vpn-manager-frontend/1``.
    """
    assert OIDC_USER_AGENT == "oidc-vpn-manager-frontend/1"


def test_oidc_client_sessions_send_the_service_user_agent(app):
    """
    Every session the registered OIDC client builds carries the service UA.

    Authlib applies ``user_agent`` to the session it creates for the token
    exchange and for metadata/JWKS fetches, so checking the session headers
    covers all back-channel calls.
    """
    with app.app_context():
        session = oauth.oidc._get_oauth_client()
    assert session.headers["User-Agent"] == OIDC_USER_AGENT


def test_oidc_user_agent_discloses_no_library_or_runtime(app):
    """
    The User-Agent does not reveal the HTTP library, Authlib or Python version.

    Information-disclosure lens: Authlib's default UA advertises the library
    name and exact version, which tells an observer of outbound traffic which
    CVEs to try. The service UA must name only the service.
    """
    with app.app_context():
        session = oauth.oidc._get_oauth_client()
    user_agent = session.headers["User-Agent"]
    assert not re.search(r"authlib|python|requests|httpx|urllib", user_agent, re.IGNORECASE)
