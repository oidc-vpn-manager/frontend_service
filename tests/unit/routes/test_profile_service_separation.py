"""Lock in the deployment-side rules for profile-issuing endpoints.

Three rules are enforced by service-separation decorators on the frontend:

* ``/api/v1/server/bundle``    — admin service only (PSK-authenticated by
  privileged operators provisioning OpenVPN servers).
* ``/api/v1/computer/bundle``  — user service only  (PSK-authenticated by
  managed devices that have no route to the admin side).
* ``/download`` and ``/download/<token_id>`` — user service only (token-based
  user-profile delivery driven by the OIDC login flow).

These tests fail loudly if a future refactor accidentally swaps the decorator
on any of these routes — the original bug was a ``computer_bundle`` route
mistakenly decorated ``@admin_service_only_api`` which made the endpoint
unreachable from any node that could only see the user-service URL.

The tests do not exercise PSK auth or actual bundle generation; they only
assert the routing-layer behaviour of the decorators.
"""

import pytest


# ---------------------------------------------------------------------------
# /api/v1/server/bundle  — admin service only
# ---------------------------------------------------------------------------

class TestServerBundleAdminOnly:
    """``/api/v1/server/bundle`` must be reachable only on the admin service."""

    def test_blocked_on_user_service(self, client, app):
        """When ``ADMIN_URL_BASE`` is set this is the user service: must return 403."""
        app.config['ADMIN_URL_BASE'] = 'https://admin.example.com'

        response = client.get('/api/v1/server/bundle')

        assert response.status_code == 403, (
            "server bundle must be 403 Forbidden on the user service deployment"
        )

    def test_decorator_passes_through_on_admin_service(self, client, app):
        """When ``USER_URL_BASE`` is set this is the admin service: decorator must let the request through."""
        app.config['USER_URL_BASE'] = 'https://user.example.com'

        response = client.get('/api/v1/server/bundle')

        # Decorator did not abort with 403; the request reached psk_required and
        # was rejected for missing PSK auth (401). Anything other than 403 is
        # acceptable here — the rule under test is "decorator allows through".
        assert response.status_code != 403, (
            "server bundle must not be blocked on the admin service deployment"
        )
        assert response.status_code == 401

    def test_decorator_passes_through_on_combined_service(self, client, app):
        """Combined deployment (no URL_BASE set): decorator no-op, request reaches psk_required."""
        app.config.pop('ADMIN_URL_BASE', None)
        app.config.pop('USER_URL_BASE', None)

        response = client.get('/api/v1/server/bundle')

        assert response.status_code == 401, (
            "server bundle on combined service should reach psk_required and 401"
        )


# ---------------------------------------------------------------------------
# /api/v1/computer/bundle  — user service only
# ---------------------------------------------------------------------------

class TestComputerBundleUserOnly:
    """``/api/v1/computer/bundle`` must be reachable only on the user service."""

    def test_redirected_on_admin_service(self, client, app):
        """When ``USER_URL_BASE`` is set this is the admin service: must 301 redirect to user service."""
        app.config['USER_URL_BASE'] = 'https://user.example.com'

        response = client.get('/api/v1/computer/bundle')

        assert response.status_code == 301, (
            "computer bundle must 301 redirect to user service when hit on admin"
        )
        assert response.headers['Location'].startswith(
            'https://user.example.com/api/v1/computer/bundle'
        ), f"redirect target wrong: {response.headers.get('Location')}"

    def test_decorator_passes_through_on_user_service(self, client, app):
        """When ``ADMIN_URL_BASE`` is set this is the user service: decorator must let the request through."""
        app.config['ADMIN_URL_BASE'] = 'https://admin.example.com'

        response = client.get('/api/v1/computer/bundle')

        assert response.status_code != 301, (
            "computer bundle must not redirect when hit on user service"
        )
        assert response.status_code == 401, (
            "computer bundle on user service should reach psk_required and 401"
        )

    def test_decorator_passes_through_on_combined_service(self, client, app):
        """Combined deployment (no URL_BASE set): decorator no-op, request reaches psk_required."""
        app.config.pop('ADMIN_URL_BASE', None)
        app.config.pop('USER_URL_BASE', None)

        response = client.get('/api/v1/computer/bundle')

        assert response.status_code == 401, (
            "computer bundle on combined service should reach psk_required and 401"
        )


# ---------------------------------------------------------------------------
# /download  — user service only (drives the user-profile OIDC flow)
# ---------------------------------------------------------------------------

class TestUserProfileDownloadUserOnly:
    """``/download`` is the user-profile delivery endpoint and must be user-side."""

    def test_redirected_on_admin_service(self, client, app):
        """When ``USER_URL_BASE`` is set this is the admin service: must 301 redirect to user service."""
        app.config['USER_URL_BASE'] = 'https://user.example.com'

        response = client.get('/download?token=any-token')

        assert response.status_code == 301, (
            "user profile download must 301 redirect to user service when hit on admin"
        )
        assert response.headers['Location'].startswith(
            'https://user.example.com/download'
        ), f"redirect target wrong: {response.headers.get('Location')}"

    def test_decorator_passes_through_on_user_service(self, client, app):
        """When ``ADMIN_URL_BASE`` is set this is the user service: decorator must let the request through."""
        app.config['ADMIN_URL_BASE'] = 'https://admin.example.com'
        # The unit-test ``app`` fixture has TESTING=True, which makes Flask
        # propagate handler exceptions instead of returning 500. We override
        # that here so a DB-layer failure inside the handler does not mask
        # the routing-layer assertion below.
        app.config['PROPAGATE_EXCEPTIONS'] = False

        # The route reaches the handler; whatever the handler does (400 token
        # invalid, 500 if the in-memory DB has no DownloadToken table, etc.)
        # is acceptable — the rule under test is "the decorator did not 301".
        response = client.get('/download?token=nonexistent-token')

        assert response.status_code != 301, (
            "user profile download must not redirect when hit on user service"
        )

    def test_path_segment_form_redirected_on_admin_service(self, client, app):
        """The ``/download/<token_id>`` form must also redirect when hit on admin."""
        app.config['USER_URL_BASE'] = 'https://user.example.com'

        response = client.get('/download/some-token-id')

        assert response.status_code == 301
        assert response.headers['Location'].startswith(
            'https://user.example.com/download/some-token-id'
        )
