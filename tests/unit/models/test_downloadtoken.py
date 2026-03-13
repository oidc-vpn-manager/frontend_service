"""
Unit tests for the DownloadToken model.
"""

from datetime import datetime, timezone, timedelta
import json
import pytest
from freezegun import freeze_time

from app.models.downloadtoken import DownloadToken

class TestDownloadToken:
    """
    Tests the logic within the DownloadToken model.
    """

    def test_is_download_window_not_expired(self):
        """
        Tests that the token is not considered expired within the 5-minute window.
        """
        # Arrange: Create a token at a specific time
        creation_time = datetime(2025, 7, 21, 10, 0, 0, tzinfo=timezone.utc)
        token = DownloadToken()
        token.created_at = creation_time  # Set directly to bypass mass assignment protection
        
        # Act: Freeze time to be 4 minutes and 59 seconds after creation
        with freeze_time("2025-07-21 10:04:59"):
            is_expired = token.is_download_window_expired()

        # Assert: The window should still be open
        assert is_expired is False

    def test_is_download_window_expired(self):
        """
        Tests that the token is considered expired after the 5-minute window.
        """
        # Arrange: Create a token at a specific time
        creation_time = datetime(2025, 7, 21, 10, 0, 0, tzinfo=timezone.utc)
        token = DownloadToken()
        token.created_at = creation_time  # Set directly to bypass mass assignment protection
        
        # Act: Freeze time to be 5 minutes and 1 second after creation
        with freeze_time("2025-07-21 10:05:01"):
            is_expired = token.is_download_window_expired()

        # Assert: The window should be closed
        assert is_expired is True

    def test_is_download_window_at_boundary(self):
        """
        Tests that the token is not expired exactly at the 5-minute mark.
        The condition is `now > created + 5 mins`, so it should be false at the boundary.
        """
        # Arrange: Create a token at a specific time
        creation_time = datetime(2025, 7, 21, 10, 0, 0, tzinfo=timezone.utc)
        token = DownloadToken()
        token.created_at = creation_time  # Set directly to bypass mass assignment protection
        
        # Act: Freeze time to be exactly 5 minutes after creation
        with freeze_time("2025-07-21 10:05:00"):
            is_expired = token.is_download_window_expired()

        # Assert: The window should still be open
        assert is_expired is False

    def test_is_download_window_expired_with_naive_datetime(self):
        """
        Tests that the method correctly handles a timezone-naive created_at value
        by treating it as UTC.
        """
        # Arrange: Create a token with a naive datetime object
        # This simulates data that might have been created without timezone info
        creation_time_naive = datetime(2025, 7, 21, 10, 0, 0)
        token = DownloadToken()
        token.created_at = creation_time_naive  # Set directly to bypass mass assignment protection
        
        # Act: Freeze time to be just outside the 5-minute window in UTC
        with freeze_time("2025-07-21 10:05:01"):
            is_expired = token.is_download_window_expired()

        # Assert: The window should be correctly identified as closed
        assert is_expired is True


class TestDownloadTokenUserGroups:
    """
    Tests for the user_groups field and get_user_groups_list helper method.

    Security considerations:
    - user_groups stores OIDC group memberships used for OpenVPN template selection.
    - Stored as JSON text to support arbitrary group name strings.
    - get_user_groups_list() provides a safe parsed interface used by download routes.
    """

    def test_user_groups_field_exists(self):
        """
        Tests that the DownloadToken model has a user_groups attribute.
        """
        token = DownloadToken()
        assert hasattr(token, 'user_groups')

    def test_user_groups_defaults_to_none(self):
        """
        Tests that user_groups is None when not explicitly set,
        supporting backward compatibility with existing CLI tokens.
        """
        token = DownloadToken()
        assert token.user_groups is None

    def test_user_groups_can_store_json_string(self):
        """
        Tests that user_groups accepts and stores a JSON-encoded list of group names.
        """
        token = DownloadToken()
        groups_json = json.dumps(['engineering', 'vpn-users'])
        token.user_groups = groups_json  # Set directly to bypass mass assignment
        assert token.user_groups == groups_json

    def test_user_groups_allowed_in_constructor(self):
        """
        Tests that user_groups can be set via the constructor (in _allowed_attributes).
        Required so routes can pass groups when creating tokens.
        """
        groups_json = json.dumps(['admin', 'vpn-users'])
        token = DownloadToken(
            user='user123',
            user_groups=groups_json,
        )
        assert token.user_groups == groups_json

    def test_get_user_groups_list_with_populated_groups(self):
        """
        Tests that get_user_groups_list() returns the parsed Python list
        when user_groups contains valid JSON.
        """
        token = DownloadToken()
        token.user_groups = json.dumps(['engineering', 'vpn-users'])
        result = token.get_user_groups_list()
        assert result == ['engineering', 'vpn-users']

    def test_get_user_groups_list_with_none(self):
        """
        Tests that get_user_groups_list() returns an empty list when user_groups is None.
        This ensures backward compatibility with tokens created before this field existed.
        """
        token = DownloadToken()
        token.user_groups = None
        assert token.get_user_groups_list() == []

    def test_get_user_groups_list_with_empty_list(self):
        """
        Tests that get_user_groups_list() returns an empty list when
        user_groups encodes an empty JSON array.
        """
        token = DownloadToken()
        token.user_groups = json.dumps([])
        assert token.get_user_groups_list() == []

    def test_get_user_groups_list_with_single_group(self):
        """
        Tests that get_user_groups_list() works correctly for a single group.
        """
        token = DownloadToken()
        token.user_groups = json.dumps(['vpn-users'])
        assert token.get_user_groups_list() == ['vpn-users']

    def test_get_user_groups_list_with_invalid_json(self):
        """
        Tests that get_user_groups_list() returns an empty list when
        user_groups contains malformed JSON rather than raising an exception.
        Defensive against DB corruption or injection attempts.
        """
        token = DownloadToken()
        token.user_groups = 'not-valid-json'
        assert token.get_user_groups_list() == []

    def test_user_groups_not_accepted_for_sensitive_fields(self):
        """
        OWASP API3 (Mass Assignment): Verifies that fields intentionally excluded
        from _allowed_attributes (downloadable, collected) cannot be set via constructor,
        confirming the protection mechanism still works after adding user_groups.
        """
        token = DownloadToken(
            user='user123',
            user_groups=json.dumps(['vpn-users']),
            collected=True,      # Should be ignored
            downloadable=False,  # Should be ignored
        )
        # collected and downloadable are not set (SQLAlchemy defaults only apply on DB insert)
        # The key assertion is that the constructor silently ignored them rather than raising
        assert token.collected is None  # Not True as supplied - ignored by mass assignment protection
        assert token.downloadable is None  # Not False as supplied - ignored by mass assignment protection