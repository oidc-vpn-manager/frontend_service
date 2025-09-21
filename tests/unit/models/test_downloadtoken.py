"""
Unit tests for the DownloadToken model.
"""

from datetime import datetime, timezone, timedelta
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