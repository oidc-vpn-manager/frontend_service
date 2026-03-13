import json
import uuid
from datetime import datetime, timezone, timedelta
from app.extensions import db
from app.models.base import SecureModelMixin


class DownloadToken(SecureModelMixin, db.Model):
    """
    Represents a one-time-use download token for OpenVPN profile retrieval.

    Used by both the CLI workflow (get_openvpn_config) and the WEB_AUTH flow
    (OpenVPN Connect /openvpn-api/profile endpoint). Stores the authenticated
    user's identity, OIDC group memberships for template selection, and
    certificate expiry for profile freshness checks.

    Security considerations:
    - Mass assignment protection via SecureModelMixin prevents setting sensitive
      fields (collected, downloadable) through user-supplied input.
    - user_groups is stored as JSON text; always access via get_user_groups_list()
      to guard against malformed data.
    - Tokens have a 5-minute redemption window (is_download_window_expired).
    - cert_expiry supports the WEB_AUTH HEAD freshness check so OpenVPN Connect
      can determine whether a profile needs renewal without re-authenticating.
    """

    __tablename__ = 'download_tokens'
    id = db.Column(db.Integer, primary_key=True)

    # Mass assignment protection - only allow these fields during creation/update
    _allowed_attributes = [
        'user', 'cn', 'requester_ip', 'requester_user_agent', 'cert_expiry',
        'user_agent_string', 'detected_os', 'optionset_used', 'ovpn_content',
        'user_groups',
        # Note: 'downloadable' and 'collected' intentionally excluded to test protection
    ]

    token = db.Column(db.String(36), unique=True, nullable=False, index=True, default=lambda: str(uuid.uuid4()))
    user = db.Column(db.String(255), nullable=False, index=True)
    cn = db.Column(db.String(255), nullable=True, index=True)
    requester_ip = db.Column(db.String(45), nullable=True)
    requester_user_agent = db.Column(db.Text, nullable=True)
    cert_expiry = db.Column(db.DateTime(timezone=True), nullable=True)
    user_agent_string = db.Column(db.String(255), nullable=True)
    detected_os = db.Column(db.String(50), nullable=True)
    optionset_used = db.Column(db.String(255), nullable=True)
    ovpn_content = db.Column(db.LargeBinary, nullable=True)
    user_groups = db.Column(db.Text, nullable=True)
    downloadable = db.Column(db.Boolean, nullable=False, default=True)
    collected = db.Column(db.Boolean, nullable=False, default=False)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))

    def is_download_window_expired(self):
        """
        Checks whether the 5-minute profile download window has expired.

        The redemption window prevents token replay: a DownloadToken is valid
        for exactly 5 minutes after creation. After that, the token cannot be
        used to download a profile even if it has not been collected.

        Returns:
            bool: True if the window has expired, False if still open.

        Example:
            >>> token = DownloadToken()
            >>> token.created_at = datetime.now(timezone.utc)
            >>> token.is_download_window_expired()
            False
        """
        created_at_utc = self.created_at
        if created_at_utc.tzinfo is None:
            created_at_utc = created_at_utc.replace(tzinfo=timezone.utc)
        return datetime.now(timezone.utc) > created_at_utc + timedelta(minutes=5)

    def get_user_groups_list(self):
        """
        Returns the user's OIDC group memberships as a Python list.

        Parses the JSON-encoded user_groups field. Returns an empty list when
        user_groups is None (backward-compatible with pre-existing CLI tokens)
        or when the stored value is malformed JSON.

        Used by the download route to select the appropriate OpenVPN template
        based on the user's group memberships.

        Returns:
            list[str]: OIDC group names, or [] if not set or unparseable.

        Example:
            >>> token = DownloadToken()
            >>> token.user_groups = '["engineering", "vpn-users"]'
            >>> token.get_user_groups_list()
            ['engineering', 'vpn-users']
            >>> token.user_groups = None
            >>> token.get_user_groups_list()
            []

        Security:
            Returns an empty list rather than raising on malformed JSON to
            prevent information leakage or denial-of-service from corrupt data.
        """
        if self.user_groups is None:
            return []
        try:
            return json.loads(self.user_groups)
        except (json.JSONDecodeError, TypeError):
            return []
