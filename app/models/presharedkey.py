"""
Pre-shared key (PSK) model for OpenVPN Manager certificate authentication.

This module provides secure storage and management of pre-shared keys used for
authenticating requests to certificate generation endpoints. PSKs enable secure
automatic certificate provisioning for servers and computer identities.
"""

import uuid
import hashlib
from datetime import datetime, timezone
from app.extensions import db
from app.utils.cryptography import get_fernet
from app.models.base import SecureModelMixin
from sqlalchemy import LargeBinary

class PreSharedKey(SecureModelMixin, db.Model):
    """
    Pre-shared key model for secure certificate request authentication.

    PSKs provide a secure way to authenticate automated certificate requests
    without requiring interactive user authentication. They support two types:
    - 'server': For OpenVPN server certificate bundles
    - 'computer': For computer identity certificates (site-to-site VPN)

    Security features:
    - Keys are stored as SHA256 hashes (never plaintext)
    - Constant-time verification to prevent timing attacks
    - Usage tracking for audit and monitoring
    - Expiration support for time-limited access
    - Truncated display for identification without exposure

    Attributes:
        id (int): Primary key
        key_hash (str): SHA256 hash of the plaintext key (64 chars)
        description (str): Human-readable description of the PSK purpose
        template_set (str): Template set name for configuration generation
        psk_type (str): Type of PSK ('server' or 'computer')
        key_truncated (str): Truncated key for safe display
        last_used_at (datetime): Timestamp of last usage
        use_count (int): Number of times this PSK has been used
        expires_at (datetime): Optional expiration timestamp
        is_enabled (bool): Whether the PSK is active
        created_at (datetime): Creation timestamp

    Example:
        >>> # Create a new server PSK
        >>> psk = PreSharedKey(
        ...     description="Production Web Server",
        ...     template_set="WebServers",
        ...     psk_type="server",
        ...     key="my-secret-key-123"
        ... )
        >>> db.session.add(psk)
        >>> db.session.commit()
        >>>
        >>> # Verify the key later
        >>> if psk.verify_key("my-secret-key-123") and psk.is_valid():
        ...     psk.record_usage()
        ...     # Allow certificate generation
    """
    __tablename__ = 'pre_shared_keys'
    id = db.Column(db.Integer, primary_key=True)

    # Mass assignment protection - only allow these fields during creation/update
    _allowed_attributes = [
        'description', 'template_set', 'psk_type', 'expires_at',
        'key', 'key_hash', 'key_truncated'  # key handled specially in __init__
    ]
    
    # Store the key as a hash (SHA256) in the database
    key_hash = db.Column(db.String(64), unique=True, nullable=False)
    
    description = db.Column(db.String(255), nullable=False, index=True)
    template_set = db.Column(db.String(100), nullable=False, default='Default')

    # PSK type: 'server' for server bundles, 'computer' for computer-identity (site-to-site, managed assets)
    psk_type = db.Column(db.String(20), nullable=False, default='server', index=True)
    
    # Store truncated version for identification (e.g., "5ffb****-****-****-****-********44de")
    key_truncated = db.Column(db.String(50), nullable=True, index=True)
    
    # Usage tracking
    last_used_at = db.Column(db.DateTime(timezone=True), nullable=True)
    use_count = db.Column(db.Integer, nullable=False, default=0)
    
    expires_at = db.Column(db.DateTime(timezone=True), nullable=True)
    is_enabled = db.Column(db.Boolean, nullable=False, default=True)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))

    def __init__(self, **kwargs):
        """
        Initialize a new PreSharedKey instance.

        Automatically handles key hashing and truncation if a plaintext key
        is provided. If no key is provided, generates a new UUID-based key.

        Args:
            **kwargs: Model attributes including:
                key (str, optional): Plaintext key to hash and store
                description (str): Purpose description
                template_set (str, optional): Template set name (default: 'Default')
                psk_type (str, optional): PSK type (default: 'server')
                expires_at (datetime, optional): Expiration time

        Example:
            >>> psk = PreSharedKey(
            ...     description="API Server",
            ...     key="secret-key-123",
            ...     psk_type="server"
            ... )
        """
        # Set default psk_type if not provided
        if 'psk_type' not in kwargs:
            kwargs['psk_type'] = 'server'

        # If a plaintext key is provided, hash it and store truncated version
        if 'key' in kwargs:
            plaintext_key = kwargs.pop('key')
            kwargs['key_hash'] = self.hash_key(plaintext_key)
            kwargs['key_truncated'] = self.truncate_key(plaintext_key)
        elif 'key_hash' not in kwargs:
            # Generate a new UUID for the key if none provided
            plaintext_key = str(uuid.uuid4())
            kwargs['key_hash'] = self.hash_key(plaintext_key)
            kwargs['key_truncated'] = self.truncate_key(plaintext_key)
        super().__init__(**kwargs)
        
    @staticmethod
    def hash_key(plaintext_key):
        """
        Generate SHA256 hash of a plaintext key for secure database storage.

        Args:
            plaintext_key (str): The plaintext key to hash

        Returns:
            str: 64-character hexadecimal SHA256 hash

        Example:
            >>> hash_val = PreSharedKey.hash_key("my-secret-key")
            >>> len(hash_val)
            64
        """
        return hashlib.sha256(plaintext_key.encode('utf-8')).hexdigest()
    
    @staticmethod
    def truncate_key(plaintext_key):
        """
        Create a truncated version of the key for safe display and identification.

        Shows first 4 and last 4 characters with asterisks in between, formatted
        like a UUID for readability. Used for logging and UI display without
        exposing the actual key.

        Args:
            plaintext_key (str): The plaintext key to truncate

        Returns:
            str: Truncated key in format 'XXXX****-****-****-****-********XXXX'
                 or '****' if key is too short

        Example:
            >>> PreSharedKey.truncate_key("abcdef12-3456-7890-abcd-ef1234567890")
            'abcd****-****-****-****-********7890'
        """
        if len(plaintext_key) >= 8:
            return f"{plaintext_key[:4]}****-****-****-****-********{plaintext_key[-4:]}"
        return "****"
        
    def verify_key(self, plaintext_key):
        """
        Verify a plaintext key against the stored hash using constant-time comparison.

        Uses hmac.compare_digest for timing-attack-resistant comparison.
        This prevents attackers from inferring key values through timing analysis.

        Args:
            plaintext_key (str): The plaintext key to verify

        Returns:
            bool: True if the key matches the stored hash, False otherwise

        Example:
            >>> psk = PreSharedKey(key="secret-123")
            >>> psk.verify_key("secret-123")
            True
            >>> psk.verify_key("wrong-key")
            False
        """
        import hmac
        return hmac.compare_digest(self.key_hash, self.hash_key(plaintext_key))
    
    def record_usage(self):
        """
        Record that this PSK has been used for certificate generation.

        Updates the last_used_at timestamp and increments the use counter.
        Used for audit logging and usage monitoring.

        Note:
            This method only updates the model instance. Call db.session.commit()
            to persist changes to the database.

        Example:
            >>> psk.record_usage()
            >>> db.session.commit()
        """
        self.last_used_at = datetime.now(timezone.utc)
        self.use_count = (self.use_count or 0) + 1

    def is_valid(self):
        """
        Check if the PSK is currently valid for use.

        A PSK is valid if it is enabled and has not expired. Handles both
        timezone-aware and naive datetime objects for expiration checking.

        Returns:
            bool: True if PSK is enabled and not expired, False otherwise

        Example:
            >>> psk = PreSharedKey(description="Test", expires_at=None)
            >>> psk.is_valid()  # No expiration
            True
            >>>
            >>> # Expired PSK
            >>> past_date = datetime.now(timezone.utc) - timedelta(hours=1)
            >>> psk.expires_at = past_date
            >>> psk.is_valid()
            False
        """
        if not self.is_enabled:
            return False
        if self.expires_at:
            # Handle timezone-aware datetime comparison
            now = datetime.now(timezone.utc)
            expires_at = self.expires_at
            
            # If expires_at is naive, make it timezone-aware
            if expires_at.tzinfo is None:
                expires_at = expires_at.replace(tzinfo=timezone.utc)
            
            if now > expires_at:
                return False
        return True

    def revoke(self):
        """
        Revoke the PSK by disabling it.

        Sets is_enabled to False, preventing future use. This is the recommended
        way to disable a PSK rather than deleting it (preserves audit trail).

        Note:
            This method only updates the model instance. Call db.session.commit()
            to persist changes to the database.

        Example:
            >>> psk.revoke()
            >>> db.session.commit()
            >>> psk.is_valid()
            False
        """
        self.is_enabled = False

    def is_server_psk(self):
        """
        Check if this PSK is configured for server certificate bundles.

        Returns:
            bool: True if psk_type is 'server', False otherwise

        Example:
            >>> server_psk = PreSharedKey(psk_type="server")
            >>> server_psk.is_server_psk()
            True
        """
        return self.psk_type == 'server'

    def is_computer_psk(self):
        """
        Check if this PSK is configured for computer identity certificates.

        Computer PSKs are used for machine-to-machine authentication in
        scenarios like site-to-site VPN connections and managed assets.

        Returns:
            bool: True if psk_type is 'computer', False otherwise

        Example:
            >>> computer_psk = PreSharedKey(psk_type="computer")
            >>> computer_psk.is_computer_psk()
            True
        """
        return self.psk_type == 'computer'

    def get_certificate_type(self):
        """
        Get the appropriate certificate type for signing requests.

        Maps PSK types to certificate types used by the signing service:
        - 'computer' PSK → 'computer' certificate type
        - 'server' PSK → 'server' certificate type

        Returns:
            str: Certificate type ('computer' or 'server')

        Example:
            >>> server_psk = PreSharedKey(psk_type="server")
            >>> server_psk.get_certificate_type()
            'server'
            >>>
            >>> computer_psk = PreSharedKey(psk_type="computer")
            >>> computer_psk.get_certificate_type()
            'computer'
        """
        if self.is_computer_psk():
            return 'computer'
        return 'server'  # Default for server PSKs