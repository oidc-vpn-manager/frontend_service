import uuid
import hashlib
from datetime import datetime, timezone
from app.extensions import db
from app.utils.cryptography import get_fernet
from sqlalchemy import LargeBinary

class PreSharedKey(db.Model):
    __tablename__ = 'pre_shared_keys'
    id = db.Column(db.Integer, primary_key=True)
    
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
        """Hash a plaintext PSK for secure storage."""
        return hashlib.sha256(plaintext_key.encode('utf-8')).hexdigest()
    
    @staticmethod
    def truncate_key(plaintext_key):
        """Create a truncated version for identification (e.g., '5ffb****-****-****-****-********44de')."""
        if len(plaintext_key) >= 8:
            return f"{plaintext_key[:4]}****-****-****-****-********{plaintext_key[-4:]}"
        return "****"
        
    def verify_key(self, plaintext_key):
        """Verify a plaintext key against the stored hash."""
        return self.key_hash == self.hash_key(plaintext_key)
    
    def record_usage(self):
        """Record that this PSK has been used."""
        self.last_used_at = datetime.now(timezone.utc)
        self.use_count = (self.use_count or 0) + 1

    def is_valid(self):
        """Checks if the key is enabled and not expired."""
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
        """Revokes the PSK by disabling it."""
        self.is_enabled = False

    def is_server_psk(self):
        """Check if this PSK is for server bundles."""
        return self.psk_type == 'server'

    def is_computer_psk(self):
        """Check if this PSK is for computer-identity (site-to-site, managed assets)."""
        return self.psk_type == 'computer'

    def get_certificate_type(self):
        """Get the appropriate certificate type for this PSK."""
        if self.is_computer_psk():
            return 'computer'
        return 'server'  # Default for server PSKs