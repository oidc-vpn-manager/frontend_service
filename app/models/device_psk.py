"""
DevicePSK model for computer-identity profiles.

This model extends the basic PSK functionality to support device/computer
authentication for site-to-site VPNs and managed remote assets.
"""

import uuid
import hashlib
from datetime import datetime, timezone
from enum import Enum
from app.extensions import db
from app.models.base import SecureModelMixin
from app.utils.cryptography import get_fernet
from sqlalchemy import LargeBinary


class CertificateType(Enum):
    """Certificate types for device PSKs."""
    CLIENT = "client"          # Standard client certificate for device authentication
    SERVER = "server"          # Server certificate for site-to-site connections
    BOTH = "both"             # Both client and server capabilities (dual-use)


class DeviceType(Enum):
    """Device types for categorization and policy application."""
    WORKSTATION = "workstation"       # Individual workstations/laptops
    SERVER = "server"                 # Server infrastructure
    GATEWAY = "gateway"               # VPN gateways for site-to-site
    IOT_DEVICE = "iot_device"        # Internet of Things devices
    MOBILE = "mobile"                # Mobile devices (phones, tablets)
    KIOSK = "kiosk"                  # Public kiosks or terminals
    APPLIANCE = "appliance"          # Network appliances
    OTHER = "other"                  # Other device types


class DevicePSK(SecureModelMixin, db.Model):
    """
    Pre-Shared Key model for device/computer identity authentication.

    This model supports computer-identity profiles for:
    - Site-to-site VPN connections
    - Managed remote assets
    - Device-specific authentication
    - Automated certificate provisioning
    """
    __tablename__ = 'device_pre_shared_keys'

    id = db.Column(db.Integer, primary_key=True)

    # Mass assignment protection - only allow these fields during creation/update
    _allowed_attributes = [
        'device_name', 'device_type', 'device_serial', 'device_mac_address',
        'certificate_type', 'common_name', 'subject_alt_names', 'location',
        'department', 'owner_email', 'assigned_ip_range', 'dns_suffix',
        'template_set', 'policy_group', 'expires_at', 'is_enabled',
        'is_managed', 'created_by', 'key', 'key_hash', 'key_truncated'
    ]

    # Core PSK functionality (similar to PreSharedKey)
    key_hash = db.Column(db.String(64), unique=True, nullable=False)
    key_truncated = db.Column(db.String(50), nullable=True, index=True)

    # Device identification
    device_name = db.Column(db.String(255), nullable=False, index=True)
    device_type = db.Column(db.Enum(DeviceType), nullable=False, default=DeviceType.OTHER)
    device_serial = db.Column(db.String(255), nullable=True, index=True)  # Hardware serial number
    device_mac_address = db.Column(db.String(17), nullable=True, index=True)  # MAC address

    # Certificate configuration
    certificate_type = db.Column(db.Enum(CertificateType), nullable=False, default=CertificateType.CLIENT)
    common_name = db.Column(db.String(255), nullable=True)  # CN for certificate (defaults to device_name)
    subject_alt_names = db.Column(db.Text, nullable=True)  # JSON array of SANs

    # Organizational information
    location = db.Column(db.String(255), nullable=True)  # Physical location
    department = db.Column(db.String(255), nullable=True)  # Owning department
    owner_email = db.Column(db.String(255), nullable=True)  # Device owner/admin

    # Network configuration
    assigned_ip_range = db.Column(db.String(18), nullable=True)  # CIDR notation for allowed IPs
    dns_suffix = db.Column(db.String(255), nullable=True)  # DNS suffix for the device

    # Policy and template configuration
    template_set = db.Column(db.String(100), nullable=False, default='Device')
    policy_group = db.Column(db.String(100), nullable=True)  # Policy group for access control

    # Usage and lifecycle tracking
    last_used_at = db.Column(db.DateTime(timezone=True), nullable=True)
    use_count = db.Column(db.Integer, nullable=False, default=0)
    last_certificate_issued = db.Column(db.DateTime(timezone=True), nullable=True)
    certificate_serial = db.Column(db.String(255), nullable=True)  # Last issued cert serial

    # Lifecycle management
    provisioned_at = db.Column(db.DateTime(timezone=True), nullable=True)  # First certificate issued
    expires_at = db.Column(db.DateTime(timezone=True), nullable=True)
    is_enabled = db.Column(db.Boolean, nullable=False, default=True)
    is_managed = db.Column(db.Boolean, nullable=False, default=True)  # Managed by system vs manual

    # Audit trail
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    created_by = db.Column(db.String(255), nullable=True)  # Admin who created this device PSK
    last_modified_at = db.Column(db.DateTime(timezone=True), nullable=True)
    last_modified_by = db.Column(db.String(255), nullable=True)

    # Device status
    is_online = db.Column(db.Boolean, nullable=True)  # Last known online status
    last_seen_at = db.Column(db.DateTime(timezone=True), nullable=True)  # Last connection time
    last_seen_ip = db.Column(db.String(45), nullable=True)  # Last known IP address

    # Relationships (for future expansion)
    # certificate_requests = db.relationship('DeviceCertificateRequest', back_populates='device_psk')

    def __init__(self, **kwargs):
        """Initialize DevicePSK with automatic key generation if needed."""
        # Handle PSK key generation/hashing
        if 'key' in kwargs:
            plaintext_key = kwargs.pop('key')
            kwargs['key_hash'] = self.hash_key(plaintext_key)
            kwargs['key_truncated'] = self.truncate_key(plaintext_key)
        elif 'key_hash' not in kwargs:
            # Generate a new UUID for the key if none provided
            plaintext_key = str(uuid.uuid4())
            kwargs['key_hash'] = self.hash_key(plaintext_key)
            kwargs['key_truncated'] = self.truncate_key(plaintext_key)

        # Set common name to device name if not provided
        if 'common_name' not in kwargs and 'device_name' in kwargs:
            kwargs['common_name'] = kwargs['device_name']

        # Set defaults for boolean fields if not provided
        if 'is_enabled' not in kwargs:
            kwargs['is_enabled'] = True
        if 'is_managed' not in kwargs:
            kwargs['is_managed'] = True

        # Set default certificate type if not provided
        if 'certificate_type' not in kwargs:
            kwargs['certificate_type'] = CertificateType.CLIENT

        # Set timestamps
        now = datetime.now(timezone.utc)
        kwargs['created_at'] = now
        kwargs['last_modified_at'] = now

        super().__init__(**kwargs)

    @staticmethod
    def hash_key(plaintext_key):
        """Hash a plaintext PSK for secure storage."""
        return hashlib.sha256(plaintext_key.encode('utf-8')).hexdigest()

    @staticmethod
    def truncate_key(plaintext_key):
        """Create a truncated version for identification."""
        if len(plaintext_key) >= 8:
            return f"{plaintext_key[:4]}****-****-****-****-********{plaintext_key[-4:]}"
        return "****"

    def verify_key(self, plaintext_key):
        """Verify a plaintext key against the stored hash."""
        return self.key_hash == self.hash_key(plaintext_key)

    def record_usage(self, client_ip=None):
        """Record that this device PSK has been used."""
        now = datetime.now(timezone.utc)
        self.last_used_at = now
        self.last_seen_at = now
        self.use_count = (self.use_count or 0) + 1
        self.is_online = True

        if client_ip:
            self.last_seen_ip = client_ip

    def record_certificate_issuance(self, certificate_serial=None):
        """Record that a certificate was issued for this device."""
        now = datetime.now(timezone.utc)
        self.last_certificate_issued = now

        if certificate_serial:
            self.certificate_serial = certificate_serial

        if not self.provisioned_at:
            self.provisioned_at = now

    def is_valid(self):
        """Check if the device PSK is enabled and not expired."""
        if not self.is_enabled:
            return False

        if self.expires_at:
            now = datetime.now(timezone.utc)
            expires_at = self.expires_at

            # Handle timezone-aware datetime comparison
            if expires_at.tzinfo is None:
                expires_at = expires_at.replace(tzinfo=timezone.utc)

            if now > expires_at:
                return False

        return True

    def revoke(self, revoked_by=None):
        """Revoke the device PSK by disabling it."""
        self.is_enabled = False
        self.is_online = False
        self.last_modified_at = datetime.now(timezone.utc)
        if revoked_by:
            self.last_modified_by = revoked_by

    def update_online_status(self, is_online, last_seen_ip=None):
        """Update the online status of the device."""
        self.is_online = is_online

        if is_online:
            self.last_seen_at = datetime.now(timezone.utc)
            if last_seen_ip:
                self.last_seen_ip = last_seen_ip

    def get_subject_alt_names(self):
        """Get subject alternative names as a list."""
        if not self.subject_alt_names:
            return []

        try:
            import json
            return json.loads(self.subject_alt_names)
        except (json.JSONDecodeError, TypeError):
            return []

    def set_subject_alt_names(self, san_list):
        """Set subject alternative names from a list."""
        if san_list:
            import json
            self.subject_alt_names = json.dumps(san_list)
        else:
            self.subject_alt_names = None

    def is_due_for_renewal(self, days_before_expiry=30):
        """Check if the device certificate is due for renewal."""
        if not self.last_certificate_issued or not self.expires_at:
            return False

        now = datetime.now(timezone.utc)
        expires_at = self.expires_at

        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)

        from datetime import timedelta
        renewal_threshold = expires_at - timedelta(days=days_before_expiry)

        return now >= renewal_threshold

    def to_dict(self):
        """Convert device PSK to dictionary for API responses."""
        return {
            'id': self.id,
            'device_name': self.device_name,
            'device_type': self.device_type.name if self.device_type else None,
            'device_serial': self.device_serial,
            'device_mac_address': self.device_mac_address,
            'certificate_type': self.certificate_type.name if self.certificate_type else None,
            'common_name': self.common_name,
            'subject_alt_names': self.get_subject_alt_names(),
            'location': self.location,
            'department': self.department,
            'owner_email': self.owner_email,
            'assigned_ip_range': self.assigned_ip_range,
            'dns_suffix': self.dns_suffix,
            'template_set': self.template_set,
            'policy_group': self.policy_group,
            'key_truncated': self.key_truncated,
            'use_count': self.use_count,
            'last_used_at': self.last_used_at.isoformat() if self.last_used_at else None,
            'last_certificate_issued': self.last_certificate_issued.isoformat() if self.last_certificate_issued else None,
            'certificate_serial': self.certificate_serial,
            'provisioned_at': self.provisioned_at.isoformat() if self.provisioned_at else None,
            'expires_at': self.expires_at.isoformat() if self.expires_at else None,
            'is_enabled': self.is_enabled,
            'is_managed': self.is_managed,
            'is_online': self.is_online,
            'last_seen_at': self.last_seen_at.isoformat() if self.last_seen_at else None,
            'last_seen_ip': self.last_seen_ip,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'created_by': self.created_by,
            'last_modified_at': self.last_modified_at.isoformat() if self.last_modified_at else None,
            'last_modified_by': self.last_modified_by,
        }

    def __repr__(self):
        return f'<DevicePSK {self.device_name} ({self.device_type.value if self.device_type else "unknown"})>'

    @classmethod
    def find_by_device_name(cls, device_name):
        """Find device PSK by device name."""
        return cls.query.filter_by(device_name=device_name).first()

    @classmethod
    def find_by_serial(cls, device_serial):
        """Find device PSK by device serial number."""
        return cls.query.filter_by(device_serial=device_serial).first()

    @classmethod
    def find_by_mac_address(cls, mac_address):
        """Find device PSK by MAC address."""
        return cls.query.filter_by(device_mac_address=mac_address).first()

    @classmethod
    def get_active_devices(cls):
        """Get all active (enabled and not expired) device PSKs."""
        now = datetime.now(timezone.utc)
        return cls.query.filter(
            cls.is_enabled == True,
            db.or_(
                cls.expires_at == None,
                cls.expires_at > now
            )
        ).all()

    @classmethod
    def get_devices_by_type(cls, device_type):
        """Get all devices of a specific type."""
        return cls.query.filter_by(device_type=device_type).all()

    @classmethod
    def get_devices_due_for_renewal(cls, days_before_expiry=30):
        """Get devices due for certificate renewal."""
        from datetime import timedelta

        now = datetime.now(timezone.utc)
        renewal_threshold = now + timedelta(days=days_before_expiry)

        return cls.query.filter(
            cls.is_enabled == True,
            cls.expires_at != None,
            cls.expires_at <= renewal_threshold,
            cls.expires_at > now  # Not yet expired
        ).all()

    @classmethod
    def get_offline_devices(cls, offline_threshold_hours=24):
        """Get devices that haven't been seen recently."""
        from datetime import timedelta

        cutoff_time = datetime.now(timezone.utc) - timedelta(hours=offline_threshold_hours)

        return cls.query.filter(
            cls.is_enabled == True,
            cls.last_seen_at != None,
            cls.last_seen_at < cutoff_time
        ).all()