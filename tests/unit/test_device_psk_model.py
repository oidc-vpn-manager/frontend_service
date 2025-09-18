"""
Unit tests for the DevicePSK model.

These tests verify the functionality of the DevicePSK model for
computer-identity profiles including device authentication,
certificate type handling, and lifecycle management.
"""

import pytest
import uuid
from datetime import datetime, timezone, timedelta
from app.models.device_psk import DevicePSK, CertificateType, DeviceType
from app.extensions import db


@pytest.fixture(autouse=True)
def setup_database(app):
    """Setup database with DevicePSK table."""
    with app.app_context():
        db.create_all()
        yield
        db.drop_all()


class TestDevicePSKModel:
    """Test the DevicePSK model functionality."""

    def test_truncate_key_short_key(self, app):
        """Test truncate_key method with short key (< 8 chars) - covers line 148."""
        from app.models.device_psk import DevicePSK

        # Test with key shorter than 8 characters
        short_key = "abc123"  # 6 characters
        truncated = DevicePSK.truncate_key(short_key)

        # Should return "****" for short keys (line 148)
        assert truncated == "****"

    def test_truncate_key_long_key(self, app):
        """Test truncate_key method with long key (>= 8 chars)."""
        from app.models.device_psk import DevicePSK

        # Test with key 8 or more characters
        long_key = "abcd1234efgh5678"  # 16 characters
        truncated = DevicePSK.truncate_key(long_key)

        # Should return truncated format with first 4 and last 4 chars
        expected = "abcd****-****-****-****-********5678"
        assert truncated == expected

    def test_is_valid_with_naive_expiry_datetime(self, app):
        """Test is_valid method with naive datetime (no timezone) - covers line 187."""
        with app.app_context():
            device_psk = DevicePSK(
                device_name='test-naive-datetime',
                device_type=DeviceType.WORKSTATION,
                certificate_type=CertificateType.CLIENT,
                created_by='admin@example.com'
            )

            # Set expiry to naive datetime (no timezone info) in the future
            naive_future_time = datetime.now() + timedelta(hours=1)  # No timezone
            device_psk.expires_at = naive_future_time

            # Should handle naive datetime and still be valid (covers line 187)
            assert device_psk.is_valid() == True

            # Also test with past naive datetime
            naive_past_time = datetime.now() - timedelta(hours=1)  # No timezone
            device_psk.expires_at = naive_past_time

            # Should be invalid due to expiry
            assert device_psk.is_valid() == False

    def test_get_subject_alt_names_invalid_json(self, app):
        """Test get_subject_alt_names with invalid JSON - covers lines 219-220."""
        with app.app_context():
            device_psk = DevicePSK(
                device_name='test-invalid-json',
                device_type=DeviceType.WORKSTATION,
                certificate_type=CertificateType.CLIENT,
                created_by='admin@example.com'
            )

            # Set invalid JSON to trigger exception handling (lines 219-220)
            device_psk.subject_alt_names = "invalid json string"

            # Should return empty list on JSON parsing error
            result = device_psk.get_subject_alt_names()
            assert result == []

            # Also test with None/wrong type to trigger TypeError
            device_psk.subject_alt_names = 123  # Integer instead of string
            result = device_psk.get_subject_alt_names()
            assert result == []

    def test_repr_method(self, app):
        """Test __repr__ method - covers line 283."""
        with app.app_context():
            device_psk = DevicePSK(
                device_name='test-repr',
                device_type=DeviceType.SERVER,
                certificate_type=CertificateType.SERVER,
                created_by='admin@example.com'
            )

            # Test __repr__ method (line 283)
            repr_str = repr(device_psk)
            expected = "<DevicePSK test-repr (server)>"
            assert repr_str == expected

            # Test with None device_type to cover the fallback case
            device_psk.device_type = None
            repr_str = repr(device_psk)
            expected = "<DevicePSK test-repr (unknown)>"
            assert repr_str == expected

    def test_is_due_for_renewal_naive_datetime(self, app):
        """Test is_due_for_renewal with naive datetime - covers line 239."""
        with app.app_context():
            device_psk = DevicePSK(
                device_name='test-renewal-naive',
                device_type=DeviceType.WORKSTATION,
                certificate_type=CertificateType.CLIENT,
                created_by='admin@example.com'
            )

            # Set last certificate issued and expires_at as naive datetimes
            device_psk.last_certificate_issued = datetime.now() - timedelta(days=10)  # Naive
            device_psk.expires_at = datetime.now() + timedelta(days=20)  # Naive, expires in 20 days

            # Should handle naive datetime in is_due_for_renewal (covers line 239)
            # With 30 days before expiry threshold and expires in 20 days, should be due for renewal
            assert device_psk.is_due_for_renewal(days_before_expiry=30) == True

            # With 5 days threshold and expires in 20 days, should not be due for renewal yet
            assert device_psk.is_due_for_renewal(days_before_expiry=5) == False

    def test_device_psk_creation_with_generated_key(self, app):
        """Test creating a DevicePSK with automatically generated key."""
        with app.app_context():
            device_psk = DevicePSK(
                device_name='test-workstation-01',
                device_type=DeviceType.WORKSTATION,
                certificate_type=CertificateType.CLIENT,
                created_by='admin@example.com'
            )

            db.session.add(device_psk)
            db.session.commit()

            # Verify basic properties
            assert device_psk.device_name == 'test-workstation-01'
            assert device_psk.device_type == DeviceType.WORKSTATION
            assert device_psk.certificate_type == CertificateType.CLIENT
            assert device_psk.created_by == 'admin@example.com'

            # Verify key generation
            assert device_psk.key_hash is not None
            assert len(device_psk.key_hash) == 64  # SHA256 hex length
            assert device_psk.key_truncated is not None
            assert '****' in device_psk.key_truncated

            # Verify defaults
            assert device_psk.is_enabled is True
            assert device_psk.is_managed is True
            assert device_psk.use_count == 0
            assert device_psk.template_set == 'Device'

            # Verify common name defaults to device name
            assert device_psk.common_name == 'test-workstation-01'

    def test_device_psk_creation_with_custom_key(self, app):
        """Test creating a DevicePSK with a custom key."""
        with app.app_context():
            custom_key = str(uuid.uuid4())
            device_psk = DevicePSK(
                device_name='test-server-01',
                device_type=DeviceType.SERVER,
                certificate_type=CertificateType.SERVER,
                key=custom_key,
                created_by='admin@example.com'
            )

            db.session.add(device_psk)
            db.session.commit()

            # Verify key was properly hashed
            assert device_psk.verify_key(custom_key)
            assert not device_psk.verify_key('wrong-key')

    def test_device_psk_certificate_types(self, app):
        """Test different certificate types for DevicePSK."""
        certificate_types = [
            CertificateType.CLIENT,
            CertificateType.SERVER,
            CertificateType.BOTH
        ]

        with app.app_context():
            for cert_type in certificate_types:
                device_psk = DevicePSK(
                    device_name=f'test-device-{cert_type.value}',
                    device_type=DeviceType.OTHER,
                    certificate_type=cert_type,
                    created_by='admin@example.com'
                )

                db.session.add(device_psk)
                db.session.commit()

                assert device_psk.certificate_type == cert_type

    def test_device_types(self, app):
        """Test different device types."""
        device_types = [
            DeviceType.WORKSTATION,
            DeviceType.SERVER,
            DeviceType.GATEWAY,
            DeviceType.IOT_DEVICE,
            DeviceType.MOBILE,
            DeviceType.KIOSK,
            DeviceType.APPLIANCE,
            DeviceType.OTHER
        ]

        with app.app_context():
            for device_type in device_types:
                device_psk = DevicePSK(
                    device_name=f'test-{device_type.value}',
                    device_type=device_type,
                    created_by='admin@example.com'
                )

                db.session.add(device_psk)
                db.session.commit()

                assert device_psk.device_type == device_type

    def test_usage_recording(self, app):
        """Test recording device PSK usage."""
        with app.app_context():
            device_psk = DevicePSK(
                device_name='usage-test-device',
                device_type=DeviceType.WORKSTATION,
                created_by='admin@example.com'
            )

            db.session.add(device_psk)
            db.session.commit()

            # Initial state
            assert device_psk.use_count == 0
            assert device_psk.last_used_at is None
            assert device_psk.last_seen_at is None
            assert device_psk.is_online is None

            # Record usage
            client_ip = '192.168.1.100'
            device_psk.record_usage(client_ip=client_ip)

            assert device_psk.use_count == 1
            assert device_psk.last_used_at is not None
            assert device_psk.last_seen_at is not None
            assert device_psk.last_seen_ip == client_ip
            assert device_psk.is_online is True

            # Record another usage
            device_psk.record_usage()
            assert device_psk.use_count == 2

    def test_certificate_issuance_recording(self, app):
        """Test recording certificate issuance."""
        with app.app_context():
            device_psk = DevicePSK(
                device_name='cert-test-device',
                device_type=DeviceType.SERVER,
                created_by='admin@example.com'
            )

            db.session.add(device_psk)
            db.session.commit()

            # Initial state
            assert device_psk.last_certificate_issued is None
            assert device_psk.certificate_serial is None
            assert device_psk.provisioned_at is None

            # Record certificate issuance
            cert_serial = '1234567890ABCDEF'
            device_psk.record_certificate_issuance(certificate_serial=cert_serial)

            assert device_psk.last_certificate_issued is not None
            assert device_psk.certificate_serial == cert_serial
            assert device_psk.provisioned_at is not None

            # Record another issuance (renewal)
            first_issuance = device_psk.last_certificate_issued
            first_provisioning = device_psk.provisioned_at

            device_psk.record_certificate_issuance(certificate_serial='NEW_SERIAL')

            assert device_psk.last_certificate_issued > first_issuance
            assert device_psk.certificate_serial == 'NEW_SERIAL'
            assert device_psk.provisioned_at == first_provisioning  # Should not change

    def test_subject_alt_names(self, app):
        """Test subject alternative names handling."""
        with app.app_context():
            device_psk = DevicePSK(
                device_name='san-test-device',
                device_type=DeviceType.GATEWAY,
                created_by='admin@example.com'
            )

            # Test empty SANs
            assert device_psk.get_subject_alt_names() == []

            # Test setting SANs
            san_list = ['gateway.company.com', '192.168.1.1', 'vpn.company.com']
            device_psk.set_subject_alt_names(san_list)

            assert device_psk.get_subject_alt_names() == san_list

            # Test clearing SANs
            device_psk.set_subject_alt_names(None)
            assert device_psk.get_subject_alt_names() == []

            device_psk.set_subject_alt_names([])
            assert device_psk.get_subject_alt_names() == []

    def test_validity_checks(self, app):
        """Test device PSK validity checks."""
        with app.app_context():
            device_psk = DevicePSK(
                device_name='validity-test-device',
                device_type=DeviceType.WORKSTATION,
                created_by='admin@example.com'
            )

            # Should be valid initially
            assert device_psk.is_valid()

            # Test disabling
            device_psk.is_enabled = False
            assert not device_psk.is_valid()

            # Re-enable for expiry testing
            device_psk.is_enabled = True
            assert device_psk.is_valid()

            # Test expiry in future
            future_date = datetime.now(timezone.utc) + timedelta(days=30)
            device_psk.expires_at = future_date
            assert device_psk.is_valid()

            # Test expiry in past
            past_date = datetime.now(timezone.utc) - timedelta(days=1)
            device_psk.expires_at = past_date
            assert not device_psk.is_valid()

    def test_renewal_due_check(self, app):
        """Test certificate renewal due check."""
        with app.app_context():
            device_psk = DevicePSK(
                device_name='renewal-test-device',
                device_type=DeviceType.SERVER,
                created_by='admin@example.com'
            )

            # No certificate issued yet
            assert not device_psk.is_due_for_renewal()

            # Set certificate issued and expiry
            now = datetime.now(timezone.utc)
            device_psk.last_certificate_issued = now
            device_psk.expires_at = now + timedelta(days=60)

            # Not due for renewal yet (default 30 days before expiry)
            assert not device_psk.is_due_for_renewal()

            # Due for renewal (20 days before expiry)
            device_psk.expires_at = now + timedelta(days=20)
            assert device_psk.is_due_for_renewal()

            # Custom threshold
            device_psk.expires_at = now + timedelta(days=40)
            assert not device_psk.is_due_for_renewal(days_before_expiry=30)
            assert device_psk.is_due_for_renewal(days_before_expiry=50)

    def test_revocation(self, app):
        """Test device PSK revocation."""
        with app.app_context():
            device_psk = DevicePSK(
                device_name='revocation-test-device',
                device_type=DeviceType.WORKSTATION,
                created_by='admin@example.com'
            )

            device_psk.is_online = True
            assert device_psk.is_valid()

            # Revoke
            revoker = 'admin@example.com'
            device_psk.revoke(revoked_by=revoker)

            assert not device_psk.is_enabled
            assert not device_psk.is_valid()
            assert device_psk.is_online is False
            assert device_psk.last_modified_by == revoker
            assert device_psk.last_modified_at is not None

    def test_online_status_updates(self, app):
        """Test online status updates."""
        with app.app_context():
            device_psk = DevicePSK(
                device_name='status-test-device',
                device_type=DeviceType.IOT_DEVICE,
                created_by='admin@example.com'
            )

            # Test going online
            test_ip = '10.0.1.50'
            device_psk.update_online_status(True, test_ip)

            assert device_psk.is_online is True
            assert device_psk.last_seen_at is not None
            assert device_psk.last_seen_ip == test_ip

            # Test going offline
            device_psk.update_online_status(False)

            assert device_psk.is_online is False
            # last_seen_at and IP should remain from when it was last online

    def test_to_dict_serialization(self, app):
        """Test dictionary serialization."""
        with app.app_context():
            device_psk = DevicePSK(
                device_name='serialize-test-device',
                device_type=DeviceType.GATEWAY,
                certificate_type=CertificateType.BOTH,
                device_serial='SN123456789',
                device_mac_address='aa:bb:cc:dd:ee:ff',
                location='Data Center 1',
                department='IT Infrastructure',
                owner_email='admin@company.com',
                assigned_ip_range='10.1.0.0/24',
                dns_suffix='internal.company.com',
                policy_group='gateways',
                created_by='admin@example.com'
            )

            device_psk.set_subject_alt_names(['gateway1.company.com', '10.1.0.1'])

            db.session.add(device_psk)
            db.session.commit()

            dict_data = device_psk.to_dict()

            assert dict_data['device_name'] == 'serialize-test-device'
            assert dict_data['device_type'] == 'GATEWAY'
            assert dict_data['certificate_type'] == 'BOTH'
            assert dict_data['device_serial'] == 'SN123456789'
            assert dict_data['device_mac_address'] == 'aa:bb:cc:dd:ee:ff'
            assert dict_data['location'] == 'Data Center 1'
            assert dict_data['department'] == 'IT Infrastructure'
            assert dict_data['owner_email'] == 'admin@company.com'
            assert dict_data['assigned_ip_range'] == '10.1.0.0/24'
            assert dict_data['dns_suffix'] == 'internal.company.com'
            assert dict_data['policy_group'] == 'gateways'
            assert dict_data['subject_alt_names'] == ['gateway1.company.com', '10.1.0.1']
            assert dict_data['is_enabled'] is True
            assert dict_data['is_managed'] is True
            assert dict_data['created_by'] == 'admin@example.com'

    def test_class_methods(self, app):
        """Test class methods for querying devices."""
        with app.app_context():
            # Create test devices
            workstation1 = DevicePSK(
                device_name='workstation-01',
                device_type=DeviceType.WORKSTATION,
                device_serial='WS001',
                device_mac_address='aa:bb:cc:00:00:01',
                created_by='admin@example.com'
            )

            workstation2 = DevicePSK(
                device_name='workstation-02',
                device_type=DeviceType.WORKSTATION,
                expires_at=datetime.now(timezone.utc) + timedelta(days=20),
                created_by='admin@example.com'
            )

            server1 = DevicePSK(
                device_name='server-01',
                device_type=DeviceType.SERVER,
                device_serial='SRV001',
                created_by='admin@example.com'
            )

            offline_device = DevicePSK(
                device_name='offline-device',
                device_type=DeviceType.IOT_DEVICE,
                last_seen_at=datetime.now(timezone.utc) - timedelta(hours=48),
                created_by='admin@example.com'
            )

            db.session.add_all([workstation1, workstation2, server1, offline_device])
            db.session.commit()

            # Test find by device name
            found = DevicePSK.find_by_device_name('workstation-01')
            assert found == workstation1

            # Test find by serial
            found = DevicePSK.find_by_serial('WS001')
            assert found == workstation1

            # Test find by MAC address
            found = DevicePSK.find_by_mac_address('aa:bb:cc:00:00:01')
            assert found == workstation1

            # Test get active devices
            active = DevicePSK.get_active_devices()
            assert len(active) == 4  # All should be active initially

            # Test get devices by type
            workstations = DevicePSK.get_devices_by_type(DeviceType.WORKSTATION)
            assert len(workstations) == 2

            servers = DevicePSK.get_devices_by_type(DeviceType.SERVER)
            assert len(servers) == 1

            # Test get devices due for renewal
            due_for_renewal = DevicePSK.get_devices_due_for_renewal(days_before_expiry=30)
            assert workstation2 in due_for_renewal

            # Test get offline devices
            offline = DevicePSK.get_offline_devices(offline_threshold_hours=24)
            assert offline_device in offline
            assert workstation1 not in offline  # No last_seen_at set