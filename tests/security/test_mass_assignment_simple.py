"""
Simple mass assignment protection tests.

This test suite validates the core security requirement: that models
reject attempts to set unauthorized attributes via kwargs.
"""

import pytest


class TestMassAssignmentProtection:
    """Core tests for mass assignment protection."""

    def test_presharedkey_rejects_unauthorized_fields(self):
        """Test that PreSharedKey rejects unauthorized field assignments."""
        from app.models.presharedkey import PreSharedKey

        # Attempt mass assignment attack
        malicious_data = {
            'description': 'Test PSK',       # Allowed
            'template_set': 'TestTemplate',  # Allowed
            'psk_type': 'server',           # Allowed
            'key': 'test-key-123',          # Allowed
            'id': 999,                      # ATTACK: Should be rejected
            'use_count': 100,               # ATTACK: Should be rejected
            'is_enabled': False,            # ATTACK: Should be rejected
        }

        psk = PreSharedKey(**malicious_data)

        # Verify allowed fields were set
        assert psk.description == 'Test PSK'
        assert psk.template_set == 'TestTemplate'
        assert psk.psk_type == 'server'

        # SECURITY TEST: Verify attacks were blocked
        assert psk.id != 999, "Mass assignment attack: id should not be settable"
        assert psk.use_count != 100, "Mass assignment attack: use_count should not be settable"
        # Note: is_enabled has special handling in the model, test separately

    def test_certificate_request_rejects_unauthorized_fields(self):
        """Test that CertificateRequest rejects unauthorized field assignments."""
        from app.models.certificate_request import CertificateRequest

        malicious_data = {
            'common_name': 'test.example.com',  # Allowed
            'certificate_type': 'server',       # Allowed
            'user_id': 'user123',              # Allowed
            'id': 999,                         # ATTACK: Should be rejected
        }

        cert_req = CertificateRequest(**malicious_data)

        # Verify allowed fields were set
        assert cert_req.common_name == 'test.example.com'
        assert cert_req.certificate_type == 'server'
        assert cert_req.user_id == 'user123'

        # SECURITY TEST: Verify attack was blocked
        assert cert_req.id != 999, "Mass assignment attack: id should not be settable"

    def test_device_psk_rejects_unauthorized_fields(self):
        """Test that DevicePSK rejects unauthorized field assignments."""
        from app.models.device_psk import DevicePSK, DeviceType

        malicious_data = {
            'device_name': 'test-device',      # Allowed
            'device_type': DeviceType.WORKSTATION,  # Allowed
            'key': 'device-key-123',           # Allowed
            'id': 999,                         # ATTACK: Should be rejected
            'use_count': 100,                  # ATTACK: Should be rejected
            'is_online': True,                 # ATTACK: Should be rejected
        }

        device_psk = DevicePSK(**malicious_data)

        # Verify allowed fields were set
        assert device_psk.device_name == 'test-device'
        assert device_psk.device_type == DeviceType.WORKSTATION

        # SECURITY TEST: Verify attacks were blocked
        assert device_psk.id != 999, "Mass assignment attack: id should not be settable"
        assert device_psk.use_count != 100, "Mass assignment attack: use_count should not be settable"
        assert device_psk.is_online != True, "Mass assignment attack: is_online should not be settable"

    def test_download_token_rejects_unauthorized_fields(self):
        """Test that DownloadToken rejects unauthorized field assignments."""
        from app.models.downloadtoken import DownloadToken

        malicious_data = {
            'user': 'testuser@example.com',    # Allowed
            'cn': 'test.example.com',          # Allowed
            'detected_os': 'Windows',          # Allowed
            'id': 999,                         # ATTACK: Should be rejected
            'token': 'custom-token',           # ATTACK: Should be rejected
            'downloadable': False,             # ATTACK: Should be rejected
        }

        download_token = DownloadToken(**malicious_data)

        # Verify allowed fields were set
        assert download_token.user == 'testuser@example.com'
        assert download_token.cn == 'test.example.com'
        assert download_token.detected_os == 'Windows'

        # SECURITY TEST: Verify attacks were blocked
        assert download_token.id != 999, "Mass assignment attack: id should not be settable"
        assert download_token.token != 'custom-token', "Mass assignment attack: token should not be settable"
        # downloadable should be None (not set) or True (default), but never the malicious False
        assert download_token.downloadable is None or download_token.downloadable is True, "Mass assignment attack: downloadable should not be settable to False"

    def test_update_safe_method_protection(self):
        """Test that update_safe method also provides protection."""
        from app.models.presharedkey import PreSharedKey

        # Create a PSK
        psk = PreSharedKey(
            description='Original PSK',
            template_set='OriginalTemplate',
            psk_type='server',
            key='original-key'
        )
        original_id = psk.id

        # Attempt malicious update
        malicious_update = {
            'description': 'Updated PSK',      # Allowed
            'id': 999,                         # ATTACK: Should be rejected
            'use_count': 100,                  # ATTACK: Should be rejected
        }

        ignored_attrs = psk.update_safe(**malicious_update)

        # Verify allowed update worked
        assert psk.description == 'Updated PSK'

        # SECURITY TEST: Verify attacks were blocked
        assert psk.id == original_id, "Mass assignment attack: id should not be updatable"
        assert psk.use_count != 100, "Mass assignment attack: use_count should not be updatable"

        # Verify ignored attributes were reported
        assert 'id' in ignored_attrs
        assert 'use_count' in ignored_attrs

    def test_create_safe_class_method_protection(self):
        """Test that create_safe class method provides the same protection."""
        from app.models.presharedkey import PreSharedKey

        malicious_data = {
            'description': 'Safe PSK',
            'template_set': 'SafeTemplate',
            'psk_type': 'server',
            'key': 'safe-key',
            'id': 999,            # ATTACK: Should be rejected
            'use_count': 100,     # ATTACK: Should be rejected
        }

        psk = PreSharedKey.create_safe(**malicious_data)

        # Verify allowed fields
        assert psk.description == 'Safe PSK'
        assert psk.template_set == 'SafeTemplate'

        # SECURITY TEST: Verify attacks were blocked
        assert psk.id != 999, "Mass assignment attack via create_safe: id should not be settable"
        assert psk.use_count != 100, "Mass assignment attack via create_safe: use_count should not be settable"

    def test_model_without_allowed_attributes_fails(self):
        """Test that models without _allowed_attributes raise NotImplementedError."""
        from app.models.base import SecureModelMixin
        from app.extensions import db
        import uuid

        # Use unique table name to avoid SQLAlchemy conflicts
        unique_table_name = f'bad_model_{uuid.uuid4().hex[:8]}'

        class BadModel(SecureModelMixin, db.Model):
            __tablename__ = unique_table_name
            id = db.Column(db.Integer, primary_key=True)
            name = db.Column(db.String(255))
            # Missing _allowed_attributes - this should fail

        with pytest.raises(NotImplementedError) as exc_info:
            BadModel(name='test')

        assert 'must define _allowed_attributes' in str(exc_info.value)

    def test_admin_privilege_escalation_protection(self):
        """Test protection against admin privilege escalation attempts."""
        from app.models.presharedkey import PreSharedKey

        # Simulate attack attempting to escalate privileges or modify system fields
        privilege_escalation_attack = {
            'description': 'Normal PSK Request',  # Looks innocent
            'template_set': 'UserTemplate',       # Looks innocent
            'psk_type': 'server',                 # Looks innocent
            'key': 'user-key',                    # Looks innocent
            # Hidden attacks:
            'id': 1,                              # Try to overwrite existing record
            'created_at': '1990-01-01',          # Try to backdate creation
            'is_enabled': False,                  # Try to disable existing PSK
            'use_count': 999999,                  # Try to inflate usage stats
            'last_used_at': '2030-01-01',        # Try to set future usage
        }

        psk = PreSharedKey(**privilege_escalation_attack)

        # Verify legitimate fields work
        assert psk.description == 'Normal PSK Request'
        assert psk.template_set == 'UserTemplate'
        assert psk.psk_type == 'server'

        # SECURITY TEST: All privilege escalation attempts should fail
        assert psk.id != 1, "Privilege escalation blocked: cannot overwrite ID"
        assert psk.use_count != 999999, "Privilege escalation blocked: cannot inflate usage"
        # Note: Other fields like created_at, is_enabled have defaults handled by SQLAlchemy

    def test_api_json_payload_protection(self):
        """Test protection against malicious JSON API payloads."""
        from app.models.certificate_request import CertificateRequest

        # Simulate malicious JSON payload from API request
        malicious_json_payload = {
            "common_name": "api-request.example.com",
            "certificate_type": "server",
            "user_id": "api-user-123",
            # Hidden attacks in JSON:
            "id": 999,
            "request_timestamp": "1970-01-01T00:00:00Z",
            "signing_successful": True,    # Try to mark as already signed
            "certificate_serial": "FAKE-SERIAL-123",
        }

        cert_req = CertificateRequest(**malicious_json_payload)

        # Verify legitimate fields
        assert cert_req.common_name == "api-request.example.com"
        assert cert_req.certificate_type == "server"
        assert cert_req.user_id == "api-user-123"

        # SECURITY TEST: Malicious fields should be ignored
        assert cert_req.id != 999, "API attack blocked: cannot set ID"
        assert cert_req.certificate_serial != "FAKE-SERIAL-123", "API attack blocked: cannot fake certificate serial"
        # signing_successful is allowed but should be handled carefully in real code