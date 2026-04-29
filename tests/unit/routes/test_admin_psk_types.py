"""
Unit tests for admin PSK management with computer-identity types.
"""

import pytest
from unittest.mock import patch
from flask import Flask
from app import create_app
from app.extensions import db
from app.models.presharedkey import PreSharedKey


class TestAdminPskTypes:
    """Tests for admin PSK management with new PSK types."""

    @pytest.fixture
    def app(self):
        """Create a test Flask app with database."""
        import os
        # Set required environment variables for testing
        os.environ['FLASK_SECRET_KEY'] = 'test-secret-key-for-testing-only'
        os.environ['FERNET_ENCRYPTION_KEY'] = 'test-encryption-key-for-testing-only-32-chars-long'
        os.environ['TESTING'] = 'True'

        app = create_app('testing')
        app.config.update({
            'TESTING': True,
            'SQLALCHEMY_DATABASE_URI': 'sqlite:///:memory:',
            'WTF_CSRF_ENABLED': False,
            'SECRET_KEY': 'test-secret-key-for-testing-only',
            'ENCRYPTION_KEY': 'test-encryption-key-for-testing-only-32-chars',
            'OIDC_ADMIN_GROUP': 'admin',
        })

        with app.app_context():
            db.create_all()
            yield app

    @pytest.fixture
    def client(self, app):
        """Create a test client."""
        return app.test_client()

    def test_create_server_psk_type(self, client):
        """Test creating a server PSK through admin interface."""
        with client.session_transaction() as sess:
            sess['user'] = {
                'sub': 'admin123',
                'groups': ['admin']
            }

        with patch('app.utils.server_templates.get_template_set_choices', return_value=[('default', 'Default')]), \
             patch('app.utils.render_config_template.get_group_profile_choices', return_value=[('Default', 'Default (0100.Default.ovpn)')]):
            response = client.post('/admin/psk/new', data={
                'description': 'Test Server PSK',
                'psk_type': 'server',
                'template_set': 'default',
                'csrf_token': 'test-token'
            })

            assert response.status_code == 200

            # Verify PSK was created with correct type
            with client.application.app_context():
                psk = PreSharedKey.query.filter_by(description='Test Server PSK').first()
                assert psk is not None
                assert psk.psk_type == 'server'
                assert psk.template_set == 'default'
                assert psk.is_server_psk() is True
                assert psk.is_computer_psk() is False

    def test_create_computer_psk_type(self, client):
        """Test creating a computer PSK through admin interface."""
        with client.session_transaction() as sess:
            sess['user'] = {
                'sub': 'admin123',
                'groups': ['admin']
            }

        with patch('app.utils.server_templates.get_template_set_choices', return_value=[('sitetosite', 'Site-to-Site')]), \
             patch('app.utils.render_config_template.get_group_profile_choices', return_value=[('Developers', 'Developers (0200.Developers.ovpn)')]):
            response = client.post('/admin/psk/new', data={
                'description': 'Test Computer PSK',
                'psk_type': 'computer',
                'group_profile': 'Developers',
                'csrf_token': 'test-token'
            })

            assert response.status_code == 200

            # Verify PSK was created with correct type and stored the
            # selected group profile in the shared template_set column.
            with client.application.app_context():
                psk = PreSharedKey.query.filter_by(description='Test Computer PSK').first()
                assert psk is not None
                assert psk.psk_type == 'computer'
                assert psk.template_set == 'Developers'
                assert psk.is_computer_psk() is True
                assert psk.is_server_psk() is False

    def test_psk_created_template_shows_correct_instructions(self, client):
        """Test that PSK created template shows appropriate instructions for each type."""
        with client.session_transaction() as sess:
            sess['user'] = {
                'sub': 'admin123',
                'groups': ['admin']
            }

        with patch('app.utils.server_templates.get_template_set_choices', return_value=[('default', 'Default')]), \
             patch('app.utils.render_config_template.get_group_profile_choices', return_value=[('Default', 'Default (0100.Default.ovpn)')]):
            # Create server PSK
            response = client.post('/admin/psk/new', data={
                'description': 'Test Server Instructions',
                'psk_type': 'server',
                'template_set': 'default',
                'csrf_token': 'test-token'
            })

            assert response.status_code == 200
            # Should contain server bundle instructions
            assert b'get_openvpn_server_config.py' in response.data
            assert b'Server Bundle' in response.data
            assert b'template set' in response.data

            # Create computer PSK
            response = client.post('/admin/psk/new', data={
                'description': 'Test Computer Instructions',
                'psk_type': 'computer',
                'group_profile': 'Default',
                'csrf_token': 'test-token'
            })

            assert response.status_code == 200
            # Should contain computer identity instructions
            assert b'get_openvpn_computer_config.py' in response.data
            assert b'Computer Identity' in response.data
            assert b'group profile' in response.data

    def test_psk_list_shows_psk_types(self, client):
        """Test that PSK list displays PSK types correctly."""
        with client.session_transaction() as sess:
            sess['user'] = {
                'sub': 'admin123',
                'groups': ['admin']
            }

        with client.application.app_context():
            # Create PSKs of different types
            server_psk = PreSharedKey(
                description='Server PSK',
                psk_type='server',
                template_set='default'
            )
            computer_psk = PreSharedKey(
                description='Computer PSK',
                psk_type='computer',
                template_set='sitetosite'
            )
            db.session.add_all([server_psk, computer_psk])
            db.session.commit()

        response = client.get('/admin/psk')
        assert response.status_code == 200

        # Should show both PSK types
        assert b'Server PSK' in response.data
        assert b'Computer PSK' in response.data
        # Should show type badges
        assert b'psk-type-server' in response.data
        assert b'psk-type-computer' in response.data

    def test_form_validation_defaults_psk_type_when_missing(self, client):
        """Test that PSK type defaults to 'server' when not provided in form."""
        with client.session_transaction() as sess:
            sess['user'] = {
                'sub': 'admin123',
                'groups': ['admin']
            }

        with patch('app.utils.server_templates.get_template_set_choices', return_value=[('default', 'Default')]), \
             patch('app.utils.render_config_template.get_group_profile_choices', return_value=[('Default', 'Default (0100.Default.ovpn)')]):
            # Submit form without psk_type - should default to server
            response = client.post('/admin/psk/new', data={
                'description': 'Test Default Type PSK',
                'template_set': 'default',
                'csrf_token': 'test-token'
                # Missing psk_type - should default to 'server'
            })

            # Form should succeed and create PSK
            assert response.status_code == 200
            assert b'PSK Created Successfully' in response.data

            # Verify PSK was created with default server type
            with client.application.app_context():
                psk = PreSharedKey.query.filter_by(description='Test Default Type PSK').first()
                assert psk is not None
                assert psk.psk_type == 'server'

    def test_psk_type_defaults_to_server(self, client):
        """Test that PSK type form defaults to server."""
        with client.session_transaction() as sess:
            sess['user'] = {
                'sub': 'admin123',
                'groups': ['admin']
            }

        with patch('app.utils.server_templates.get_template_set_choices', return_value=[('default', 'Default')]), \
             patch('app.utils.render_config_template.get_group_profile_choices', return_value=[('Default', 'Default (0100.Default.ovpn)')]):
            response = client.get('/admin/psk/new')
            assert response.status_code == 200
            # Should contain the server option as default
            assert b'value="server" selected' in response.data or b'Server Bundle' in response.data
            # Should expose both selectors so JS can swap them
            assert b'id="template_set"' in response.data
            assert b'id="group_profile"' in response.data

    def test_create_computer_psk_with_invalid_group_profile_rejected(self, client):
        """Computer PSK submission with a group profile not in the choices is rejected."""
        with client.session_transaction() as sess:
            sess['user'] = {
                'sub': 'admin123',
                'groups': ['admin']
            }

        with patch('app.utils.server_templates.get_template_set_choices', return_value=[('default', 'Default')]), \
             patch('app.utils.render_config_template.get_group_profile_choices', return_value=[('Developers', 'Developers (0200.Developers.ovpn)')]):
            response = client.post('/admin/psk/new', data={
                'description': 'Bad Group Profile PSK',
                'psk_type': 'computer',
                'group_profile': 'NotARealGroup',
                'csrf_token': 'test-token'
            })

            # Re-rendered form (200) but with field error and no PSK saved.
            assert response.status_code == 200
            assert b'Invalid group profile selected.' in response.data
            with client.application.app_context():
                assert PreSharedKey.query.filter_by(description='Bad Group Profile PSK').first() is None

    def test_create_computer_psk_no_group_profiles_redirects(self, client):
        """When no group profiles are configured, computer PSK creation redirects with a flash."""
        with client.session_transaction() as sess:
            sess['user'] = {
                'sub': 'admin123',
                'groups': ['admin']
            }

        with patch('app.utils.server_templates.get_template_set_choices', return_value=[('default', 'Default')]), \
             patch('app.utils.render_config_template.get_group_profile_choices', return_value=[]):
            response = client.post('/admin/psk/new', data={
                'description': 'No Profiles PSK',
                'psk_type': 'computer',
                'group_profile': '',
                'csrf_token': 'test-token'
            }, follow_redirects=False)

            assert response.status_code == 302
            with client.application.app_context():
                assert PreSharedKey.query.filter_by(description='No Profiles PSK').first() is None

    def test_create_server_psk_no_template_sets_redirects(self, client):
        """Server PSK POST with no server template sets redirects to PSK list."""
        with client.session_transaction() as sess:
            sess['user'] = {
                'sub': 'admin123',
                'groups': ['admin']
            }

        # Group profiles non-empty so the up-front "both empty" branch is bypassed,
        # forcing the POST handler into the server-only empty-list branch.
        with patch('app.utils.server_templates.get_template_set_choices', return_value=[]), \
             patch('app.utils.render_config_template.get_group_profile_choices', return_value=[('Default', 'Default (0100.Default.ovpn)')]):
            response = client.post('/admin/psk/new', data={
                'description': 'Server PSK No Templates',
                'psk_type': 'server',
                'template_set': '',
                'csrf_token': 'test-token'
            }, follow_redirects=False)

            assert response.status_code == 302
            with client.application.app_context():
                assert PreSharedKey.query.filter_by(description='Server PSK No Templates').first() is None

    def test_create_computer_psk_defaults_group_profile_when_blank(self, client):
        """Submitting a computer PSK with no selection picks the first available group profile."""
        with client.session_transaction() as sess:
            sess['user'] = {
                'sub': 'admin123',
                'groups': ['admin']
            }

        with patch('app.utils.server_templates.get_template_set_choices', return_value=[('default', 'Default')]), \
             patch('app.utils.render_config_template.get_group_profile_choices', return_value=[('Default', 'Default (0100.Default.ovpn)'), ('Developers', 'Developers (0200.Developers.ovpn)')]):
            response = client.post('/admin/psk/new', data={
                'description': 'Defaulted Group Profile PSK',
                'psk_type': 'computer',
                'group_profile': '',
                'csrf_token': 'test-token'
            })

            assert response.status_code == 200
            with client.application.app_context():
                psk = PreSharedKey.query.filter_by(description='Defaulted Group Profile PSK').first()
                assert psk is not None
                assert psk.psk_type == 'computer'
                assert psk.template_set == 'Default'