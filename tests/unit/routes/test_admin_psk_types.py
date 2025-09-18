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

        with patch('app.utils.server_templates.get_template_set_choices', return_value=[('default', 'Default')]):
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
                assert psk.is_server_psk() is True
                assert psk.is_computer_psk() is False

    def test_create_computer_psk_type(self, client):
        """Test creating a computer PSK through admin interface."""
        with client.session_transaction() as sess:
            sess['user'] = {
                'sub': 'admin123',
                'groups': ['admin']
            }

        with patch('app.utils.server_templates.get_template_set_choices', return_value=[('sitetosite', 'Site-to-Site')]):
            response = client.post('/admin/psk/new', data={
                'description': 'Test Computer PSK',
                'psk_type': 'computer',
                'template_set': 'sitetosite',
                'csrf_token': 'test-token'
            })

            assert response.status_code == 200

            # Verify PSK was created with correct type
            with client.application.app_context():
                psk = PreSharedKey.query.filter_by(description='Test Computer PSK').first()
                assert psk is not None
                assert psk.psk_type == 'computer'
                assert psk.is_computer_psk() is True
                assert psk.is_server_psk() is False

    def test_psk_created_template_shows_correct_instructions(self, client):
        """Test that PSK created template shows appropriate instructions for each type."""
        with client.session_transaction() as sess:
            sess['user'] = {
                'sub': 'admin123',
                'groups': ['admin']
            }

        with patch('app.utils.server_templates.get_template_set_choices', return_value=[('default', 'Default')]):
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

            # Create computer PSK
            response = client.post('/admin/psk/new', data={
                'description': 'Test Computer Instructions',
                'psk_type': 'computer',
                'template_set': 'default',
                'csrf_token': 'test-token'
            })

            assert response.status_code == 200
            # Should contain computer identity instructions
            assert b'get_openvpn_computer_config.py' in response.data
            assert b'Computer Identity' in response.data

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

        with patch('app.utils.server_templates.get_template_set_choices', return_value=[('default', 'Default')]):
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

        with patch('app.utils.server_templates.get_template_set_choices', return_value=[('default', 'Default')]):
            response = client.get('/admin/psk/new')
            assert response.status_code == 200
            # Should contain the server option as default
            assert b'value="server" selected' in response.data or b'Server Bundle' in response.data