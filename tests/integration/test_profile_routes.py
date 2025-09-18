"""
Integration tests for the profile blueprint.
"""

import pytest
from app.utils.signing_client import SigningServiceError

def test_config_page_loads_for_authenticated_user(client, app):
    """
    GIVEN a logged-in user
    WHEN they visit the root config page
    THEN the form with OVPN options is displayed.
    """
    # Arrange: Add some test options to the app config
    app.config['OVPN_OPTIONS'] = {
        'use_tcp': {
            'display_name': 'Use TCP Test',
            'description': 'A test description.'
        }
    }

    with client.session_transaction() as sess:
        sess['user'] = {'sub': '123', 'name': 'Test User'}

    # Act
    response = client.get('/')

    # Assert
    assert response.status_code == 200
    assert b"Generate VPN Configuration" in response.data
    assert b"Use TCP Test" in response.data # Check for the option's display name

def test_config_generation_handles_signing_error(client, app, monkeypatch):
    """
    GIVEN the signing service returns an error
    WHEN a user posts to the config generation endpoint
    THEN a graceful error page is displayed.
    """
    # Arrange: Mock the signing client to raise an error directly
    def mock_raise_error(csr_pem, user_id=None, client_ip=None, request_metadata=None):
        raise SigningServiceError('Test signing error')

    monkeypatch.setattr(
        'app.routes.root.request_signed_certificate',
        mock_raise_error
    )

    with client.session_transaction() as sess:
        sess['user'] = {'sub': '123', 'email': 'test@example.com'}

    # Act
    response = client.post('/')

    # Assert
    assert response.status_code == 500
    assert b"Error generating configuration: Test signing error" in response.data

def test_config_generation_lazy_loads_templates(client, app, httpserver, tmp_path):
    """
    GIVEN that the OVPN templates have not been loaded into the config
    WHEN a user generates a profile
    THEN the application should load the templates from the filesystem.
    """
    # Arrange 1: Create a dummy template file on disk
    template_dir = tmp_path / "ovpn_templates"
    template_dir.mkdir()
    (template_dir / "999.default.ovpn").write_text("proto {{ protocol }}")
    
    # Arrange 2: Configure the app
    app.config['OVPN_TEMPLATE_PATH'] = str(template_dir)
    app.config['TEMPLATE_COLLECTION'] = None
    # Add the OVPN_OPTIONS to this test's config
    app.config['OVPN_OPTIONS'] = {
        'use_tcp': {
            'display_name': 'Use TCP Test',
            'description': 'A test description.',
            'settings': {
                'protocol': 'tcp-client',
            }
        }
    }
    
    # Arrange 3: Set up mocks and log in the user
    httpserver.expect_request("/api/v1/sign-csr").respond_with_json({"certificate": "cert"})
    app.config["SIGNING_SERVICE_URL"] = httpserver.url_for("/")
    app.config["SIGNING_SERVICE_API_SECRET"] = "test-secret"

    with client.session_transaction() as sess:
        sess['user'] = {'sub': '123', 'email': 'test@example.com'}
    
    # Act
    response = client.post('/', data={'options': 'use_tcp'})
    
    # Assert (with debugging)
    if response.status_code != 200:
        print(f"\nDEBUG: Server response text: {response.get_data(as_text=True)}")

    assert response.status_code == 200
    assert b"proto tcp-client" in response.data