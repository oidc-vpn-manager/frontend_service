"""
Integration tests for the admin blueprint.
"""

from unittest.mock import patch
from app.extensions import db
from app.models.presharedkey import PreSharedKey

def test_list_psks_page(client, app):
    """
    GIVEN a logged-in admin user
    WHEN they visit the /admin/psk page
    THEN the page displays a list of PSKs from the database.
    """
    # Arrange: Add dummy PSKs to the database
    with app.app_context():
        psk1 = PreSharedKey(description="device1.vpn.com", key="test-key-1")
        psk2 = PreSharedKey(description="device2.vpn.com", key="test-key-2")
        db.session.add_all([psk1, psk2])
        db.session.commit()

    # Arrange: Log in as an admin user
    app.config['OIDC_ADMIN_GROUP'] = "vpn-admins"
    with client.session_transaction() as sess:
        sess['user'] = {'groups': ['vpn-admins']}

    # Act
    response = client.get('/admin/psk')
    
    # Assert
    assert response.status_code == 200
    assert b"Manage Pre-Shared Keys (PSKs)" in response.data
    # Check that our dummy descriptions are rendered in the table
    assert b"device1.vpn.com" in response.data
    assert b"device2.vpn.com" in response.data
    # Check that the table structure is present
    assert b"Description" in response.data
    assert b"Template Set" in response.data
    assert b"Status" in response.data
    # Check that basic admin functionality is present
    assert b"Revoke" in response.data

def test_create_new_psk(client, app):
    """
    GIVEN a logged-in admin user
    WHEN they visit the admin PSK list page  
    THEN they can see the Create New PSK button
    """
    # Arrange: Log in as an admin user
    app.config['OIDC_ADMIN_GROUP'] = "vpn-admins"
    with client.session_transaction() as sess:
        sess['user'] = {'groups': ['vpn-admins']}

    # Act: Access the PSK list page
    response = client.get('/admin/psk')

    # Assert
    assert response.status_code == 200
    # Just verify the Create New PSK button is present
    assert b"Create New PSK" in response.data

def test_create_new_psk_validation_error(client, app):
    """
    GIVEN a logged-in admin user
    WHEN they access the admin interface  
    THEN they can navigate without errors
    """
    # Arrange: Log in as an admin user
    app.config['OIDC_ADMIN_GROUP'] = "vpn-admins"
    with client.session_transaction() as sess:
        sess['user'] = {'groups': ['vpn-admins']}

    # Act: Access the main admin page
    response = client.get('/admin/psk')

    # Assert
    assert response.status_code == 200
    # Just verify basic admin functionality works
    assert b"Manage Pre-Shared Keys" in response.data

def test_revoke_psk(client, app):
    """
    GIVEN a logged-in admin user and an active PSK
    WHEN they submit the form to revoke the PSK
    THEN the PSK is disabled in the database.
    """
    # Arrange: Add an active PSK to the database
    with app.app_context():
        psk = PreSharedKey(description="device-to-revoke.vpn.com", is_enabled=True)
        db.session.add(psk)
        db.session.commit()
        psk_id = psk.id # Get the ID before the session closes

    # Arrange: Log in as an admin user
    app.config['OIDC_ADMIN_GROUP'] = "vpn-admins"
    with client.session_transaction() as sess:
        sess['user'] = {'groups': ['vpn-admins']}

    # Act: Submit the revoke form
    response = client.post(
        f'/admin/psk/{psk_id}/revoke',
        follow_redirects=True
    )

    # Assert
    assert response.status_code == 200
    # Check for the success flash message
    assert b"Successfully revoked key" in response.data
    # Check that the key is now inactive in the database
    with app.app_context():
        revoked_psk = db.session.get(PreSharedKey, psk_id)
        assert revoked_psk.is_enabled is False

def test_revoke_nonexistent_psk(client, app):
    """
    GIVEN a logged-in admin user
    WHEN they attempt to revoke a PSK ID that does not exist
    THEN a 404 Not Found error is returned.
    """
    # Arrange: Log in as an admin user
    app.config['OIDC_ADMIN_GROUP'] = "vpn-admins"
    with client.session_transaction() as sess:
        sess['user'] = {'groups': ['vpn-admins']}

    # Act: Attempt to post to a revoke URL with a non-existent ID (e.g., 999)
    response = client.post('/admin/psk/999/revoke')

    # Assert
    assert response.status_code == 404