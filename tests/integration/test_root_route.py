"""
Integration tests for the root blueprint.
"""

def test_index_unauthenticated(client):
    """
    GIVEN a user who is not logged in
    WHEN a GET request is made to the '/' route
    THEN the user is redirected to the login page.
    """
    response = client.get('/', follow_redirects=False)
    
    assert response.status_code == 302
    assert response.location == '/auth/login'

def test_index_authenticated(client, app):
    """
    GIVEN a user who is logged in
    WHEN a GET request is made to the '/' route
    THEN check that the response is successful and contains the user-specific header.
    """
    # Arrange: Simulate a logged-in user and get the site name
    with client.session_transaction() as sess:
        # Using a name that we can specifically check for in the response
        sess['user'] = {'sub': '12345', 'name': 'Test User'}

    site_name = app.config.get('SITE_NAME', 'VPN Service')

    # Act
    response = client.get('/')
    
    # Assert
    assert response.status_code == 200
    # Check for the main content
    assert f"<h1>{site_name}</h1>".encode('utf-8') in response.data
    # Check for the authenticated user navigation
    assert b'Test User' in response.data
    assert b'Reauthenticate' in response.data