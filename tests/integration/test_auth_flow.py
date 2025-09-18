def test_homepage_redirects_unauthenticated_user(live_server, page):
    """
    GIVEN a running frontend application
    WHEN an unauthenticated user visits the home page with a browser
    THEN they should be redirected to the mocked OIDC login page.
    """
    page.goto(live_server.url())

    # Assert that the browser followed all redirects and landed on our mock page
    assert "/mock_oidc_login" in page.url
    assert "redirect_uri" in page.url