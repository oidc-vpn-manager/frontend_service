def test_swagger_docs_load(live_server, page):
    """
    GIVEN a running frontend application
    WHEN a user navigates to the /api/docs endpoint
    THEN the Swagger UI documentation page is displayed correctly.
    """
    # Act: Navigate to the live server's API docs URL
    page.goto(f"{live_server.url()}/api/docs")
    
    # Wait for Swagger UI JavaScript to render
    page.wait_for_load_state('networkidle', timeout=10000)
    
    # Wait for the swagger content to load by looking for a known swagger UI element
    try:
        page.wait_for_selector('.swagger-ui', timeout=10000)
    except:
        pass  # Continue with the test even if selector doesn't appear

    # Assert: Check the page title
    # The title is set by the 'app_name' config when creating the swagger blueprint
    expected_title = f"{live_server.app.config.get('SITE_NAME')} API"
    assert page.title() == expected_title

    # Assert: Check for swagger UI elements that should be present
    page_content = page.content()
    assert "swagger-ui" in page_content
    assert "swagger-ui-bundle" in page_content