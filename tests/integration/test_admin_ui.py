from unittest.mock import patch
from app.extensions import db
from app.models.presharedkey import PreSharedKey

def test_psk_list_page(live_server, page):
    """
    GIVEN a running frontend application
    WHEN an admin user creates PSKs and navigates to the /admin/psk page
    THEN the list of PSKs is displayed.
    """
    # Debug: Check server templates configuration  
    print(f"SERVER_TEMPLATES_DIR: {live_server.app.config.get('SERVER_TEMPLATES_DIR')}")
    
    # Navigate to home page first to set up session
    page.goto(f"{live_server.url()}/")
    
    # Set up admin session using test endpoint
    admin_group = live_server.app.config.get('OIDC_ADMIN_GROUP', 'admins')
    page.evaluate(f"""
        () => fetch('{live_server.url()}/test/set-session', {{
            method: 'POST',
            headers: {{'Content-Type': 'application/json'}},
            body: JSON.stringify({{
                user_id: 'test-admin-user',
                email: 'admin@example.com',
                name: 'Test Admin',
                groups: ['{admin_group}']
            }})
        }})
    """)
    
    # Create first PSK via web interface
    page.goto(f"{live_server.url()}/admin/psk/new")
    
    # Debug: Check what's actually on the page
    page_content = page.content()
    print("=== PAGE CONTENT ===")
    print(page_content)  # Full content to see flash messages
    print("=== END PAGE CONTENT ===")
    
    # Check if we got redirected due to server template issue
    current_url = page.url
    print(f"Current URL: {current_url}")
    
    if 'admin/psk/new' not in current_url:
        print("Redirected away from new PSK page - likely server template issue")
        print("Checking what page we actually got to...")
        # Don't skip anymore, let's see what the actual error is
    
    page.wait_for_selector('input[name="description"]', timeout=10000)
    page.fill('input[name="description"]', "device1.functional.test")
    page.click('input[type="submit"]')
    
    # Create second PSK via web interface
    page.goto(f"{live_server.url()}/admin/psk/new")
    page.wait_for_selector('input[name="description"]', timeout=10000)
    page.fill('input[name="description"]', "device2.functional.test")
    page.click('input[type="submit"]')
    
    # Now navigate to admin page to verify PSKs are listed
    page.goto(f"{live_server.url()}/admin/psk")

    assert page.title().startswith("Manage Pre-Shared Keys")
    page_content = page.content()
    assert "<h1>Manage Pre-Shared Keys (PSKs)</h1>" in page_content
    # Check that PSKs were created (look for forms with revoke actions)
    assert "/admin/psk/1/revoke" in page_content or "/admin/psk/2/revoke" in page_content
    # Check that we don't see the "No Pre-Shared Keys" message
    assert "No Pre-Shared Keys have been created yet" not in page_content

def test_create_psk_flow(live_server, page):
    """
    GIVEN a running frontend application
    WHEN an admin user creates a new PSK via the UI
    THEN the new PSK appears in the list.
    """
    # Server templates are configured globally in conftest.py
    # Navigate to home page first to set up session
    page.goto(f"{live_server.url()}/")
    
    # Set up admin session using test endpoint
    admin_group = live_server.app.config.get('OIDC_ADMIN_GROUP', 'admins')
    page.evaluate(f"""
        () => fetch('{live_server.url()}/test/set-session', {{
            method: 'POST',
            headers: {{'Content-Type': 'application/json'}},
            body: JSON.stringify({{
                user_id: 'test-admin-user',
                email: 'admin@example.com',
                name: 'Test Admin',
                groups: ['{admin_group}']
            }})
        }})
    """)
    
    # Now navigate to admin page - session should be set up
    page.goto(f"{live_server.url()}/admin/psk")
    page.wait_for_selector('a:has-text("Create New PSK")', timeout=10000)
    page.click('a:has-text("Create New PSK")')

    page.wait_for_selector('text="Create New Pre-Shared Key"', timeout=10000)

    page.wait_for_selector('input[name="description"]', timeout=10000)
    page.fill('input[name="description"]', "new-device.functional.test")
    page.click('input[type="submit"]')

    # Wait for a page load/navigation (not necessarily to a specific URL)
    page.wait_for_load_state("load", timeout=10000)
    
    # Debug: Check what page we're actually on
    current_url = page.url
    print(f"After form submission - Current URL: {current_url}")
    page_content = page.content()
    print(f"Page title: {page.evaluate('() => document.title')}")
    
    # Check if we're on the right page (either success page or list page)
    if 'admin/psk' not in current_url:
        print("Not on expected PSK admin page")
        print(f"Page content snippet: {page_content[:500]}...")
        # Let's continue anyway to see what happens

    # Now that the new page has loaded, we can make our assertions
    page_content = page.content()
    assert "new-device.functional.test" in page_content
    assert "Pre-Shared Key Created Successfully" in page_content

def test_revoke_psk_flow(live_server, page):
    """
    GIVEN a running frontend application
    WHEN an admin user creates and then revokes a PSK via the UI
    THEN the PSK's status is updated on the list page.
    """
    # Server templates are configured globally in conftest.py
    # Navigate to home page first to set up session
    page.goto(f"{live_server.url()}/")
    
    # Set up admin session using test endpoint
    admin_group = live_server.app.config.get('OIDC_ADMIN_GROUP', 'admins')
    page.evaluate(f"""
        () => fetch('{live_server.url()}/test/set-session', {{
            method: 'POST',
            headers: {{'Content-Type': 'application/json'}},
            body: JSON.stringify({{
                user_id: 'test-admin-user',
                email: 'admin@example.com',
                name: 'Test Admin',
                groups: ['{admin_group}']
            }})
        }})
    """)
    
    # Create a PSK via web interface first
    page.goto(f"{live_server.url()}/admin/psk/new")
    page.wait_for_selector('input[name="description"]', timeout=10000)
    page.fill('input[name="description"]', "device-to-revoke.test")
    page.click('input[type="submit"]')
    
    # Now navigate to admin page and find the revoke form
    page.goto(f"{live_server.url()}/admin/psk")
    page.wait_for_selector('form[action*="/revoke"]', timeout=10000)
    
    # Handle JavaScript confirm dialog
    page.on("dialog", lambda dialog: dialog.accept())
    page.click('form[action*="/revoke"] button')

    # Wait for the "Successfully revoked" flash message to appear
    page.wait_for_selector('text=/.*revoked.*/i', timeout=10000)

    page_content = page.content()
    assert "Inactive/Expired" in page_content