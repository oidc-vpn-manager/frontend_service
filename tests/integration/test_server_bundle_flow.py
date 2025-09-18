"""
Functional tests for the server bundle workflow end-to-end.
"""

import pytest
from unittest.mock import patch


class TestServerBundleFlow:
    """Functional tests for server bundle generation workflow."""

    def test_server_bundle_api_workflow(self, app, live_server, page, httpserver):
        """Test the complete server bundle API workflow via browser automation."""
        
        # Server templates are configured globally in conftest.py
        
        # Configure the app for the test
        app.config.update({
            'SIGNING_SERVICE_URL': httpserver.url_for("/"),
            'SIGNING_SERVICE_API_SECRET': 'test-signing-secret',
            'ROOT_CA_CERTIFICATE': '-----BEGIN CERTIFICATE-----\nROOT_CA_DATA\n-----END CERTIFICATE-----',
            'INTERMEDIATE_CA_CERTIFICATE': '-----BEGIN CERTIFICATE-----\nINTERMEDIATE_CA_DATA\n-----END CERTIFICATE-----',
            'OPENVPN_TLS_CRYPT_KEY': '-----BEGIN OpenVPN Static key V1-----\ntest-tls-crypt-key-data\n-----END OpenVPN Static key V1-----',
        })
        
        # Setup mock responses for the signing service httpserver
        httpserver.expect_request("/api/v1/sign-csr", method="POST").respond_with_json({
            'certificate': '-----BEGIN CERTIFICATE-----\ntest-signed-certificate-pem\n-----END CERTIFICATE-----',
            'status': 'success'
        })

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
        
        # Create a new PSK
        page.wait_for_selector('a:has-text("Create New PSK")', timeout=10000)
        page.click('a:has-text("Create New PSK")')
        
        # Fill in PSK creation form
        page.wait_for_selector('input[name="description"]', timeout=10000)
        page.fill('input[name="description"]', "test-functional-server")
        page.click('input[type="submit"]')
        
        # Wait for success page to load
        page.wait_for_load_state("load", timeout=10000)
        
        # Check we're on the success page
        assert "PSK Created Successfully" in page.evaluate('() => document.title')
        
        # The new post-creation screen shows the PSK directly in the Python command
        # No modal needed - PSK is displayed on the success page
        page.wait_for_timeout(2000)  # Wait for page to fully load
        
        # Extract the Python command from the success page
        python_command = page.locator('#pythonCommand').text_content()
        
        # Extract PSK from the command (it's after --psk)
        import re
        psk_match = re.search(r'--psk\s+(\S+)', python_command)
        test_psk = psk_match.group(1) if psk_match else None
        assert test_psk, f"Could not extract PSK from command: {python_command}"
        
        # Test server bundle API
        api_result = page.evaluate(f"""
            async () => {{
                try {{
                    const response = await fetch('{live_server.url()}/api/v1/server/bundle', {{
                        method: 'POST',
                        headers: {{
                            'Authorization': 'Bearer {test_psk}',
                            'Content-Type': 'application/json'
                        }},
                        body: JSON.stringify({{'description': 'test-functional-server'}})
                    }});
                    const responseText = await response.text();
                    return {{
                        status: response.status,
                        headers: Object.fromEntries(response.headers.entries()),
                        contentType: response.headers.get('content-type'),
                        body: responseText
                    }};
                }} catch (error) {{
                    return {{error: error.message}};
                }}
            }}
        """)
        
        assert 'error' not in api_result, f"API call failed: {api_result.get('error')}"
        print(f"API response status: {api_result['status']}")
        print(f"API response body: {api_result.get('body', 'No body')}")
        assert api_result['status'] == 200, f"Expected 200, got {api_result['status']}. Response: {api_result.get('body')}"
        assert api_result['contentType'] == 'application/gzip'

    def test_server_bundle_error_handling_workflow(self, app, live_server, page):
        """Test server bundle API error handling via browser."""
        
        # Test with invalid PSK
        page.goto(live_server.url())
        
        api_result = page.evaluate(f"""
            async () => {{
                try {{
                    const response = await fetch('{live_server.url()}/api/v1/server/bundle', {{
                        method: 'POST',
                        headers: {{
                            'Authorization': 'Bearer invalid-psk-token',
                            'Content-Type': 'application/json'
                        }},
                        body: JSON.stringify({{'description': 'test-server'}})
                    }});
                    const data = await response.json();
                    return {{
                        status: response.status,
                        data: data
                    }};
                }} catch (error) {{
                    return {{error: error.message}};
                }}
            }}
        """)
        
        # Verify error response
        assert 'error' not in api_result, f"Request failed: {api_result.get('error')}"
        assert api_result['status'] == 401
        assert 'error' in api_result['data']

    def test_server_bundle_development_mode_indicators(self, app, live_server, page):
        """Test that development mode warnings are visible during server bundle workflow."""
        
        # Navigate to admin page
        page.goto(f"{live_server.url()}/admin/psk")
        
        # Check for development mode warnings
        try:
            page.wait_for_selector('.alert-danger', timeout=5000)
            banner_text = page.locator('.alert-danger').text_content().lower()
            assert "development" in banner_text or "dev" in banner_text
        except:
            # Fallback: check for any development indicator
            page_content = page.content().lower()
            assert "development" in page_content or "[dev]" in page_content