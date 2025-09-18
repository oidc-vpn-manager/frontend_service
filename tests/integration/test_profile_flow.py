import time
import os
import pytest
from unittest.mock import patch

@patch('app.routes.profile.process_tls_crypt_key')
def test_user_profile_generation_flow(mock_process_tls_crypt_key, live_server, page, httpserver):
    """
    GIVEN a running frontend application
    WHEN a logged-in user selects an option and generates a profile
    THEN an .ovpn file with the correct settings is downloaded.
    """
    # Arrange 1: Set up the mock signing service and TLS processing
    app = live_server.app
    mock_certificate = "-----BEGIN CERTIFICATE-----\nSIGNED_CERT_DATA\n-----END CERTIFICATE-----"
    httpserver.expect_request("/api/v1/sign-csr").respond_with_json({
        "certificate": mock_certificate
    })
    
    # Mock TLS key processing to return a valid result
    mock_process_tls_crypt_key.return_value = (1, "mock-tls-crypt-key-data")

    # Arrange 2: Configure the live frontend app to use the mock server's URL
    app.config["SIGNING_SERVICE_URL"] = httpserver.url_for("/")
    app.config["SIGNING_SERVICE_API_SECRET"] = "test-signing-secret"
    
    # Configure OVPN options so the form has elements to interact with
    app.config["OVPN_OPTIONS"] = {
        "use_tcp": {
            "display_name": "Use TCP Protocol",
            "description": "Use TCP instead of UDP for better reliability",
            "settings": {
                "proto": "tcp-client",
                "port": "443"
            }
        }
    }
    
    # Configure other required settings with proper template structure
    app.config["TEMPLATE_COLLECTION"] = [
        {
            'name': 'default.ovpn',
            'priority': 100,
            'target_groups': [],
            'content': '''# OpenVPN Client Configuration
client
dev tun
{% if proto %}proto {{ proto }}{% else %}proto udp{% endif %}
{% if port %}port {{ port }}{% else %}port 1194{% endif %}
remote vpn.example.com {% if port %}{{ port }}{% else %}1194{% endif %}
resolv-retry infinite
nobind
persist-key
persist-tun
{% if tlscrypt_version == 2 %}tls-crypt-v2 <connection>{% else %}tls-crypt <connection>{% endif %}
{{ tlscrypt_key }}
</connection>
<ca>
{{ ca_cert_pem }}
</ca>
<cert>
{{ device_cert_pem }}
</cert>
<key>
{{ device_key_pem }}
</key>
verb 3'''
        }
    ]
    app.config["ROOT_CA_CERTIFICATE"] = "-----BEGIN CERTIFICATE-----\nROOT_CA_DATA\n-----END CERTIFICATE-----"
    app.config["INTERMEDIATE_CA_CERTIFICATE"] = "-----BEGIN CERTIFICATE-----\nINTERMEDIATE_CA_DATA\n-----END CERTIFICATE-----"

    # Arrange 3: Set up authentication using test endpoint
    # Navigate to home page first to set up session
    page.goto(f"{live_server.url()}/")
    
    # Set up user session using test endpoint
    page.evaluate(f"""
        () => fetch('{live_server.url()}/test/set-session', {{
            method: 'POST',
            headers: {{'Content-Type': 'application/json'}},
            body: JSON.stringify({{
                user_id: 'test-user',
                email: 'user@example.com',
                name: 'Test User',
                groups: ['users']
            }})
        }})
    """)
    
    # Act 1: Navigate to the home page - session should be set up
    page.goto(f"{live_server.url()}/")
    
    # Check if page loaded successfully
    if page.locator('text="An Error Occurred"').is_visible(timeout=1000):
        page_content = page.content()
        print("ERROR DETECTED:")
        print(page_content)
        pytest.fail("Error occurred during profile generation")
    
    # Wait for the form to load, then expand details if present (collapsible options)
    page.wait_for_selector('form', timeout=10000)
    
    # Check if there's a details element that needs expanding (for collapsible options)
    details_summary = page.locator("details summary")
    if details_summary.count() > 0:
        details_summary.click()
    
    # Now wait for and check the TCP checkbox
    page.wait_for_selector('#use_tcp', timeout=10000)
    page.check('#use_tcp')
    
    # Set up download handler before clicking submit
    with page.expect_download() as download_info:
        page.click('input[type="submit"]')
    
    download = download_info.value
    
    # Save the download to verify content
    download_path = page.download_dir / "dev.ovpn"
    download.save_as(download_path)

    # Assert: Check the contents of the downloaded file
    with open(download_path, 'r') as f:
        config_content = f.read()

    assert "SIGNED_CERT_DATA" in config_content
    assert "proto tcp-client" in config_content
    assert "port 443" in config_content