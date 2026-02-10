"""
Signing service CRL client for generating Certificate Revocation Lists.

This module provides a client for communicating with the signing service
to generate CRLs based on revocation data from the Certificate Transparency service.
"""

import requests
import logging
from typing import List, Dict, Any, Optional
from flask import current_app

from app.utils.environment import loadConfigValueFromFileOrEnvironment
from app.utils.tracing import trace


class SigningCRLClientError(Exception):
    """Exception raised for signing service CRL client errors."""
    pass


def get_signing_crl_client():
    """Get a configured signing CRL client."""
    return SigningCRLClient()


class SigningCRLClient:
    """Client for interacting with the signing service CRL generation."""
    
    def __init__(self):
        trace(
            current_app,
            'utils.signing_crl_client.SigningCRLClient.__init__',
            {
                'self': 'SELF'
            }
        )
        self.base_url = loadConfigValueFromFileOrEnvironment('SIGNING_SERVICE_URL', 'http://localhost:8500')
        self.api_secret = loadConfigValueFromFileOrEnvironment('SIGNING_SERVICE_API_SECRET', '')
        self.session = requests.Session()
        self.session.headers.update({
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {self.api_secret}'
        })
        from app.utils.environment import loadBoolConfigValue
        tls_validate = loadBoolConfigValue('SIGNING_SERVICE_URL_TLS_VALIDATE', 'true')
        if self.base_url.startswith('https://') and not tls_validate:
            self.session.verify = False

    def generate_crl(self, revoked_certificates: List[Dict[str, Any]], next_update_hours: int = 24) -> bytes:
        """
        Generate a CRL by sending revoked certificate data to the signing service.
        
        Args:
            revoked_certificates: List of revoked certificate dictionaries
            next_update_hours: Hours until next CRL update (default 24)
            
        Returns:
            CRL data in DER format
            
        Raises:
            SigningCRLClientError: If the signing service request fails
        """
        trace(
            current_app,
            'utils.signing_crl_client.SigningCRLClient.generate_crl',
            {
                'self': 'SELF',
                'revoked_certificates': revoked_certificates,
                'next_update_hours': next_update_hours
            }
        )
        endpoint = f"{self.base_url}/api/v1/generate-crl"
        
        payload = {
            'revoked_certificates': revoked_certificates,
            'next_update_hours': next_update_hours
        }
        
        try:
            current_app.logger.debug(f"Requesting CRL generation for {len(revoked_certificates)} revoked certificates")
            
            response = self.session.post(endpoint, json=payload, timeout=30)
            response.raise_for_status()
            
            current_app.logger.info(f"Successfully generated CRL from signing service, size: {len(response.content)} bytes")
            return response.content
            
        except requests.exceptions.RequestException as e:
            error_msg = f"Failed to generate CRL from signing service: {e}"
            current_app.logger.error(error_msg)
            raise SigningCRLClientError(error_msg) from e