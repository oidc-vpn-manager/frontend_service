"""
Client for communicating with the internal Signing Service API.
"""

import requests
from flask import current_app
from app.utils.tracing import trace

class SigningServiceError(Exception):
    """Custom exception for errors from the signing service."""
    pass

def request_signed_certificate(csr_pem: str, user_id: str = None, certificate_type: str = 'client', client_ip: str = None) -> str:
    """
    Requests a signed certificate from the signing service.

    Args:
        csr_pem: The PEM-encoded Certificate Signing Request string.
        user_id: Optional user ID to track who requested the certificate.
        certificate_type: Type of certificate ('client' or 'server'). Defaults to 'client'.
        client_ip: Optional client IP address for geolocation tracking.

    Returns:
        The PEM-encoded signed certificate string.

    Raises:
        SigningServiceError: If the API call fails or returns an error.
    """
    trace(
        current_app,
        'utils.signing_client.request_signed_certificate',
        {
            'csr_pem': csr_pem,
            'user_id': user_id,
            'certificate_type': certificate_type,
            'client_ip': client_ip
        }
    )
    # 1. Get configuration
    service_url = current_app.config.get('SIGNING_SERVICE_URL')
    api_secret = current_app.config.get('SIGNING_SERVICE_API_SECRET')

    if not service_url or not api_secret:
        raise SigningServiceError("Signing service is not configured.")

    endpoint_url = f"{service_url}/api/v1/sign-csr"
    headers = {'Authorization': f'Bearer {api_secret}'}
    payload = {'csr': csr_pem, 'certificate_type': certificate_type}
    
    # Include user_id in payload if provided and not empty
    if user_id and user_id.strip():
        payload['user_id'] = user_id
    
    # Include client_ip in payload if provided and not empty
    if client_ip and client_ip.strip():
        payload['client_ip'] = client_ip

    try:
        # 2. Make the request
        response = requests.post(
            endpoint_url,
            headers=headers,
            json=payload,
            timeout=5 # Set a reasonable timeout
        )
        # Raise an exception for HTTP error statuses (4xx or 5xx)
        response.raise_for_status()

        # 3. Process the successful response
        response_json = response.json()
        return response_json['certificate']

    except requests.exceptions.RequestException as e:
        # Catch network errors, timeouts, etc.
        raise SigningServiceError(f"Failed to connect to signing service: {e}")
    except (KeyError, ValueError) as e:
        # Catch malformed JSON responses or missing 'certificate' key
        raise SigningServiceError(f"Invalid response from signing service: {e}")


def request_certificate_revocation(fingerprint: str, reason: str, revoked_by: str) -> dict:
    """
    Request certificate revocation from the signing service.
    
    Args:
        fingerprint: SHA-256 fingerprint of the certificate to revoke
        reason: Reason for revocation
        revoked_by: User ID who is performing the revocation
        
    Returns:
        Dict containing revocation response
        
    Raises:
        SigningServiceError: If the API call fails or returns an error
    """
    trace(
        current_app,
        'utils.signing_client.request_certificate_revocation',
        {
            'fingerprint': fingerprint,
            'reason': reason,
            'revoked_by': revoked_by
        }
    )
    # 1. Get configuration
    service_url = current_app.config.get('SIGNING_SERVICE_URL')
    api_secret = current_app.config.get('SIGNING_SERVICE_API_SECRET')
    
    if not service_url or not api_secret:
        raise SigningServiceError("Signing service is not configured.")
    
    endpoint_url = f"{service_url}/api/v1/revoke-certificate"
    headers = {'Authorization': f'Bearer {api_secret}'}
    payload = {
        'fingerprint': fingerprint,
        'reason': reason,
        'revoked_by': revoked_by
    }
    
    try:
        # 2. Make the request
        response = requests.post(
            endpoint_url,
            headers=headers,
            json=payload,
            timeout=10  # Revocation might take longer than signing
        )
        
        # 3. Handle response
        if response.status_code == 404:
            raise SigningServiceError("Certificate not found")
        elif response.status_code == 400:
            error_msg = response.json().get('error', 'Bad request')
            raise SigningServiceError(f"Invalid revocation request: {error_msg}")
        elif response.status_code == 503:
            raise SigningServiceError("Certificate Transparency service unavailable")
        
        # Raise an exception for other HTTP error statuses  
        response.raise_for_status()
        
        # 4. Process the successful response
        response_json = response.json()
        current_app.logger.info(f"Certificate {fingerprint} revoked successfully via signing service")
        return response_json
        
    except requests.exceptions.RequestException as e:
        # Catch network errors, timeouts, etc.
        raise SigningServiceError(f"Failed to connect to signing service: {e}")
    except (KeyError, ValueError) as e:
        # Catch malformed JSON responses
        raise SigningServiceError(f"Invalid response from signing service: {e}")


def request_bulk_certificate_revocation(user_id: str, reason: str, revoked_by: str) -> dict:
    """
    Request bulk certificate revocation for all user certificates from the signing service.
    
    Args:
        user_id: User ID whose certificates should be revoked
        reason: Reason for revocation
        revoked_by: User ID who is performing the revocation
        
    Returns:
        Dict containing bulk revocation response
        
    Raises:
        SigningServiceError: If the API call fails or returns an error
    """
    trace(
        current_app,
        'utils.signing_client.request_bulk_certificate_revocation',
        {
            'user_id': user_id,
            'reason': reason,
            'revoked_by': revoked_by
        }
    )
    # 1. Get configuration
    service_url = current_app.config.get('SIGNING_SERVICE_URL')
    api_secret = current_app.config.get('SIGNING_SERVICE_API_SECRET')
    
    if not service_url or not api_secret:
        raise SigningServiceError("Signing service is not configured.")
    
    endpoint_url = f"{service_url}/api/v1/bulk-revoke-user-certificates"
    headers = {'Authorization': f'Bearer {api_secret}'}
    payload = {
        'user_id': user_id,
        'reason': reason,
        'revoked_by': revoked_by
    }
    
    try:
        # 2. Make the request
        response = requests.post(
            endpoint_url,
            headers=headers,
            json=payload,
            timeout=30  # Bulk operations might take longer
        )
        
        # 3. Handle response
        if response.status_code == 400:
            error_msg = response.json().get('error', 'Bad request')
            raise SigningServiceError(f"Invalid bulk revocation request: {error_msg}")
        elif response.status_code == 503:
            raise SigningServiceError("Certificate Transparency service unavailable")
        
        # Raise an exception for other HTTP error statuses  
        response.raise_for_status()
        
        # 4. Process the successful response
        response_json = response.json()
        revoked_count = response_json.get('revoked_count', 0)
        current_app.logger.info(f"Bulk revocation completed via signing service: {revoked_count} certificates revoked for user {user_id}")
        return response_json
        
    except requests.exceptions.RequestException as e:
        # Catch network errors, timeouts, etc.
        raise SigningServiceError(f"Failed to connect to signing service: {e}")
    except (KeyError, ValueError) as e:
        # Catch malformed JSON responses
        raise SigningServiceError(f"Invalid response from signing service: {e}")