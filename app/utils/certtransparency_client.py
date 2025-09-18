"""
HTTP client for communicating with the Certificate Transparency service.
"""

import requests
from typing import Dict, Optional, List, Any
from flask import current_app
from app.utils.tracing import trace

class CertTransparencyClientError(Exception):
    """Exception raised when Certificate Transparency service communication fails."""
    pass


class CertTransparencyClient:
    """Client for interacting with the Certificate Transparency service API."""
    
    def __init__(self, base_url: Optional[str] = None, timeout: int = 30):
        """
        Initialize the Certificate Transparency client.
        
        Args:
            base_url: Base URL for the Certificate Transparency service.
                     If None, will use CERTTRANSPARENCY_SERVICE_URL from config.
            timeout: Request timeout in seconds.
        """
        trace(
            current_app,
            'utils.certtransparency_client.CertTransparencyClient.__init__',
            {
                'self': 'SELF',
                'base_url': base_url,
                'timeout': timeout
            }
        )
        self.base_url = base_url or current_app.config.get(
            'CERTTRANSPARENCY_SERVICE_URL', 
            'http://certtransparency:8400'
        )
        self.timeout = timeout
        
    def _make_request(self, endpoint: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Make a GET request to the Certificate Transparency service.
        
        Args:
            endpoint: API endpoint (without leading slash)
            params: Query parameters
            
        Returns:
            JSON response data
            
        Raises:
            CertTransparencyClientError: If request fails or returns error
        """
        trace(
            current_app,
            'utils.certtransparency_client.CertTransparencyClient._make_request',
            {
                'self': 'SELF',
                'endpoint': endpoint,
                'params': params
            }
        )
        url = f"{self.base_url}/{endpoint}"
        
        try:
            response = requests.get(url, params=params, timeout=self.timeout)
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            current_app.logger.error(f"Certificate Transparency API request failed: {e}")
            raise CertTransparencyClientError(f"Failed to communicate with Certificate Transparency service: {e}")
        except ValueError as e:
            current_app.logger.error(f"Invalid JSON response from Certificate Transparency service: {e}")
            raise CertTransparencyClientError(f"Invalid response from Certificate Transparency service: {e}")
    
    def list_certificates(self, page: int = 1, limit: int = 100, **filters) -> Dict[str, Any]:
        """
        List certificates with pagination and filtering.
        
        Args:
            page: Page number (default: 1)
            limit: Number of results per page (default: 100, max: 1000)
            **filters: Additional filter parameters:
                - type: Certificate type ('client', 'server', 'intermediate')
                - subject: Filter by subject common name (partial match)
                - issuer: Filter by issuer common name (partial match)
                - serial: Filter by serial number (exact match)
                - fingerprint: Filter by SHA-256 fingerprint (exact match)
                - from_date: Filter certificates issued from this date (ISO format)
                - to_date: Filter certificates issued until this date (ISO format)
                - include_revoked: Include revoked certificates (default: true)
                - include_pem: Include PEM certificate data (default: false)
                - sort: Sort field ('issued_at', 'not_before', 'not_after', 'subject_common_name')
                - order: Sort order ('asc', 'desc') (default: 'desc')
        
        Returns:
            Dict containing certificates list and pagination metadata
        """
        trace(
            current_app,
            'utils.certtransparency_client.CertTransparencyClient.list_certificates',
            {
                'self': 'SELF',
                'page': page,
                'limit': limit,
                'filters': filters
            }
        )
        params = {'page': page, 'limit': limit}
        params.update(filters)
        
        return self._make_request('certificates', params=params)
    
    def get_certificate_by_fingerprint(self, fingerprint: str, include_pem: bool = True) -> Dict[str, Any]:
        """
        Get a specific certificate by its SHA-256 fingerprint.
        
        Args:
            fingerprint: SHA-256 fingerprint of the certificate
            include_pem: Include PEM certificate data (default: true)
        
        Returns:
            Dict containing certificate details
        """
        trace(
            current_app,
            'utils.certtransparency_client.CertTransparencyClient.get_certificate_by_fingerprint',
            {
                'self': 'SELF',
                'fingerprint': fingerprint,
                'include_pem': include_pem
            }
        )
        params = {'include_pem': str(include_pem).lower()}
        return self._make_request(f'certificates/{fingerprint}', params=params)
    
    def get_certificate_by_serial(self, serial_number: str, include_pem: bool = True) -> Dict[str, Any]:
        """
        Get a specific certificate by its serial number.
        
        Args:
            serial_number: Serial number of the certificate
            include_pem: Include PEM certificate data (default: true)
        
        Returns:
            Dict containing certificate details
        """
        trace(
            current_app,
            'utils.certtransparency_client.CertTransparencyClient.get_certificate_by_serial',
            {
                'self': 'SELF',
                'serial_number': serial_number,
                'include_pem': include_pem
            }
        )
        params = {'include_pem': str(include_pem).lower()}
        return self._make_request(f'certificates/serial/{serial_number}', params=params)
    
    def get_certificates_by_subject(self, common_name: str, include_pem: bool = False, 
                                   include_revoked: bool = True) -> Dict[str, Any]:
        """
        Get all certificates for a specific subject common name.
        
        Args:
            common_name: Subject common name
            include_pem: Include PEM certificate data (default: false)
            include_revoked: Include revoked certificates (default: true)
        
        Returns:
            Dict containing list of certificates for the subject
        """
        trace(
            current_app,
            'utils.certtransparency_client.CertTransparencyClient.get_certificates_by_subject',
            {
                'self': 'SELF',
                'common_name': common_name,
                'include_pem': include_pem,
                'include_revoked': include_revoked
            }
        )
        params = {
            'include_pem': str(include_pem).lower(),
            'include_revoked': str(include_revoked).lower()
        }
        return self._make_request(f'certificates/subject/{common_name}', params=params)
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get certificate transparency statistics.
        
        Returns:
            Dict containing various statistics about issued certificates
        """
        trace(
            current_app,
            'utils.certtransparency_client.CertTransparencyClient.get_statistics',
            {
                'self': 'SELF'
            }
        )
        return self._make_request('statistics')
    
    def search_certificates(self, query: str, exact: bool = False, limit: int = 100, 
                           include_pem: bool = False) -> Dict[str, Any]:
        """
        Search certificates with flexible criteria.
        
        Args:
            query: General search query (searches subject, issuer, serial, fingerprint)
            exact: Use exact matching instead of partial (default: false)
            limit: Number of results (default: 100, max: 1000)
            include_pem: Include PEM certificate data (default: false)
        
        Returns:
            Dict containing search results
        """
        trace(
            current_app,
            'utils.certtransparency_client.CertTransparencyClient.search_certificates',
            {
                'self': 'SELF',
                'query': query,
                'exact': exact,
                'limit': limit,
                'include_pem': include_pem
            }
        )
        params = {
            'q': query,
            'exact': str(exact).lower(),
            'limit': limit,
            'include_pem': str(include_pem).lower()
        }
        return self._make_request('search', params=params)
    
    def get_revoked_certificates(self) -> List[Dict[str, Any]]:
        """
        Get all revoked certificates for CRL generation.
        
        With the new append-only CT architecture, revoked certificates are stored
        as separate records with action_type='revoked'.
        
        Returns:
            List[Dict]: List of revoked certificate data suitable for CRL generation
            
        Raises:
            CertTransparencyClientError: If request fails
        """
        trace(
            current_app,
            'utils.certtransparency_client.CertTransparencyClient.get_revoked_certificates',
            {
                'self': 'SELF'
            }
        )
        params = {
            'revoked_only': 'true',
            'include_revocation_details': 'true',
            'limit': 10000
        }
        
        try:
            response = self._make_request('certificates', params=params)
            
            # Transform the data for CRL generation
            # In append-only model, look for certificates with revoked_at field set
            revoked_certs = []
            for cert in response.get('certificates', []):
                # Check if this certificate is revoked (has revoked_at timestamp)
                if cert.get('revoked_at'):
                    revoked_certs.append({
                        'serial_number': cert.get('serial_number'),
                        'revoked_at': cert.get('revoked_at'),
                        'revocation_reason': cert.get('revocation_reason', 'unspecified')
                    })
                    
            current_app.logger.debug(f"Found {len(revoked_certs)} revoked certificates for CRL generation")
            return revoked_certs
            
        except Exception as e:
            current_app.logger.error(f"Failed to retrieve revoked certificates: {e}")
            raise CertTransparencyClientError(f"Failed to retrieve revoked certificates: {e}")
    
    def revoke_certificate(self, fingerprint: str, reason: str, revoked_by: str) -> Dict[str, Any]:
        """
        Revoke a certificate by its fingerprint.
        
        Args:
            fingerprint (str): SHA-256 fingerprint of the certificate to revoke
            reason (str): Reason for revocation
            revoked_by (str): User ID who is performing the revocation
            
        Returns:
            Dict containing revocation status
            
        Raises:
            CertTransparencyClientError: If request fails
        """
        trace(
            current_app,
            'utils.certtransparency_client.CertTransparencyClient.revoke_certificate',
            {
                'self': 'SELF',
                'fingerprint': fingerprint,
                'reason': reason,
                'revoked_by': revoked_by
            }
        )
        url = f"{self.base_url}/certificates/{fingerprint}/revoke"
        data = {
            'reason': reason,
            'revoked_by': revoked_by
        }
        
        try:
            response = requests.post(url, json=data, timeout=self.timeout)
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            current_app.logger.error(f"Certificate revocation request failed: {e}")
            raise CertTransparencyClientError(f"Failed to revoke certificate: {e}")
    
    def bulk_revoke_user_certificates(self, user_id: str, reason: str, revoked_by: str) -> Dict[str, Any]:
        """
        Bulk revoke all active certificates for a specific user.

        Args:
            user_id (str): ID of the user whose certificates should be revoked
            reason (str): Reason for bulk revocation
            revoked_by (str): User ID who is performing the revocation

        Returns:
            Dict containing bulk revocation results

        Raises:
            CertTransparencyClientError: If request fails
        """
        trace(
            current_app,
            'utils.certtransparency_client.CertTransparencyClient.bulk_revoke_user_certificates',
            {
                'self': 'SELF',
                'user_id': user_id,
                'reason': reason,
                'revoked_by': revoked_by
            }
        )
        url = f"{self.base_url}/users/{user_id}/revoke-certificates"
        data = {
            'reason': reason,
            'revoked_by': revoked_by
        }

        try:
            response = requests.post(url, json=data, timeout=self.timeout)
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            current_app.logger.error(f"Bulk certificate revocation request failed: {e}")
            raise CertTransparencyClientError(f"Failed to bulk revoke certificates: {e}")

    def bulk_revoke_computer_certificates(self, psk_filter: str, reason: str, revoked_by: str) -> Dict[str, Any]:
        """
        Bulk revoke all active computer certificates matching PSK criteria.

        Args:
            psk_filter (str): PSK description or fragment to match certificates
            reason (str): Reason for bulk revocation
            revoked_by (str): User ID who is performing the revocation

        Returns:
            Dict containing bulk revocation results

        Raises:
            CertTransparencyClientError: If request fails
        """
        trace(
            current_app,
            'utils.certtransparency_client.CertTransparencyClient.bulk_revoke_computer_certificates',
            {
                'self': 'SELF',
                'psk_filter': psk_filter,
                'reason': reason,
                'revoked_by': revoked_by
            }
        )
        url = f"{self.base_url}/computer-certificates/bulk-revoke"
        data = {
            'psk_filter': psk_filter,
            'reason': reason,
            'revoked_by': revoked_by
        }

        try:
            response = requests.post(url, json=data, timeout=self.timeout)
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            current_app.logger.error(f"Bulk computer certificate revocation request failed: {e}")
            raise CertTransparencyClientError(f"Failed to bulk revoke computer certificates: {e}")

    def bulk_revoke_by_ca(self, ca_issuer: str, reason: str, revoked_by: str) -> Dict[str, Any]:
        """
        Bulk revoke all active certificates issued by a specific CA.

        Args:
            ca_issuer (str): Issuer common name or identifier
            reason (str): Reason for bulk revocation
            revoked_by (str): User ID who is performing the revocation

        Returns:
            Dict containing bulk revocation results

        Raises:
            CertTransparencyClientError: If request fails
        """
        trace(
            current_app,
            'utils.certtransparency_client.CertTransparencyClient.bulk_revoke_by_ca',
            {
                'self': 'SELF',
                'ca_issuer': ca_issuer,
                'reason': reason,
                'revoked_by': revoked_by
            }
        )
        url = f"{self.base_url}/certificates/bulk-revoke-by-ca"
        data = {
            'ca_issuer': ca_issuer,
            'reason': reason,
            'revoked_by': revoked_by
        }

        try:
            response = requests.post(url, json=data, timeout=self.timeout)
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            current_app.logger.error(f"Bulk CA certificate revocation request failed: {e}")
            raise CertTransparencyClientError(f"Failed to bulk revoke certificates by CA: {e}")

    def list_user_certificates(self, user_email: str, include_revoked: bool = True,
                              active_only: bool = False, revoked_only: bool = False) -> Dict[str, Any]:
        """
        List all certificates for a specific user email address.

        Args:
            user_email: User email address
            include_revoked: Include revoked certificates (default: True)
            active_only: Return only active certificates
            revoked_only: Return only revoked certificates

        Returns:
            Dict containing list of user certificates
        """
        trace(
            current_app,
            'utils.certtransparency_client.CertTransparencyClient.list_user_certificates',
            {
                'self': 'SELF',
                'user_email': user_email,
                'include_revoked': include_revoked,
                'active_only': active_only,
                'revoked_only': revoked_only
            }
        )
        params = {
            'subject': user_email,
            'include_revoked': str(include_revoked).lower(),
            'limit': 10000  # Large limit for complete user certificate listing
        }

        if active_only:
            params['active_only'] = 'true'
        elif revoked_only:
            params['revoked_only'] = 'true'

        return self._make_request('certificates', params=params)

    def list_computer_certificates(self, psk_filter: str = None, include_revoked: bool = True,
                                  active_only: bool = False, revoked_only: bool = False) -> Dict[str, Any]:
        """
        List computer certificates, optionally filtered by PSK criteria.

        Args:
            psk_filter: PSK description or fragment to match certificates (optional)
            include_revoked: Include revoked certificates (default: True)
            active_only: Return only active certificates
            revoked_only: Return only revoked certificates

        Returns:
            Dict containing list of computer certificates
        """
        trace(
            current_app,
            'utils.certtransparency_client.CertTransparencyClient.list_computer_certificates',
            {
                'self': 'SELF',
                'psk_filter': psk_filter,
                'include_revoked': include_revoked,
                'active_only': active_only,
                'revoked_only': revoked_only
            }
        )
        params = {
            'type': 'computer',
            'include_revoked': str(include_revoked).lower(),
            'limit': 10000  # Large limit for complete computer certificate listing
        }

        if psk_filter:
            params['subject'] = f"computer-{psk_filter}"

        if active_only:
            params['active_only'] = 'true'
        elif revoked_only:
            params['revoked_only'] = 'true'

        return self._make_request('certificates', params=params)


def get_certtransparency_client() -> CertTransparencyClient:
    """
    Get a Certificate Transparency client instance.
    
    Returns:
        CertTransparencyClient instance
    """
    trace(current_app, 'utils.certtransparency_client.get_certtransparency_client')
    return CertTransparencyClient()