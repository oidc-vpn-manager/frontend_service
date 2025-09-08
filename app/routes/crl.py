"""
Certificate Revocation List (CRL) endpoint.

This module provides a public, unauthenticated endpoint for OpenVPN servers
and other systems to download the current Certificate Revocation List.
"""

from flask import Blueprint, current_app, Response
from app.utils.tracing import trace
from app.utils.certtransparency_client import get_certtransparency_client, CertTransparencyClientError
from app.utils.signing_crl_client import get_signing_crl_client, SigningCRLClientError
import time

bp = Blueprint('crl', __name__)


@bp.route('/crl', methods=['GET', 'HEAD'])
def get_crl():
    """
    Generate and return the current Certificate Revocation List.
    
    This endpoint is publicly accessible and does not require authentication.
    It fetches revoked certificates from the Certificate Transparency service
    and generates a signed CRL via the Signing service.
    
    Returns:
        Response: DER-encoded CRL with appropriate headers
    """
    trace(current_app, 'routes.crl.get_crl')
    start_time = time.time()
    
    try:
        current_app.logger.info("CRL request received")
        
        # Step 1: Get revoked certificates from Certificate Transparency service
        ct_client = get_certtransparency_client()
        revoked_certificates = ct_client.get_revoked_certificates()
        
        current_app.logger.info(f"Retrieved {len(revoked_certificates)} revoked certificates from CT service")
        
        # Step 2: Generate CRL via Signing service
        signing_client = get_signing_crl_client()
        crl_data = signing_client.generate_crl(revoked_certificates, next_update_hours=24)
        
        # Calculate processing time
        processing_time = (time.time() - start_time) * 1000  # Convert to milliseconds
        current_app.logger.info(f"CRL generated successfully in {processing_time:.2f}ms, size: {len(crl_data)} bytes")
        
        # Step 3: Return CRL with appropriate headers
        response = Response(
            crl_data,
            mimetype='application/pkix-crl',
            headers={
                'Content-Disposition': 'attachment; filename="certificate-revocation-list.crl"',
                'Cache-Control': 'public, max-age=3600',  # Cache for 1 hour
                'Access-Control-Allow-Origin': '*',  # Allow cross-origin access
                'X-CRL-Entries': str(len(revoked_certificates)),
                'X-Generation-Time-MS': f"{processing_time:.2f}"
            }
        )
        
        return response
        
    except CertTransparencyClientError as e:
        current_app.logger.error(f"Certificate Transparency service error: {e}")
        return {
            'error': 'Certificate Transparency service unavailable',
            'message': 'Unable to retrieve revocation data'
        }, 503
        
    except SigningCRLClientError as e:
        current_app.logger.error(f"Signing service error: {e}")
        return {
            'error': 'Signing service unavailable', 
            'message': 'Unable to generate CRL'
        }, 503
        
    except Exception as e:
        processing_time = (time.time() - start_time) * 1000
        current_app.logger.error(f"Unexpected error generating CRL after {processing_time:.2f}ms: {e}")
        return {
            'error': 'Internal server error',
            'message': 'Unable to generate CRL'
        }, 500


@bp.route('/crl', methods=['OPTIONS'])
def crl_options():
    """
    Handle CORS preflight requests for the CRL endpoint.
    """
    trace(current_app, 'routes.crl.crl_options')
    response = Response()
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Methods'] = 'GET, HEAD, OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type'
    response.headers['Access-Control-Max-Age'] = '3600'
    return response