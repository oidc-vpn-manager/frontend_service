"""
Routes for authenticated users to manage their profiles and configurations.
"""

from flask import Blueprint, session, redirect, url_for, current_app, request, Response, flash, jsonify
from app.utils.tracing import trace
from app.utils.security_logging import security_logger
from app.forms import GenerateProfileForm
from app.utils import render_template
from app.utils.ca_core import generate_key_and_csr
from app.utils.signing_client import request_signed_certificate, request_certificate_revocation, SigningServiceError
from app.utils.render_config_template import find_best_template_match, render_config_template
from app.utils.openvpn_helpers import process_tls_crypt_key
from app.utils.decorators import login_required, user_service_only
from app.utils.certtransparency_client import get_certtransparency_client, CertTransparencyClientError
from app.utils.validation import validate_certificate_fingerprint_or_404, validate_certificate_fingerprint_or_400
from cryptography.hazmat.primitives import serialization
import json
from app.extensions import db
from app.models import DownloadToken
from cryptography.x509.oid import NameOID
from flask import jsonify

bp = Blueprint('profile', __name__, url_prefix='/profile')

@bp.route('/certificates')
@user_service_only
@login_required
def list_user_certificates():
    """
    Display certificates issued to the current user.
    """
    trace(current_app, 'routes.profile.list_user_certificates')
    try:
        user_info = session['user']
        user_id = user_info['sub']
        
        # Get user's certificates from Certificate Transparency service
        client = get_certtransparency_client()
        
        # Filter certificates by user ID (this would need to be implemented in the CT client)
        # For now, we'll get all certificates and filter client-side
        response = client.list_certificates(limit=100, include_revoked=True)
        all_certificates = response.get('certificates', [])
        
        # Debug: Print user filtering information
        current_app.logger.debug(f"Filtering certificates for user_id: {user_id}")
        current_app.logger.debug(f"Found {len(all_certificates)} total certificates")
        for cert in all_certificates:
            current_app.logger.debug(f"Certificate fingerprint {cert.get('fingerprint_sha256', '')[:8]}... has issuing_user_id: {cert.get('issuing_user_id')}")
        
        # Filter to only user's certificates
        user_certificates = [
            cert for cert in all_certificates 
            if cert.get('issuing_user_id') == user_id
        ]
        
        current_app.logger.debug(f"After filtering: {len(user_certificates)} user certificates found")
        
        return render_template('profile/certificates.html', certificates=user_certificates)
        
    except CertTransparencyClientError as e:
        current_app.logger.error(f"Failed to fetch user certificates: {e}")
        return render_template('profile/certificates.html', certificates=[], error=str(e))


@bp.route('/certificates/<fingerprint>')
@user_service_only
@login_required
def certificate_detail(fingerprint):
    """
    Display detailed information about a specific certificate for the current user.

    Shows basic certificate information that a user needs:
    - Issue date and expiration date
    - Current status (active/revoked)  
    - Serial number
    - Subject common name
    """
    trace(current_app, 'routes.profile.certificate_detail', {'fingerprint': fingerprint})

    # Validate fingerprint format
    validate_certificate_fingerprint_or_404(fingerprint, current_app.logger)

    try:
        user = session.get('user', {})
        user_id = user.get('sub')

        # Get certificate details from Certificate Transparency service
        client = get_certtransparency_client()
        try:
            certificate = client.get_certificate_by_fingerprint(fingerprint)
            if 'certificate' in certificate:
                certificate = certificate.get('certificate', {})
        except Exception as e:
            current_app.logger.error(f"Failed to fetch certificate {fingerprint}: {e}")
            flash('Certificate not found', 'error')
            return redirect(url_for('profile.list_user_certificates'))
        
        # Verify this certificate belongs to the current user
        if certificate.get('issuing_user_id') != user_id:
            flash('Access denied: This certificate does not belong to you', 'error')
            return redirect(url_for('profile.list_user_certificates'))
        
        return render_template('profile/certificate_detail.html', certificate=certificate)
        
    except CertTransparencyClientError as e: # pragma: no cover
        ## PRAGMA-NO-COVER Exception; JS 2025-09-14 Upstream service needs to return an error to test.
        current_app.logger.error(f"Certificate Transparency service error: {e}")
        flash('Certificate service unavailable', 'error')
        return redirect(url_for('profile.list_user_certificates'))
    
    except Exception as e: # pragma: no cover
        ## PRAGMA-NO-COVER Exception; JS 2025-09-14 Upstream service needs to return an error to test.
        current_app.logger.error(f"Unexpected error viewing certificate: {e}")
        flash('Internal server error', 'error')
        return redirect(url_for('profile.list_user_certificates'))

@bp.route('/certificates/<fingerprint>/revoke', methods=['POST'])
@user_service_only
@login_required
def revoke_user_certificate(fingerprint):
    """
    Revoke a certificate owned by the current user.
    """
    trace(current_app, 'routes.profile.revoke_user_certificate', {'fingerprint': fingerprint})

    # Validate fingerprint format
    validate_certificate_fingerprint_or_400(fingerprint, current_app.logger)

    try:
        user_info = session['user']
        user_id = user_info['sub']
        
        # Get data from form submission
        reason = request.form.get('reason')
        
        if not reason:
            return jsonify({'error': 'Revocation reason is required'}), 400
        
        # Validate revocation reason
        valid_reasons = [
            'key_compromise', 'ca_compromise', 'affiliation_changed',
            'superseded', 'cessation_of_operation', 'certificate_hold',
            'remove_from_crl', 'privilege_withdrawn', 'aa_compromise'
        ]
        
        if reason not in valid_reasons:
            return jsonify({'error': f'Invalid revocation reason. Must be one of: {", ".join(valid_reasons)}'}), 400
        
        # Get certificate details from Certificate Transparency service
        client = get_certtransparency_client()
        
        try:
            response = client.get_certificate_by_fingerprint(fingerprint)
            certificate = response.get('certificate')
            
            if not certificate:
                return jsonify({'error': 'Certificate not found'}), 404
        
        except CertTransparencyClientError as e:
            if 'not found' in str(e).lower():
                return jsonify({'error': 'Certificate not found'}), 404
            else:
                raise
        
        # Check if user owns this certificate
        if certificate.get('issuing_user_id') != user_id:
            current_app.logger.warning(f"User {user_id} attempted to revoke certificate {fingerprint} owned by {certificate.get('issuing_user_id')}")
            # Log unauthorized certificate revocation attempt
            security_logger.log_access_denied(
                resource=f"certificate:{fingerprint}",
                required_permission="certificate_revoke",
                user_id=user_id,
                reason="User does not own this certificate"
            )
            return jsonify({'error': 'You are not authorized to revoke this certificate'}), 403
        
        # Check if certificate is already revoked
        if certificate.get('revoked_at') or certificate.get('revocation'):
            return jsonify({'error': 'Certificate is already revoked'}), 400
        
        # Perform revocation via Signing Service
        current_app.logger.info(f"User {user_id} requesting certificate {fingerprint} revocation with reason: {reason}")
        
        revocation_result = request_certificate_revocation(
            fingerprint=fingerprint,
            reason=reason,
            revoked_by=user_id
        )
        
        current_app.logger.info(f"Certificate {fingerprint} revoked successfully by user {user_id}")

        # Log successful certificate revocation
        security_logger.log_certificate_revoked(
            fingerprint=fingerprint,
            revocation_reason=reason,
            user_id=user_id,
            bulk_operation=False
        )

        flash('Certificate revoked successfully', 'success')
        return redirect(url_for('profile.list_user_certificates'))
        
    except SigningServiceError as e: # pragma: no cover
        ## PRAGMA-NO-COVER Exception; JS 2025-09-14 Upstream service needs to return an error to test.
        current_app.logger.error(f"Signing service error during revocation: {e}")
        if "not found" in str(e).lower():
            return jsonify({'error': 'Certificate not found'}), 404
        elif "unavailable" in str(e).lower():
            return jsonify({'error': 'Certificate revocation service temporarily unavailable'}), 503
        else:
            return jsonify({'error': str(e)}), 400
    
    except Exception as e: # pragma: no cover
        ## PRAGMA-NO-COVER Exception; JS 2025-09-14 Upstream service needs to return an error to test.
        current_app.logger.error(f"Unexpected error during certificate revocation: {e}")
        return jsonify({'error': 'Internal server error'}), 500
