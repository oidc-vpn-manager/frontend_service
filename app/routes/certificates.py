"""
Certificate Transparency log viewing routes for Auditors and Service Administrators.

This module provides read-only access to the full Certificate Transparency log
for users with appropriate privileges (auditors, service administrators, admins).
"""

from flask import Blueprint, request, current_app, session
from app.utils.tracing import trace
from app.utils.decorators import auditor_or_service_admin_required, redirect_admin_to_admin_service
from app.utils import render_template
from app.utils.certtransparency_client import get_certtransparency_client, CertTransparencyClientError

bp = Blueprint('certificates', __name__, url_prefix='/certificates')


@bp.route('/')
@redirect_admin_to_admin_service
@auditor_or_service_admin_required
def transparency_log():
    """
    Displays the full Certificate Transparency Log for auditors and service administrators.
    
    This view provides read-only access to all certificate issuance and revocation events.
    Additional metadata is shown for privileged users.
    """
    trace(current_app, 'routes.certificates.transparency_log')
    try:
        # Get query parameters for pagination and filtering
        page = request.args.get('page', 1, type=int)
        limit = min(request.args.get('limit', 50, type=int), 100)  # Cap at 100 for UI
        
        # Filter parameters (reuse admin logic)
        filters = {}
        if request.args.get('type'):
            filters['type'] = request.args.get('type')
        if request.args.get('subject'):
            filters['subject'] = request.args.get('subject')
        if request.args.get('issuer'):
            filters['issuer'] = request.args.get('issuer')
        if request.args.get('from_date'):
            filters['from_date'] = request.args.get('from_date')
        if request.args.get('to_date'):
            filters['to_date'] = request.args.get('to_date')
        if request.args.get('include_revoked') == 'false':
            filters['include_revoked'] = 'false'
        
        # Auditors can see uncollapsed records (special auditor feature)
        user = session.get('user', {})
        if user.get('is_auditor') and request.args.get('show_uncollapsed') == 'true':
            filters['show_uncollapsed'] = 'true'
        
        # Sort parameters
        if request.args.get('sort'):
            filters['sort'] = request.args.get('sort')
        if request.args.get('order'):
            filters['order'] = request.args.get('order')
        
        # Get certificates from Certificate Transparency service
        client = get_certtransparency_client()
        response = client.list_certificates(page=page, limit=limit, **filters)
        
        certificates = response.get('certificates', [])
        pagination = response.get('pagination', {})
        current_filters = response.get('filters', {})
        
        current_app.logger.info(f"CT log accessed by user {user.get('sub', 'unknown')} - returned {len(certificates)} certificates")
        
        # Get statistics for dashboard summary
        try:
            stats = client.get_statistics()
        except CertTransparencyClientError:
            # If stats fail, continue with empty stats
            stats = {}
        
        # Determine user role for template rendering
        user_role = 'admin' if user.get('is_admin') else ('system_admin' if user.get('is_system_admin') else 'auditor')
        
        return render_template('certificates/transparency_log.html', 
                             certificates=certificates,
                             pagination=pagination,
                             filters=current_filters,
                             stats=stats,
                             current_page=page,
                             user_role=user_role)
                             
    except CertTransparencyClientError as e:
        current_app.logger.error(f"Failed to fetch CT log: {e}")
        return render_template('certificates/transparency_log.html', 
                             certificates=[],
                             pagination={},
                             filters={},
                             stats={},
                             current_page=1,
                             error_message=f'Unable to fetch certificates: {e}')


@bp.route('/<fingerprint>')
@redirect_admin_to_admin_service
@auditor_or_service_admin_required  
def certificate_detail(fingerprint):
    """
    Display detailed information for a specific certificate from the CT log.
    
    Args:
        fingerprint: SHA-256 fingerprint of the certificate
    """
    trace(current_app, 'routes.certificates.certificate_detail')
    try:
        client = get_certtransparency_client()
        response = client.get_certificate_by_fingerprint(fingerprint, include_pem=True)
        certificate = response.get('certificate')
        
        if not certificate:
            current_app.logger.warning(f"Certificate not found: {fingerprint}")
            return render_template('status/404.html'), 404
        
        user = session.get('user', {})
        user_role = 'admin' if user.get('is_admin') else ('system_admin' if user.get('is_system_admin') else 'auditor')
        
        current_app.logger.info(f"Certificate {fingerprint[:8]}... viewed by user {user.get('sub', 'unknown')}")
        
        return render_template('certificates/certificate_detail.html', 
                             certificate=certificate,
                             user_role=user_role)
        
    except CertTransparencyClientError as e:
        current_app.logger.error(f"Failed to fetch certificate {fingerprint}: {e}")
        return render_template('status/500.html', 
                             error_message='Unable to fetch certificate details'), 500