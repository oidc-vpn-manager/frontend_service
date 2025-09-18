"""
Service Administrator and Auditor API endpoints for certificate management and bulk operations.

These endpoints provide programmatic access to certificate transparency logs,
bulk revocation operations, and PSK management for service accounts and auditors.
"""

from flask import Blueprint, jsonify, current_app, request
from app.utils.tracing import trace
from app.utils.decorators import (
    service_admin_required,
    service_admin_or_auditor_required,
    admin_service_only_api
)
from app.utils.certtransparency_client import get_certtransparency_client, CertTransparencyClientError
from app.utils.security_logging import security_logger
from app.models.presharedkey import PreSharedKey
from app.extensions import db, csrf
import uuid
from datetime import datetime, timezone

bp = Blueprint('service_admin', __name__, url_prefix='/service-admin')
csrf.exempt(bp)


@bp.route('/certificates', methods=['GET'])
@admin_service_only_api
@service_admin_or_auditor_required
def list_all_certificates():
    """
    List all certificates (active and revoked) for service admin/auditor access.

    Query Parameters:
    - active_only: Return only active certificates (default: false)
    - revoked_only: Return only revoked certificates (default: false)
    - page: Page number (default: 1)
    - limit: Results per page (default: 100, max: 1000)
    - type: Filter by certificate type (user, server, computer)
    - subject: Filter by subject common name
    - from_date: Filter certificates from date (ISO format)
    - to_date: Filter certificates until date (ISO format)
    """
    trace(current_app, 'routes.api.service_admin.list_all_certificates')

    try:
        ct_client = get_certtransparency_client()

        # Extract query parameters with validation
        params = {
            'page': max(1, request.args.get('page', 1, type=int)),  # Ensure page >= 1
            'limit': min(max(1, request.args.get('limit', 100, type=int)), 1000),  # Cap between 1-1000
            'include_revoked': 'true'
        }

        if request.args.get('active_only') == 'true':
            params['active_only'] = 'true'
            params['include_revoked'] = 'false'
        elif request.args.get('revoked_only') == 'true':
            params['revoked_only'] = 'true'

        # Optional filters
        for param in ['type', 'subject', 'from_date', 'to_date']:
            if request.args.get(param):
                params[param] = request.args.get(param)

        result = ct_client.list_certificates(**params)

        # Log certificate access
        from flask import session
        user = session.get('user', {})
        security_logger.log_data_access(
            data_type="certificate_list",
            access_type="query",
            user_id=user.get('sub', ''),
            additional_details={
                'query_params': dict(request.args),
                'result_count': len(result.get('certificates', []))
            }
        )

        return jsonify(result)

    except CertTransparencyClientError as e:
        current_app.logger.error(f"Failed to list certificates: {e}")
        return jsonify(error="Failed to retrieve certificates", details=str(e)), 503


@bp.route('/certificates/user/<email>', methods=['GET'])
@admin_service_only_api
@service_admin_or_auditor_required
def list_user_certificates(email):
    """
    List all certificates for a specific user email address.

    Query Parameters:
    - active_only: Return only active certificates (default: false)
    - revoked_only: Return only revoked certificates (default: false)
    """
    trace(current_app, 'routes.api.service_admin.list_user_certificates')

    try:
        ct_client = get_certtransparency_client()

        # Determine filter type
        active_only = request.args.get('active_only') == 'true'
        revoked_only = request.args.get('revoked_only') == 'true'

        result = ct_client.list_user_certificates(
            user_email=email,
            include_revoked=(not active_only),
            active_only=active_only,
            revoked_only=revoked_only
        )

        # Log user certificate access
        from flask import session
        user = session.get('user', {})
        security_logger.log_data_access(
            data_type="user_certificates",
            access_type="query",
            user_id=user.get('sub', ''),
            additional_details={
                'target_user_email': email,
                'active_only': active_only,
                'revoked_only': revoked_only,
                'result_count': len(result.get('certificates', []))
            }
        )

        return jsonify(result)

    except CertTransparencyClientError as e:
        current_app.logger.error(f"Failed to list user certificates: {e}")
        return jsonify(error="Failed to retrieve user certificates", details=str(e)), 503


@bp.route('/certificates/computer', methods=['GET'])
@admin_service_only_api
@service_admin_or_auditor_required
def list_computer_certificates():
    """
    List all computer certificates.

    Query Parameters:
    - active_only: Return only active certificates (default: false)
    - revoked_only: Return only revoked certificates (default: false)
    - psk_filter: Filter by PSK description or fragment
    """
    trace(current_app, 'routes.api.service_admin.list_computer_certificates')

    try:
        ct_client = get_certtransparency_client()

        # Determine filter type
        active_only = request.args.get('active_only') == 'true'
        revoked_only = request.args.get('revoked_only') == 'true'
        psk_filter = request.args.get('psk_filter')

        result = ct_client.list_computer_certificates(
            psk_filter=psk_filter,
            include_revoked=(not active_only),
            active_only=active_only,
            revoked_only=revoked_only
        )

        # Log computer certificate access
        from flask import session
        user = session.get('user', {})
        security_logger.log_data_access(
            data_type="computer_certificates",
            access_type="query",
            user_id=user.get('sub', ''),
            additional_details={
                'psk_filter': psk_filter,
                'active_only': active_only,
                'revoked_only': revoked_only,
                'result_count': len(result.get('certificates', []))
            }
        )

        return jsonify(result)

    except CertTransparencyClientError as e:
        current_app.logger.error(f"Failed to list computer certificates: {e}")
        return jsonify(error="Failed to retrieve computer certificates", details=str(e)), 503


@bp.route('/certificates/user/<email>/revoke', methods=['POST'])
@admin_service_only_api
@service_admin_required
def bulk_revoke_user_certificates(email):
    """
    Bulk revoke all active certificates for a specific user email address.

    Request Body:
    {
        "reason": "Reason for revocation (e.g., 'key_compromise', 'cessation_of_operation')"
    }
    """
    trace(current_app, 'routes.api.service_admin.bulk_revoke_user_certificates')

    try:
        # Validate request data
        data = request.get_json()
        if not data or not data.get('reason'):
            return jsonify(error="Missing required field: reason"), 400

        reason = data['reason']
        from flask import session
        user = session.get('user', {})
        revoked_by = user.get('sub', '')

        ct_client = get_certtransparency_client()
        result = ct_client.bulk_revoke_user_certificates(
            user_id=email,
            reason=reason,
            revoked_by=revoked_by
        )

        # Log bulk revocation
        security_logger.log_certificate_bulk_revoked(
            revocation_type="user_email",
            target_identifier=email,
            reason=reason,
            user_id=revoked_by,
            certificates_affected=result.get('revoked_count', 0)
        )

        return jsonify(result)

    except CertTransparencyClientError as e:
        current_app.logger.error(f"Failed to bulk revoke user certificates: {e}")
        return jsonify(error="Failed to bulk revoke certificates", details=str(e)), 503
    except Exception as e:
        current_app.logger.error(f"Bulk revocation error: {e}")
        return jsonify(error="Internal error occurred"), 500


@bp.route('/certificates/computer/bulk-revoke', methods=['POST'])
@admin_service_only_api
@service_admin_required
def bulk_revoke_computer_certificates():
    """
    Bulk revoke computer certificates by PSK criteria.

    Request Body:
    {
        "psk_filter": "PSK description or fragment to match certificates",
        "reason": "Reason for revocation"
    }
    """
    trace(current_app, 'routes.api.service_admin.bulk_revoke_computer_certificates')

    try:
        # Validate request data
        data = request.get_json()
        if not data or not data.get('reason') or not data.get('psk_filter'):
            return jsonify(error="Missing required fields: psk_filter, reason"), 400

        psk_filter = data['psk_filter']
        reason = data['reason']
        from flask import session
        user = session.get('user', {})
        revoked_by = user.get('sub', '')

        ct_client = get_certtransparency_client()
        result = ct_client.bulk_revoke_computer_certificates(
            psk_filter=psk_filter,
            reason=reason,
            revoked_by=revoked_by
        )

        # Log bulk revocation
        security_logger.log_certificate_bulk_revoked(
            revocation_type="computer_psk",
            target_identifier=psk_filter,
            reason=reason,
            user_id=revoked_by,
            certificates_affected=result.get('revoked_count', 0)
        )

        return jsonify(result)

    except CertTransparencyClientError as e:
        current_app.logger.error(f"Failed to bulk revoke computer certificates: {e}")
        return jsonify(error="Failed to bulk revoke computer certificates", details=str(e)), 503
    except Exception as e:
        current_app.logger.error(f"Bulk computer certificate revocation error: {e}")
        return jsonify(error="Internal error occurred"), 500


@bp.route('/certificates/bulk-revoke-by-ca', methods=['POST'])
@admin_service_only_api
@service_admin_required
def bulk_revoke_by_ca():
    """
    Bulk revoke all active certificates issued by a specific CA.

    Request Body:
    {
        "ca_issuer": "Issuer common name or identifier",
        "reason": "Reason for revocation"
    }
    """
    trace(current_app, 'routes.api.service_admin.bulk_revoke_by_ca')

    try:
        # Validate request data
        data = request.get_json()
        if not data or not data.get('reason') or not data.get('ca_issuer'):
            return jsonify(error="Missing required fields: ca_issuer, reason"), 400

        ca_issuer = data['ca_issuer']
        reason = data['reason']
        from flask import session
        user = session.get('user', {})
        revoked_by = user.get('sub', '')

        ct_client = get_certtransparency_client()
        result = ct_client.bulk_revoke_by_ca(
            ca_issuer=ca_issuer,
            reason=reason,
            revoked_by=revoked_by
        )

        # Log bulk revocation
        security_logger.log_certificate_bulk_revoked(
            revocation_type="ca_issuer",
            target_identifier=ca_issuer,
            reason=reason,
            user_id=revoked_by,
            certificates_affected=result.get('revoked_count', 0)
        )

        return jsonify(result)

    except CertTransparencyClientError as e:
        current_app.logger.error(f"Failed to bulk revoke by CA: {e}")
        return jsonify(error="Failed to bulk revoke certificates by CA", details=str(e)), 503
    except Exception as e:
        current_app.logger.error(f"Bulk CA revocation error: {e}")
        return jsonify(error="Internal error occurred"), 500


@bp.route('/psks/computer', methods=['POST'])
@admin_service_only_api
@service_admin_required
def create_computer_psk():
    """
    Create a new computer PSK for service administrator or system administrator.

    Request Body:
    {
        "description": "Description of the PSK",
        "template_set": "Template set name (optional, defaults to 'Default')",
        "expires_at": "Expiration date in ISO format (optional)"
    }
    """
    trace(current_app, 'routes.api.service_admin.create_computer_psk')

    try:
        # Validate request data
        data = request.get_json()
        if not data or not data.get('description'):
            return jsonify(error="Missing required field: description"), 400

        # Generate new PSK
        psk_key = str(uuid.uuid4())

        # Parse optional expiration date
        expires_at = None
        if data.get('expires_at'):
            try:
                expires_at = datetime.fromisoformat(data['expires_at'].replace('Z', '+00:00'))
            except ValueError:
                return jsonify(error="Invalid expires_at format. Use ISO 8601 format."), 400

        # Create computer PSK
        psk = PreSharedKey(
            key=psk_key,
            description=data['description'],
            template_set=data.get('template_set', 'Default'),
            psk_type='computer',
            expires_at=expires_at
        )

        db.session.add(psk)
        db.session.commit()

        # Log PSK creation
        from flask import session
        user = session.get('user', {})
        security_logger.log_psk_created(
            psk_type='computer',
            description=data['description'],
            template_set=psk.template_set,
            created_by=user.get('sub', ''),
            expires_at=expires_at.isoformat() if expires_at else None
        )

        return jsonify({
            'id': psk.id,
            'key': psk_key,  # Only returned during creation
            'key_truncated': psk.key_truncated,
            'description': psk.description,
            'template_set': psk.template_set,
            'psk_type': psk.psk_type,
            'expires_at': psk.expires_at.replace(tzinfo=timezone.utc).isoformat() if psk.expires_at else None,
            'created_at': psk.created_at.replace(tzinfo=timezone.utc).isoformat(),
            'is_enabled': psk.is_enabled
        }), 201

    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Failed to create computer PSK: {e}")
        return jsonify(error="Failed to create computer PSK", details=str(e)), 500


@bp.route('/health', methods=['GET'])
@admin_service_only_api
def health_check():
    """
    Health check endpoint for service admin API.
    """
    trace(current_app, 'routes.api.service_admin.health_check')

    try:
        # Test database connectivity
        db.session.execute('SELECT 1')

        # Test CT service connectivity
        ct_client = get_certtransparency_client()
        ct_stats = ct_client.get_statistics()

        return jsonify({
            'status': 'healthy',
            'database': 'connected',
            'cert_transparency_service': 'connected',
            'timestamp': datetime.now(timezone.utc).isoformat()
        })

    except Exception as e:
        current_app.logger.error(f"Health check failed: {e}")
        return jsonify({
            'status': 'unhealthy',
            'error': str(e),
            'timestamp': datetime.now(timezone.utc).isoformat()
        }), 503