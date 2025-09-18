"""
Admin routes for managing PSKs and other settings.
"""

from flask import Blueprint, flash, redirect, url_for, abort, request, current_app, jsonify, session
from app.utils.tracing import trace
from app.utils.decorators import admin_required, admin_service_only
from app.utils import render_template
from app.utils.certtransparency_client import get_certtransparency_client, CertTransparencyClientError
from app.utils.validation import validate_certificate_fingerprint_or_404, validate_certificate_fingerprint_or_400
from app.utils.signing_client import request_certificate_revocation, request_bulk_certificate_revocation, SigningServiceError
from app.models.presharedkey import PreSharedKey
from app.extensions import db
from app.forms import NewPskForm

bp = Blueprint('admin', __name__, url_prefix='/admin')

@bp.route('/psk')
@admin_service_only
@admin_required
def list_psks():
    """
    Displays a list of all Pre-Shared Keys in the database.
    """
    trace(current_app, 'routes.admin.list_psks')
    keys = PreSharedKey.query.order_by(PreSharedKey.description).all()
    return render_template('admin/psk_list.html', keys=keys)

@bp.route('/psk/new', methods=['GET', 'POST'])
@admin_service_only
@admin_required
def new_psk():
    """Handles creation of a new Pre-Shared Key."""
    trace(current_app, 'routes.admin.new_psk')
    from app.utils.server_templates import get_template_set_choices
    
    form = NewPskForm()
    
    # Populate template set choices
    template_choices = get_template_set_choices()
    if not template_choices:
        flash('No server template sets found. Please configure server templates.', 'error')
        return redirect(url_for('admin.list_psks'))
    
    form.template_set.choices = template_choices
    
    if form.validate_on_submit():
        # Server-side validation: ensure template_set is valid (default to first choice if empty)
        if not form.template_set.data and template_choices:
            # Default to first template set if none selected
            form.template_set.data = template_choices[0][0]
            
        if form.template_set.data:
            valid_template_names = [choice[0] for choice in template_choices]
            if form.template_set.data not in valid_template_names:
                form.template_set.errors.append('Invalid template set selected.')
                return render_template('admin/psk_new.html', form=form)
        
        import uuid
        # Generate the plaintext PSK
        plaintext_psk = str(uuid.uuid4())
        
        # Create the PSK record (this will hash the key automatically)
        new_key = PreSharedKey(
            description=form.description.data,
            template_set=form.template_set.data,
            psk_type=form.psk_type.data,
            key=plaintext_psk
        )
        db.session.add(new_key)
        db.session.commit()
        
        # Return the PSK creation success page with the plaintext PSK to show once
        return render_template('admin/psk_created.html',
                             psk=plaintext_psk,
                             description=new_key.description,
                             template_set=new_key.template_set,
                             psk_type=new_key.psk_type,
                             psk_id=new_key.id,
                             server_url=request.url_root)
    
    return render_template('admin/psk_new.html', form=form)

@bp.route('/psk/<int:key_id>/revoke', methods=['POST'])
@admin_service_only
@admin_required
def revoke_psk(key_id):
    """Handles revocation of a Pre-Shared Key."""
    trace(current_app, 'routes.admin.revoke_psk', {'key_id': key_id})
    key_to_revoke = db.session.get(PreSharedKey, key_id)
    if key_to_revoke is None:
        abort(404)
        
    key_to_revoke.is_enabled = False
    db.session.commit()
    flash(f'Successfully revoked key for {key_to_revoke.description}.', 'success')
    return redirect(url_for('admin.list_psks'))

@bp.route('/certificates')
@admin_service_only
@admin_required
def list_certificates():
    """
    Displays the Certificate Transparency Log with filtering and pagination.
    """
    trace(current_app, 'routes.admin.list_certificates')
    try:
        # Get query parameters with robust validation
        try:
            page = max(1, request.args.get('page', 1, type=int))  # Ensure page >= 1
        except (ValueError, TypeError): # pragma: no cover
            ## PRAGMA-NO-COVER Exception; JS 2025-09-17 Value or Type errors for values being passed in are very hard to generate.
            page = 1  # Default to page 1 if invalid

        try:
            limit = min(max(1, request.args.get('limit', 50, type=int)), 100)  # Cap between 1-100
        except (ValueError, TypeError): # pragma: no cover
            ## PRAGMA-NO-COVER Exception; JS 2025-09-17 Value or Type errors for values being passed in are very hard to generate.
            limit = 50  # Default to 50 if invalid
        
        # Filter parameters (escape user inputs to prevent XSS)
        from markupsafe import escape
        filters = {}
        if request.args.get('type'):
            filters['type'] = escape(request.args.get('type'))
        if request.args.get('subject'):
            filters['subject'] = escape(request.args.get('subject'))
        if request.args.get('issuer'):
            filters['issuer'] = escape(request.args.get('issuer'))
        if request.args.get('from_date'):
            filters['from_date'] = escape(request.args.get('from_date'))
        if request.args.get('to_date'):
            filters['to_date'] = escape(request.args.get('to_date'))
        if request.args.get('include_revoked') == 'false':
            filters['include_revoked'] = 'false'
        if request.args.get('show_uncollapsed') == 'true':
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
        current_app.logger.info(f"Filters sent to CT service: {filters}")
        current_app.logger.info(f"Filters received from CT service: {current_filters}")
        
        # Get statistics for dashboard summary
        try:
            stats = client.get_statistics()
        except CertTransparencyClientError:
            # If stats fail, continue with empty stats
            stats = {}
        
        return render_template('admin/certificates.html', 
                             certificates=certificates,
                             pagination=pagination,
                             filters=current_filters,
                             stats=stats,
                             current_page=page)
                             
    except CertTransparencyClientError as e:
        current_app.logger.error(f"Failed to fetch certificates: {e}")
        flash(f'Unable to fetch certificates: {e}', 'error')
        return render_template('admin/certificates.html', 
                             certificates=[],
                             pagination={},
                             filters={},
                             stats={},
                             current_page=1)

@bp.route('/certificates/<fingerprint>')
@admin_service_only
@admin_required
def certificate_detail(fingerprint):
    """
    Display detailed information for a specific certificate.
    """
    trace(current_app, 'routes.admin.certificate_detail', {'fingerprint': fingerprint})

    # Validate fingerprint format
    validate_certificate_fingerprint_or_404(fingerprint, current_app.logger)

    try:
        client = get_certtransparency_client()
        response = client.get_certificate_by_fingerprint(fingerprint, include_pem=True)
        certificate = response.get('certificate')
        
        if not certificate:
            abort(404)
            
        return render_template('admin/certificate_detail.html', certificate=certificate)
        
    except CertTransparencyClientError as e:
        current_app.logger.error(f"Failed to fetch certificate {fingerprint}: {e}")
        flash(f'Unable to fetch certificate details: {e}', 'error')
        return redirect(url_for('admin.list_certificates'))


@bp.route('/certificates/<fingerprint>/revoke', methods=['POST'])
@admin_service_only
@admin_required
def admin_revoke_certificate(fingerprint):
    """
    Admin revoke any certificate by fingerprint.
    """
    trace(current_app, 'routes.admin.admin_revoke_certificate', {'fingerprint': fingerprint})

    # Validate fingerprint format
    validate_certificate_fingerprint_or_400(fingerprint, current_app.logger)

    try:
        user_info = session['user']
        admin_id = user_info['sub']
        
        # Get data from form submission (like user revocation route)
        reason = request.form.get('reason')
        comment = request.form.get('comment', '')
        
        if not reason:
            flash('Revocation reason is required', 'error')
            return redirect(url_for('admin.certificate_detail', fingerprint=fingerprint))
        
        # Validate revocation reason
        valid_reasons = [
            'key_compromise', 'ca_compromise', 'affiliation_changed',
            'superseded', 'cessation_of_operation', 'certificate_hold',
            'remove_from_crl', 'privilege_withdrawn', 'aa_compromise',
            'admin_revocation', 'admin_bulk_revocation'
        ]
        
        if reason not in valid_reasons:
            flash(f'Invalid revocation reason. Must be one of: {", ".join(valid_reasons)}', 'error')
            return redirect(url_for('admin.certificate_detail', fingerprint=fingerprint))
        
        # Get certificate details from Certificate Transparency service
        client = get_certtransparency_client()
        
        try:
            response = client.get_certificate_by_fingerprint(fingerprint)
            certificate = response.get('certificate')
            
            if not certificate:
                flash('Certificate not found', 'error')
                return redirect(url_for('admin.certificate_detail', fingerprint=fingerprint))
        
        except CertTransparencyClientError as e:
            if 'not found' in str(e).lower():
                flash('Certificate not found', 'error')
                return redirect(url_for('admin.certificate_detail', fingerprint=fingerprint))
            else:
                raise
        
        # Check if certificate is already revoked
        if certificate.get('revoked_at') or certificate.get('revocation'):
            flash('Certificate is already revoked', 'error')
            return redirect(url_for('admin.certificate_detail', fingerprint=fingerprint))
        
        # Perform revocation via Signing Service (admin can revoke any certificate)
        current_app.logger.info(f"Admin {admin_id} requesting certificate {fingerprint} revocation (owner: {certificate.get('issuing_user_id')}) with reason: {reason}")
        if comment:
            current_app.logger.info(f"Admin comment for revocation: {comment}")
        
        revocation_result = request_certificate_revocation(
            fingerprint=fingerprint,
            reason=reason,
            revoked_by=admin_id
        )
        
        current_app.logger.info(f"Certificate {fingerprint} revoked successfully by admin {admin_id}")
        current_app.logger.info(f"Setting flash message: 'Certificate revoked successfully'")
        
        flash('Certificate revoked successfully', 'success')
        redirect_url = url_for('admin.certificate_detail', fingerprint=fingerprint)
        current_app.logger.info(f"Redirecting to: {redirect_url}")
        return redirect(redirect_url)
        
    except SigningServiceError as e:
        current_app.logger.error(f"Signing service error during admin revocation: {e}")
        if "not found" in str(e).lower():
            flash('Certificate not found', 'error')
        elif "unavailable" in str(e).lower():
            flash('Certificate revocation service temporarily unavailable', 'error')
        else:
            flash(f'Signing service error: {str(e)}', 'error')
        return redirect(url_for('admin.certificate_detail', fingerprint=fingerprint))
    except CertTransparencyClientError as e:
        current_app.logger.error(f"Certificate Transparency service error during admin revocation: {e}")
        flash('Certificate Transparency service unavailable', 'error')
        return redirect(url_for('admin.certificate_detail', fingerprint=fingerprint))
    
    except Exception as e:
        current_app.logger.error(f"Unexpected error during admin certificate revocation: {e}")
        flash('Internal server error during revocation', 'error')
        return redirect(url_for('admin.certificate_detail', fingerprint=fingerprint))


@bp.route('/users/<user_id>/revoke-certificates', methods=['POST'])
@admin_service_only
@admin_required
def admin_bulk_revoke_user_certificates(user_id):
    """
    Admin bulk revoke all active certificates for a specific user.
    """
    trace(current_app, 'routes.admin.admin_bulk_revoke_user_certificates', {'user_id': user_id})
    try:
        admin_info = session['user']
        admin_id = admin_info['sub']
        
        # Validate user_id parameter
        if not user_id or user_id.strip() == '':
            flash('User ID is required', 'error')
            return redirect(url_for('admin.list_certificates'))
        
        # Get data from form submission (like user revocation route)
        reason = request.form.get('reason')
        comment = request.form.get('comment', '')
        
        if not reason:
            flash('Revocation reason is required', 'error')
            return redirect(url_for('admin.list_certificates'))
        
        # Validate revocation reason
        valid_reasons = [
            'key_compromise', 'ca_compromise', 'affiliation_changed',
            'superseded', 'cessation_of_operation', 'certificate_hold',
            'remove_from_crl', 'privilege_withdrawn', 'aa_compromise',
            'admin_revocation', 'admin_bulk_revocation'
        ]
        
        if reason not in valid_reasons:
            flash(f'Invalid revocation reason. Must be one of: {", ".join(valid_reasons)}', 'error')
            return redirect(url_for('admin.list_certificates'))
        
        # Perform bulk revocation via Signing Service
        current_app.logger.info(f"Admin {admin_id} requesting bulk certificate revocation for user {user_id} with reason: {reason}")
        if comment:
            current_app.logger.info(f"Admin comment for bulk revocation: {comment}")
        
        bulk_result = request_bulk_certificate_revocation(
            user_id=user_id,
            reason=reason,
            revoked_by=admin_id
        )
        
        revoked_count = bulk_result.get('revoked_count', 0)
        
        current_app.logger.info(f"Bulk revocation completed by admin {admin_id}: {revoked_count} certificates revoked for user {user_id}")
        current_app.logger.info(f"Setting bulk flash message: 'Successfully revoked {revoked_count} certificates for user {user_id}'")
        
        flash(f'Successfully revoked {revoked_count} certificates for user {user_id}', 'success')
        redirect_url = url_for('admin.list_certificates', bulk_revoked=revoked_count, user_id=user_id)
        current_app.logger.info(f"Bulk revocation redirecting to: {redirect_url}")
        return redirect(redirect_url)
        
    except SigningServiceError as e:
        current_app.logger.error(f"Signing service error during bulk revocation: {e}")
        if "unavailable" in str(e).lower():
            flash('Certificate revocation service temporarily unavailable', 'error')
        else:
            flash(f'Signing service error: {str(e)}', 'error')
        return redirect(url_for('admin.list_certificates'))
    except CertTransparencyClientError as e:
        current_app.logger.error(f"Certificate Transparency service error during bulk revocation: {e}")
        flash('Certificate Transparency service unavailable', 'error')
        return redirect(url_for('admin.list_certificates'))
    
    except Exception as e:
        current_app.logger.error(f"Unexpected error during bulk certificate revocation: {e}")
        flash('Internal server error during bulk revocation', 'error')
        return redirect(url_for('admin.list_certificates'))


@bp.route('/bulk-revoke-by-ca', methods=['GET', 'POST'])
@admin_service_only
@admin_required
def bulk_revoke_by_ca():
    """
    Bulk revoke all active certificates issued by a specific CA.
    Service admin users only.
    """
    trace(current_app, 'routes.admin.bulk_revoke_by_ca')

    if request.method == 'GET':
        # Show form for bulk revocation by CA
        return render_template('admin/bulk_revoke_by_ca.html')

    # Handle POST request
    try:
        from flask import session
        admin_user = session.get('user', {})
        admin_id = admin_user.get('sub', 'unknown')

        # Get form data
        ca_issuer = request.form.get('ca_issuer', '').strip()
        reason = request.form.get('reason', '').strip()
        comment = request.form.get('comment', '').strip()

        # Basic validation
        if not ca_issuer:
            flash('CA Issuer is required', 'error')
            return render_template('admin/bulk_revoke_by_ca.html')

        if not reason:
            flash('Revocation reason is required', 'error')
            return render_template('admin/bulk_revoke_by_ca.html')

        # Validate revocation reason
        valid_reasons = [
            'key_compromise', 'ca_compromise', 'affiliation_changed',
            'superseded', 'cessation_of_operation', 'certificate_hold',
            'remove_from_crl', 'privilege_withdrawn', 'aa_compromise',
            'admin_revocation', 'admin_bulk_revocation'
        ]

        if reason not in valid_reasons:
            flash(f'Invalid revocation reason. Must be one of: {", ".join(valid_reasons)}', 'error')
            return render_template('admin/bulk_revoke_by_ca.html')

        # Perform bulk revocation via Certificate Transparency client
        current_app.logger.info(f"Admin {admin_id} requesting bulk certificate revocation by CA '{ca_issuer}' with reason: {reason}")
        if comment:
            current_app.logger.info(f"Admin comment for bulk CA revocation: {comment}")

        ct_client = get_certtransparency_client()
        bulk_result = ct_client.bulk_revoke_by_ca(
            ca_issuer=ca_issuer,
            reason=reason,
            revoked_by=admin_id
        )

        revoked_count = bulk_result.get('revoked_count', 0)

        current_app.logger.info(f"Bulk CA revocation completed by admin {admin_id}: {revoked_count} certificates revoked for CA '{ca_issuer}'")

        # Log the bulk revocation
        from app.utils.security_logging import security_logger
        security_logger.log_certificate_bulk_revoked(
            revocation_type="ca_issuer",
            target_identifier=ca_issuer,
            reason=reason,
            user_id=admin_id,
            certificates_affected=revoked_count
        )

        flash(f'Successfully revoked {revoked_count} certificates issued by CA: {ca_issuer}', 'success')
        return redirect(url_for('admin.list_certificates'))

    except CertTransparencyClientError as e:
        current_app.logger.error(f"Certificate Transparency service error during bulk CA revocation: {e}")
        flash('Certificate Transparency service unavailable', 'error')
        return render_template('admin/bulk_revoke_by_ca.html')

    except Exception as e:
        current_app.logger.error(f"Unexpected error during bulk CA revocation: {e}")
        flash('Internal server error during bulk CA revocation', 'error')
        return render_template('admin/bulk_revoke_by_ca.html')


@bp.route('/computer-certificates/bulk-revoke', methods=['GET', 'POST'])
@admin_service_only
@admin_required
def bulk_revoke_computer_certificates():
    """
    Bulk revoke computer certificates by PSK criteria.
    Service admin/system admin users only.
    """
    trace(current_app, 'routes.admin.bulk_revoke_computer_certificates')

    if request.method == 'GET':
        # Get available PSKs for the form
        computer_psks = PreSharedKey.query.filter_by(psk_type='computer', is_enabled=True).order_by(PreSharedKey.description).all()
        return render_template('admin/bulk_revoke_computer_certificates.html', computer_psks=computer_psks)

    # Handle POST request
    try:
        from flask import session
        admin_user = session.get('user', {})
        admin_id = admin_user.get('sub', 'unknown')

        # Get form data
        psk_filter = request.form.get('psk_filter', '').strip()
        reason = request.form.get('reason', '').strip()
        comment = request.form.get('comment', '').strip()

        # Basic validation
        if not psk_filter:
            flash('PSK filter is required', 'error')
            computer_psks = PreSharedKey.query.filter_by(psk_type='computer', is_enabled=True).order_by(PreSharedKey.description).all()
            return render_template('admin/bulk_revoke_computer_certificates.html', computer_psks=computer_psks)

        if not reason:
            flash('Revocation reason is required', 'error')
            computer_psks = PreSharedKey.query.filter_by(psk_type='computer', is_enabled=True).order_by(PreSharedKey.description).all()
            return render_template('admin/bulk_revoke_computer_certificates.html', computer_psks=computer_psks)

        # Validate revocation reason
        valid_reasons = [
            'key_compromise', 'ca_compromise', 'affiliation_changed',
            'superseded', 'cessation_of_operation', 'certificate_hold',
            'remove_from_crl', 'privilege_withdrawn', 'aa_compromise',
            'admin_revocation', 'admin_bulk_revocation'
        ]

        if reason not in valid_reasons:
            flash(f'Invalid revocation reason. Must be one of: {", ".join(valid_reasons)}', 'error')
            computer_psks = PreSharedKey.query.filter_by(psk_type='computer', is_enabled=True).order_by(PreSharedKey.description).all()
            return render_template('admin/bulk_revoke_computer_certificates.html', computer_psks=computer_psks)

        # Perform bulk revocation via Certificate Transparency client
        current_app.logger.info(f"Admin {admin_id} requesting bulk computer certificate revocation for PSK '{psk_filter}' with reason: {reason}")
        if comment:
            current_app.logger.info(f"Admin comment for bulk computer certificate revocation: {comment}")

        ct_client = get_certtransparency_client()
        bulk_result = ct_client.bulk_revoke_computer_certificates(
            psk_filter=psk_filter,
            reason=reason,
            revoked_by=admin_id
        )

        revoked_count = bulk_result.get('revoked_count', 0)

        current_app.logger.info(f"Bulk computer certificate revocation completed by admin {admin_id}: {revoked_count} certificates revoked for PSK '{psk_filter}'")

        # Log the bulk revocation
        from app.utils.security_logging import security_logger
        security_logger.log_certificate_bulk_revoked(
            revocation_type="computer_psk",
            target_identifier=psk_filter,
            reason=reason,
            user_id=admin_id,
            certificates_affected=revoked_count
        )

        flash(f'Successfully revoked {revoked_count} computer certificates matching PSK filter: {psk_filter}', 'success')
        return redirect(url_for('admin.list_certificates'))

    except CertTransparencyClientError as e:
        current_app.logger.error(f"Certificate Transparency service error during bulk computer certificate revocation: {e}")
        flash('Certificate Transparency service unavailable', 'error')
        computer_psks = PreSharedKey.query.filter_by(psk_type='computer', is_enabled=True).order_by(PreSharedKey.description).all()
        return render_template('admin/bulk_revoke_computer_certificates.html', computer_psks=computer_psks)

    except Exception as e:
        current_app.logger.error(f"Unexpected error during bulk computer certificate revocation: {e}")
        flash('Internal server error during bulk computer certificate revocation', 'error')
        computer_psks = PreSharedKey.query.filter_by(psk_type='computer', is_enabled=True).order_by(PreSharedKey.description).all()
        return render_template('admin/bulk_revoke_computer_certificates.html', computer_psks=computer_psks)


