from flask import Blueprint, session, current_app, redirect, url_for, request, Response, flash
from app.utils.tracing import trace
from app.utils import render_template
from app.utils.decorators import login_required, user_service_only
from app.forms import GenerateProfileForm
from app.utils.ca_core import generate_key_and_csr
from app.utils.signing_client import request_signed_certificate, SigningServiceError
from app.utils.render_config_template import find_best_template_match, render_config_template
from app.utils.openvpn_helpers import process_tls_crypt_key
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID
import json
from app.extensions import db
from app.models import DownloadToken

bp = Blueprint('root', __name__)

@bp.route('/', methods=['GET', 'POST'])
@login_required
def index():
    """
    Default authenticated page with VPN configuration generation.
    Handles displaying the config form (GET) and generating the config (POST).
    """
    trace(current_app, 'routes.root.index')
    form = GenerateProfileForm()
    ovpn_options_config = current_app.config.get('OVPN_OPTIONS', {})
    
    # This block will only run on a successful POST request
    if form.validate_on_submit():
        try:
            # 1. Generate a key and CSR for the logged-in user
            user_info = session['user']
            user_email = user_info.get('email', user_info['sub'])
            private_key, csr = generate_key_and_csr(common_name=user_email)

            # 2. Get the CSR signed by the signing service
            final_common_name = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
            csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode('utf-8')
            user_id = user_info['sub']  # Get the user ID for tracking
            
            # Get client IP for geolocation tracking
            client_ip = request.remote_addr
            if request.headers.get('X-Forwarded-For'):
                # Take the first IP from the X-Forwarded-For chain (original client)
                forwarded_ips = request.headers.get('X-Forwarded-For').split(',')
                if forwarded_ips:
                    client_ip = forwarded_ips[0].strip()
            
            # Track certificate request with user agent and OS detection first
            from app.models.certificate_request import CertificateRequest
            cert_request = CertificateRequest.create_from_request(
                flask_request=request,
                common_name=final_common_name,
                certificate_type='user',
                user_info=user_info,
                request_source='web'
            )

            # Create metadata dictionary from certificate request for CT logging
            # Map to CT service field names
            request_metadata = {
                'requester_user_agent': cert_request.raw_user_agent,
                'requester_os': cert_request.detected_os,
                'request_source': cert_request.client_ip,  # Use actual client IP for GeoIP lookup
                # Store additional metadata in extra fields for rich display
                'user_email': cert_request.user_email,
                'os_version': cert_request.os_version,
                'browser': cert_request.browser,
                'browser_version': cert_request.browser_version,
                'is_mobile': cert_request.is_mobile,
                'request_timestamp': cert_request.request_timestamp.isoformat() if cert_request.request_timestamp else None,
                'request_type': cert_request.request_source  # Keep the original request source as additional metadata
            }

            signed_cert_pem = request_signed_certificate(csr_pem, user_id=user_id, client_ip=client_ip, request_metadata=request_metadata)
            cert_request.signing_successful = True
            db.session.add(cert_request)
            
            # 3. Process the master TLS-Crypt key
            master_tls_key = current_app.config.get('OPENVPN_TLS_CRYPT_KEY')
            tls_crypt_version, client_tls_crypt_key = process_tls_crypt_key(master_tls_key)

            # 4. Determine the best base template based on the user's OIDC groups
            user_groups_raw = session['user'].get('groups', '')
            # Convert comma-separated string to list
            if isinstance(user_groups_raw, str) and user_groups_raw:
                user_groups = [group.strip() for group in user_groups_raw.split(',')]
            else:
                user_groups = user_groups_raw if isinstance(user_groups_raw, list) else []
            
            current_app.logger.info(f"User groups parsed: {user_groups}")
            template_collection = current_app.config.get('TEMPLATE_COLLECTION', [])
            template_name, template_content = find_best_template_match(
                current_app, user_groups, template_collection
            )
            
            # Update certificate request with template information
            cert_request.template_name = template_name

            root_ca_cert = current_app.config.get('ROOT_CA_CERTIFICATE', '')
            current_app.logger.info(f'Config root cert: {root_ca_cert}')
            intermediate_ca_cert = current_app.config.get('INTERMEDIATE_CA_CERTIFICATE', '')
            current_app.logger.info(f'Config intermediate cert: {intermediate_ca_cert}')
            ca_chain = f"{intermediate_ca_cert}\n{root_ca_cert}".strip()

            # 5. Build the final context for the Jinja2 template
            context = {
                'template_name': template_name,
                'common_name': final_common_name,
                'userinfo': session['user'],
                'ca_cert_pem': ca_chain,
                'device_cert_pem': signed_cert_pem.strip(),
                'device_key_pem': private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ).decode('utf-8').strip(),
                'tlscrypt_key': client_tls_crypt_key,
                'tls_crypt_key': client_tls_crypt_key,  # Alias for template compatibility
                'tlscrypt_version': tls_crypt_version,
                # Default values for template compatibility
                'protocol': 'udp',
                'port': 1194,
                'use_tcp': False,
                'custom_port': None,
                'enable_compression': False,
                'mobile_settings': False,
            }

            # 6. Apply settings from user-selected options
            selected_options = request.form.getlist('options')
            for option_key in selected_options:
                if option_key in ovpn_options_config:
                    context.update(ovpn_options_config[option_key].get('settings', {}))
            
            # 7. Render the final OpenVPN configuration
            final_config = render_config_template(current_app, template_content, **context)

            audit_record = DownloadToken(
                user=user_info['sub'],
                cn=final_common_name,
                optionset_used=json.dumps(selected_options),
                detected_os=request.user_agent.platform,
                requester_ip=request.remote_addr
            )
            db.session.add(audit_record)
            db.session.commit()

            # 8. Return the file as a download
            download_filename = f"{user_email.split('@')[0]}.ovpn"
            return Response(
                final_config,
                mimetype="application/x-openvpn-profile",
                headers={"Content-disposition": f"attachment; filename={download_filename}"}
            )

        except (SigningServiceError, ValueError) as e: # pragma: no cover
            ## PRAGMA-NO-COVER Exception; JS 2025-09-14 Database Exception requires SQL bug to test.
            # Mark certificate request as failed if it was created
            if 'cert_request' in locals():
                cert_request.signing_successful = False
                cert_request.signing_error_message = str(e)
                db.session.add(cert_request)
                try:
                    db.session.commit()
                except Exception:
                    db.session.rollback()
            
            # Gracefully handle errors from downstream services or bad data
            flash(f'Error generating configuration: {str(e)}', 'error')
            return render_template('index.html', form=form, ovpn_options=ovpn_options_config), 500
    
    # This line will be executed for GET requests and failed POST requests.
    return render_template('index.html', form=form, ovpn_options=ovpn_options_config)


@bp.route('/bounce-to-admin')
@login_required
def bounce_to_admin():
    """
    Bounce page that redirects admin users to the admin service.
    Only used when service separation is configured via ADMIN_URL_BASE.
    """
    trace(current_app, 'routes.root.bounce_to_admin')
    
    admin_url_base = current_app.config.get('ADMIN_URL_BASE')
    if not admin_url_base:
        # Service separation not configured, redirect to home
        return redirect(url_for('root.index'))
    
    target_url = request.args.get('target_url')
    if not target_url:
        # No target specified, redirect to admin home
        target_url = admin_url_base.rstrip('/')
    
    # Validate that target_url starts with admin_url_base for security
    if not target_url.startswith(admin_url_base.rstrip('/')):
        current_app.logger.warning(f"Invalid admin redirect target: {target_url}")
        target_url = admin_url_base.rstrip('/')
    
    return render_template('bounce_to_admin.html', 
                         admin_url=target_url,
                         site_name=current_app.config.get('SITE_NAME', 'VPN Service'))


@bp.route('/bounce-to-user')
@login_required
def bounce_to_user():
    """
    Bounce page that redirects regular users to the user service.
    Only used when service separation is configured via USER_URL_BASE.
    """
    trace(current_app, 'routes.root.bounce_to_user')
    
    user_url_base = current_app.config.get('USER_URL_BASE')
    if not user_url_base:
        # Service separation not configured, redirect to home
        return redirect(url_for('root.index'))
    
    target_url = request.args.get('target_url')
    if not target_url:
        # No target specified, redirect to user home
        target_url = user_url_base.rstrip('/')
    
    # Validate that target_url starts with user_url_base for security
    if not target_url.startswith(user_url_base.rstrip('/')):
        current_app.logger.warning(f"Invalid user redirect target: {target_url}")
        target_url = user_url_base.rstrip('/')
    
    return render_template('bounce_to_user.html', 
                         user_url=target_url,
                         site_name=current_app.config.get('SITE_NAME', 'VPN Service'))