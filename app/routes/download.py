"""
Download routes for CLI workflow.
Handles token-based OpenVPN profile downloads for get_openvpn_config script.
"""

from flask import Blueprint, request, current_app, Response, jsonify
from app.utils.tracing import trace
from app.models import DownloadToken
from app.utils.decorators import user_service_only
from app.utils.ca_core import generate_key_and_csr
from app.utils.signing_client import request_signed_certificate, SigningServiceError
from app.utils.render_config_template import find_best_template_match, render_config_template
from app.utils.openvpn_helpers import process_tls_crypt_key
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID
from datetime import datetime, timezone
import json

bp = Blueprint('download', __name__)


@bp.route('/download')
@user_service_only
def download_profile():
    """
    Download OpenVPN profile using a token from CLI workflow.
    
    Expected query parameter:
    - token: UUID token generated during OIDC authentication
    
    Returns:
    - OpenVPN profile content (application/x-openvpn-profile)
    - 400 if token missing or invalid
    - 410 if token expired
    - 500 if profile generation fails
    """
    trace(current_app, 'routes.download.download_profile')
    
    # Get token from query parameters
    token = request.args.get('token')
    if not token:
        current_app.logger.warning("Download attempt without token")
        return jsonify({'error': 'Token required'}), 400
    
    # Find and validate token
    download_token = DownloadToken.query.filter_by(token=token).first()
    if not download_token:
        current_app.logger.warning(f"Download attempt with invalid token: {token}")
        return jsonify({'error': 'Invalid token'}), 400
    
    # Check if token is expired (5 minute window)
    if download_token.is_download_window_expired():
        current_app.logger.warning(f"Download attempt with expired token: {token}")
        return jsonify({'error': 'Token expired'}), 410
    
    # Check if already collected
    if download_token.collected:
        current_app.logger.warning(f"Download attempt with already used token: {token}")
        return jsonify({'error': 'Token already used'}), 410
    
    try:
        # Generate OpenVPN profile for the user
        user_id = download_token.user
        user_email = download_token.cn
        optionset_used = download_token.optionset_used
        
        current_app.logger.info(f"Generating profile for CLI user {user_id} with options: {optionset_used}")
        
        # 1. Generate a key and CSR for the user
        private_key, csr = generate_key_and_csr(common_name=user_email)

        # 2. Get the CSR signed by the signing service
        final_common_name = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode('utf-8')
        
        # Get client IP for geolocation tracking
        client_ip = request.remote_addr
        if request.headers.get('X-Forwarded-For'):
            forwarded_ips = request.headers.get('X-Forwarded-For').split(',')
            if forwarded_ips:
                client_ip = forwarded_ips[0].strip()
        
        signed_cert_pem = request_signed_certificate(csr_pem, user_id=user_id, client_ip=client_ip)

        # 3. Process the master TLS-Crypt key
        master_tls_key = current_app.config.get('OPENVPN_TLS_CRYPT_KEY')
        tls_crypt_version, client_tls_crypt_key = process_tls_crypt_key(master_tls_key)

        # 4. Determine template based on stored user info or default
        # Note: For CLI workflow, we don't have full session but can use defaults
        user_groups = []  # CLI users get default template
        template_collection = current_app.config.get('TEMPLATE_COLLECTION', [])
        template_name, template_content = find_best_template_match(
            current_app, user_groups, template_collection
        )

        root_ca_cert = current_app.config.get('ROOT_CA_CERTIFICATE', '')
        intermediate_ca_cert = current_app.config.get('INTERMEDIATE_CA_CERTIFICATE', '')
        ca_chain = f"{intermediate_ca_cert}\n{root_ca_cert}".strip()

        # 5. Build the final context for the Jinja2 template
        context = {
            'template_name': template_name,
            'common_name': final_common_name,
            'userinfo': {'sub': user_id, 'email': user_email, 'name': user_email},
            'ca_cert_pem': ca_chain,
            'device_cert_pem': signed_cert_pem.strip(),
            'device_key_pem': private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ).decode('utf-8').strip(),
            'tlscrypt_key': client_tls_crypt_key,
            'tlscrypt_version': tls_crypt_version,
        }

        # 6. Apply settings from optionset if specified
        if optionset_used:
            ovpn_options_config = current_app.config.get('OVPN_OPTIONS', {})
            selected_options = optionset_used.split(',') if optionset_used else []
            for option_key in selected_options:
                option_key = option_key.strip()
                if option_key in ovpn_options_config:
                    context.update(ovpn_options_config[option_key].get('settings', {}))
        
        # 7. Render the final OpenVPN configuration
        final_config = render_config_template(current_app, template_content, **context)

        # 8. Mark token as collected and update download info
        download_token.collected = True
        download_token.ovpn_content = final_config.encode('utf-8')
        download_token.cert_expiry = None  # Could parse cert expiry from signed_cert_pem if needed
        
        # Update audit record with final details
        download_token.cn = final_common_name
        
        from app.extensions import db
        db.session.commit()

        current_app.logger.info(f"CLI profile generated successfully for {user_id}")

        # 9. Return the file as download
        download_filename = f"{user_email.split('@')[0]}.ovpn"
        return Response(
            final_config,
            mimetype="application/x-openvpn-profile",
            headers={"Content-disposition": f"attachment; filename={download_filename}"}
        )

    except SigningServiceError as e:
        current_app.logger.error(f"Signing service error during CLI download: {e}")
        return jsonify({'error': 'Certificate signing failed'}), 500
    except Exception as e:
        current_app.logger.error(f"Error generating CLI profile: {e}")
        return jsonify({'error': 'Profile generation failed'}), 500