"""
Defines the routes for version 1 of the API.
"""

from flask import Blueprint, jsonify, current_app, Response, request
from app.utils.tracing import trace
from app.utils.decorators import psk_required, admin_service_only_api
from app.utils.ca_core import generate_key_and_csr
from app.utils.signing_client import request_signed_certificate, SigningServiceError
from app.utils.openvpn_helpers import process_tls_crypt_key
from app.utils.render_config_template import find_best_template_match, render_config_template
from cryptography.hazmat.primitives import serialization
from app.extensions import csrf
import tarfile
import io
import os
import tempfile
from datetime import datetime, timezone

bp = Blueprint('v1', __name__, url_prefix='/v1')
csrf.exempt(bp)


def psk_type_required(required_type):
    """
    Decorator to ensure PSK is of the correct type (server or computer).
    """
    def decorator(f):
        def wrapper(psk_object, *args, **kwargs):
            if psk_object.psk_type != required_type:
                current_app.logger.warning(f"PSK type mismatch: expected {required_type}, got {psk_object.psk_type}")
                return jsonify(error=f"This endpoint requires a {required_type} PSK"), 403
            return f(psk_object, *args, **kwargs)
        wrapper.__name__ = f.__name__
        return wrapper
    return decorator


@bp.route('/server/bundle', methods=['GET', 'POST'])
@admin_service_only_api
@psk_required
@psk_type_required('server')
def server_bundle(psk_object):
    """
    Server bundle endpoint. Returns a tar file containing all components
    needed to set up an OpenVPN server: certificates, keys, and configurations.
    """
    trace(current_app, 'routes.api.v1.server_bundle')
    
    # Record PSK usage
    from app.extensions import db
    psk_object.record_usage()
    db.session.commit()
    try:
        # 1. Generate server certificate and key with timestamp for uniqueness
        timestamp = int(datetime.now(timezone.utc).timestamp())
        server_key, server_csr = generate_key_and_csr(
            common_name=f"server-{psk_object.description}-{timestamp}",
        )
        
        # 2. Get the server certificate signed
        csr_pem = server_csr.public_bytes(
            encoding=serialization.Encoding.PEM
        ).decode('utf-8')
        
        # Get client IP for geolocation tracking
        client_ip = request.remote_addr
        if request.headers.get('X-Forwarded-For'):
            forwarded_ips = request.headers.get('X-Forwarded-For').split(',')
            if forwarded_ips and forwarded_ips[0].strip():
                client_ip = forwarded_ips[0].strip()
        
        server_cert_pem = request_signed_certificate(csr_pem, certificate_type='server', client_ip=client_ip)
        
        # Track certificate request with user agent and OS detection
        from app.models.certificate_request import CertificateRequest
        cert_request = CertificateRequest.create_from_request(
            flask_request=request,
            common_name=f"server-{psk_object.description}-{timestamp}",
            certificate_type='server',
            user_info=None,  # No user info for API requests
            template_set=psk_object.template_set,
            request_source='api'
        )
        cert_request.signing_successful = True
        db.session.add(cert_request)
        
        # 3. Serialize the private key
        server_key_pem = server_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')
        
        # 4. Get CA certificates
        root_ca_cert = current_app.config.get('ROOT_CA_CERTIFICATE', '')
        intermediate_ca_cert = current_app.config.get('INTERMEDIATE_CA_CERTIFICATE', '')
        ca_chain = f"{intermediate_ca_cert}\n{root_ca_cert}".strip()
        
        # 5. Get TLS-Crypt key
        master_tls_key = current_app.config.get('OPENVPN_TLS_CRYPT_KEY')
                
        # 6. Get server configuration file matching PSK's template set
        server_configs = []
        server_templates_dir = current_app.config.get('SERVER_TEMPLATES_DIR')
        
        if server_templates_dir and os.path.exists(server_templates_dir):
            current_app.logger.info(f"Looking for server config matching template set '{psk_object.template_set}' in {server_templates_dir}")
            for filename in os.listdir(server_templates_dir):
                # Check if filename starts with the template set name (e.g., "JustTCP.0443.ovpn")
                if filename.endswith('.ovpn') and filename.startswith(psk_object.template_set + '.'):
                    filepath = os.path.join(server_templates_dir, filename)
                    try:
                        with open(filepath, 'r') as f:
                            config_content = f.read()
                            server_configs.append({
                                'filename': filename,
                                'content': config_content
                            })
                            current_app.logger.info(f"Loaded matching server config: {filename}, length: {len(config_content)}")
                    except Exception as e: # pragma: no cover
                        ## PRAGMA-NO-COVER exception; JS 2025-09-14 FS Exceptions require FS bug to test
                        current_app.logger.error(f"Error reading server config file {filename}: {e}")
        
        if not server_configs:
            current_app.logger.warning(f"No server configuration files found matching template set '{psk_object.template_set}'")
        
        # 7. Create tar file in memory
        tar_buffer = io.BytesIO()
        with tarfile.open(fileobj=tar_buffer, mode='w:gz') as tar:
            # Add CA certificate chain
            current_app.logger.debug(f"Adding ca_chain to tar: {type(ca_chain)}, length: {len(ca_chain) if ca_chain else 0}")
            ca_info = tarfile.TarInfo('ca-chain.crt')
            ca_info.size = len(ca_chain.encode('utf-8'))
            tar.addfile(ca_info, io.BytesIO(ca_chain.encode('utf-8')))
            
            # Add server certificate
            current_app.logger.debug(f"Adding server_cert_pem: {server_cert_pem is not None}")
            server_cert_info = tarfile.TarInfo('server.crt')
            server_cert_info.size = len(server_cert_pem.encode('utf-8'))
            tar.addfile(server_cert_info, io.BytesIO(server_cert_pem.encode('utf-8')))
            
            # Add server private key
            current_app.logger.debug(f"Adding server_key_pem: {server_key_pem is not None}")
            server_key_info = tarfile.TarInfo('server.key')
            server_key_info.size = len(server_key_pem.encode('utf-8'))
            tar.addfile(server_key_info, io.BytesIO(server_key_pem.encode('utf-8')))
            
            # Add TLS-Crypt key
            if master_tls_key is not None:
                current_app.logger.debug(f"Adding server_tls_crypt_key: {master_tls_key is not None}, value: '{master_tls_key}'")
                tls_key_info = tarfile.TarInfo('tls-crypt.key')
                tls_key_info.size = len(master_tls_key.encode('utf-8'))
                tar.addfile(tls_key_info, io.BytesIO(master_tls_key.encode('utf-8')))
            
            # Add all server configuration files
            for server_config in server_configs:
                filename = server_config['filename']
                content = server_config['content']
                current_app.logger.debug(f"Adding server config: {filename}, length: {len(content)}")
                config_info = tarfile.TarInfo(filename)
                config_info.size = len(content.encode('utf-8'))
                tar.addfile(config_info, io.BytesIO(content.encode('utf-8')))
        
        tar_buffer.seek(0)
        tar_content = tar_buffer.getvalue()
        
        # 8. Return tar file as response
        return Response(
            tar_content,
            mimetype='application/gzip',
            headers={
                'Content-Disposition': f'attachment; filename=openvpn-server-{psk_object.description}.tar.gz'
            }
        )
        
    except SigningServiceError as e: # pragma: no cover
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
        
        # Handle errors from the signing service
        current_app.logger.error(f"Signing service error in server bundle: {e}")
        return jsonify(error="Signing service unavailable"), 503
    except Exception as e: # pragma: no cover
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
        
        # Log the full error for debugging, but don't expose details to client
        current_app.logger.error(f"Server bundle generation error: {e}")
        return jsonify(error="An internal error occurred"), 500


@bp.route('/computer/bundle', methods=['GET', 'POST'])
@admin_service_only_api
@psk_required
@psk_type_required('computer')
def computer_bundle(psk_object):
    """
    Computer-identity bundle endpoint. Returns a tar file containing all components
    needed for computer-identity authentication (site-to-site VPN, managed assets).
    Uses computer certificates instead of server certificates.
    """
    trace(current_app, 'routes.api.v1.computer_bundle')

    # Record PSK usage
    from app.extensions import db
    psk_object.record_usage()
    db.session.commit()

    try:
        # 1. Generate computer certificate and key with timestamp for uniqueness
        timestamp = int(datetime.now(timezone.utc).timestamp())
        computer_key, computer_csr = generate_key_and_csr(
            common_name=f"computer-{psk_object.description}-{timestamp}",
        )

        # 2. Get the computer certificate signed with 'computer' type
        csr_pem = computer_csr.public_bytes(
            encoding=serialization.Encoding.PEM
        ).decode('utf-8')

        # Get client IP for geolocation tracking
        client_ip = request.remote_addr
        if request.headers.get('X-Forwarded-For'):
            forwarded_ips = request.headers.get('X-Forwarded-For').split(',')
            if forwarded_ips and forwarded_ips[0].strip():
                client_ip = forwarded_ips[0].strip()

        computer_cert_pem = request_signed_certificate(csr_pem, certificate_type='client', client_ip=client_ip)

        # Track certificate request with user agent and OS detection
        from app.models.certificate_request import CertificateRequest
        cert_request = CertificateRequest.create_from_request(
            flask_request=request,
            common_name=f"computer-{psk_object.description}-{timestamp}",
            certificate_type='computer',
            user_info=None,  # No user info for API requests
            template_set=psk_object.template_set,
            request_source='api'
        )
        cert_request.signing_successful = True
        db.session.add(cert_request)

        # 3. Serialize the private key
        computer_key_pem = computer_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')

        # 4. Get CA certificates
        root_ca_cert = current_app.config.get('ROOT_CA_CERTIFICATE', '')
        intermediate_ca_cert = current_app.config.get('INTERMEDIATE_CA_CERTIFICATE', '')
        ca_chain = f"{intermediate_ca_cert}\n{root_ca_cert}".strip()

        # 5. Get TLS-Crypt key
        master_tls_key = current_app.config.get('OPENVPN_TLS_CRYPT_KEY')
        computer_tls_crypt_key = None
        tls_crypt_version = None
        if master_tls_key is not None:
            tls_crypt_version, computer_tls_crypt_key = process_tls_crypt_key(master_tls_key)

        # Base context for computer configuration
        base_context = {
            'common_name': f"computer-{psk_object.description}-{timestamp}",
            'description': psk_object.description,
            'ca_cert_pem': ca_chain,
            'device_cert_pem': computer_cert_pem.strip(),
            'device_key_pem': computer_key_pem.strip(),
            'tlscrypt_key': computer_tls_crypt_key or '',
            'tlscrypt_version': tls_crypt_version,
            'userinfo': {'name': f'Computer Identity {psk_object.description}-{timestamp}', 'email': f'computer-{psk_object.description}-{timestamp}@local'},
        }

        # 6. Generate computer configuration using template rendering (like user profiles)
        try:
            # Use the same template selection logic as user profiles
            # Computer PSK template_set determines which template to use
            user_group_memberships = [psk_object.template_set or 'default']
            template_filename, template_content = find_best_template_match(current_app, user_group_memberships)

            current_app.logger.info(f"Using template: {template_filename} for computer configuration")

            # Render the template with computer certificate data
            final_config = render_config_template(current_app, template_content, **base_context)

            current_app.logger.info(f"Generated computer profile for {psk_object.description}")

        except Exception as e: # pragma: no cover
            ## PRAGMA-NO-COVER exception; JS 2025-09-18 FS Exceptions require FS bug to test
            current_app.logger.error(f"Error finding or rendering computer config template: {e}")
            return jsonify({'error': 'Template rendering failed'}), 500

        # 7. Return single OVPN file like user profiles
        download_filename = f"computer-{psk_object.description}.ovpn"
        return Response(
            final_config,
            mimetype="application/x-openvpn-profile",
            headers={"Content-disposition": f"attachment; filename={download_filename}"}
        )

    except SigningServiceError as e: # pragma: no cover
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

        # Handle errors from the signing service
        current_app.logger.error(f"Signing service error in computer bundle: {e}")
        return jsonify(error="Signing service unavailable"), 503
    except Exception as e: # pragma: no cover
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

        # Log the full error for debugging, but don't expose details to client
        current_app.logger.error(f"Computer bundle generation error: {e}")
        return jsonify(error="An internal error occurred"), 500


