"""
Defines the routes for version 1 of the API.
"""

from flask import Blueprint, jsonify, current_app, Response, request
from app.utils.tracing import trace
from app.utils.decorators import psk_required, admin_service_only_api
from app.utils.ca_core import generate_key_and_csr
from app.utils.signing_client import request_signed_certificate, SigningServiceError
from app.utils.openvpn_helpers import process_tls_crypt_key
from cryptography.hazmat.primitives import serialization
from app.extensions import csrf
import tarfile
import io
import os
import tempfile
from datetime import datetime, timezone

bp = Blueprint('v1', __name__, url_prefix='/v1')
csrf.exempt(bp)


@bp.route('/server/bundle', methods=['GET', 'POST'])
@admin_service_only_api
@psk_required
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
            if forwarded_ips:
                client_ip = forwarded_ips[0].strip()
        
        server_cert_pem = request_signed_certificate(csr_pem, certificate_type='server', client_ip=client_ip)
        
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
        server_tls_crypt_key = None
        tls_crypt_version = None
        if master_tls_key is not None:
            tls_crypt_version, server_tls_crypt_key = process_tls_crypt_key(master_tls_key)
        
        # Debug logging for None values
        if not root_ca_cert:
            current_app.logger.warning("ROOT_CA_CERTIFICATE is empty or None")
        if not intermediate_ca_cert:
            current_app.logger.warning("INTERMEDIATE_CA_CERTIFICATE is empty or None")
        if not server_cert_pem:
            current_app.logger.warning("server_cert_pem is empty or None") # pragma: no cover
        if not server_key_pem:
            current_app.logger.warning("server_key_pem is empty or None") # pragma: no cover
        if not master_tls_key:
            current_app.logger.warning("OPENVPN_TLS_CRYPT_KEY is empty or None")
        if not server_tls_crypt_key:
            current_app.logger.warning(f"server_tls_crypt_key is empty or None. master_tls_key length: {len(master_tls_key) if master_tls_key else 0}, tls_crypt_version: {tls_crypt_version}")
        
        # Base context for server configuration
        base_context = {
            'common_name': f"server-{psk_object.description}-{timestamp}",
            'description': psk_object.description,
            'ca_cert_pem': ca_chain,
            'device_cert_pem': server_cert_pem.strip(),
            'device_key_pem': server_key_pem.strip(),
            'tlscrypt_key': server_tls_crypt_key or '',
            'tlscrypt_version': tls_crypt_version,
            'userinfo': {'name': f'OpenVPN Server {psk_object.description}-{timestamp}', 'email': f'server-{psk_object.description}-{timestamp}@local'},
        }
        
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
                    except Exception as e:
                        current_app.logger.error(f"Error reading server config file {filename}: {e}")
        
        if not server_configs:
            current_app.logger.warning(f"No server configuration files found matching template set '{psk_object.template_set}'")
        
        # 7. Create tar file in memory
        tar_buffer = io.BytesIO()
        with tarfile.open(fileobj=tar_buffer, mode='w:gz') as tar:
            # Add CA certificate chain
            current_app.logger.info(f"Adding ca_chain to tar: {type(ca_chain)}, length: {len(ca_chain) if ca_chain else 0}")
            ca_info = tarfile.TarInfo('ca-chain.crt')
            ca_info.size = len(ca_chain.encode('utf-8'))
            tar.addfile(ca_info, io.BytesIO(ca_chain.encode('utf-8')))
            
            # Add server certificate
            current_app.logger.info(f"Adding server_cert_pem: {server_cert_pem is not None}")
            server_cert_info = tarfile.TarInfo('server.crt')
            server_cert_info.size = len(server_cert_pem.encode('utf-8'))
            tar.addfile(server_cert_info, io.BytesIO(server_cert_pem.encode('utf-8')))
            
            # Add server private key
            current_app.logger.info(f"Adding server_key_pem: {server_key_pem is not None}")
            server_key_info = tarfile.TarInfo('server.key')
            server_key_info.size = len(server_key_pem.encode('utf-8'))
            tar.addfile(server_key_info, io.BytesIO(server_key_pem.encode('utf-8')))
            
            # Add TLS-Crypt key
            current_app.logger.info(f"Adding server_tls_crypt_key: {server_tls_crypt_key is not None}, value: '{server_tls_crypt_key}'")
            tls_key_info = tarfile.TarInfo('tls-crypt.key')
            tls_key_info.size = len((server_tls_crypt_key or '').encode('utf-8'))
            tar.addfile(tls_key_info, io.BytesIO((server_tls_crypt_key or '').encode('utf-8')))
            
            # Add all server configuration files
            for server_config in server_configs:
                filename = server_config['filename']
                content = server_config['content']
                current_app.logger.info(f"Adding server config: {filename}, length: {len(content)}")
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
        
    except SigningServiceError as e:
        # Handle errors from the signing service
        current_app.logger.error(f"Signing service error in server bundle: {e}")
        return jsonify(error="Signing service unavailable"), 503
    except Exception as e:
        # Log the full error for debugging, but don't expose details to client
        current_app.logger.error(f"Server bundle generation error: {e}")
        return jsonify(error="An internal error occurred"), 500


