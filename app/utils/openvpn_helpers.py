"""
Helper functions for generating OpenVPN specific configurations.
"""
from flask import current_app
from app.utils.tracing import trace
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

class TLSCryptV2Key:
    """A helper class for handling OpenVPN TLS-Crypt-V2 keys."""
    def __init__(self, key_data):
        trace(
            current_app,
            'utils.openvpn_helpers.TLSCryptV2Key.__init__',
            {
                'self': 'SELF',
                'key_data': key_data
            }
        )
        if len(key_data) != 128:
            raise ValueError("TLS-Crypt-V2 key must be 128 bytes.")
        self.master_key = key_data[:64]
        self.hmac_key = key_data[64:]

    def generate_client_key(self):
        """Generates a new client key from the master key."""
        trace(
            current_app,
            'utils.openvpn_helpers.TLSCryptV2Key.generate_client_key',
            {
                'self': 'SELF'
            }
        )
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(self.master_key[:32]), modes.CTR(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        client_key_data = encryptor.update(b'\0' * 64) + encryptor.finalize()
        return iv + client_key_data

def process_tls_crypt_key(master_key_pem: str):
    """
    Processes a master TLS-Crypt key, determines its version, and returns
    the appropriate key material for a client config.

    Returns:
        A tuple of (key_version, client_key_string).
    """
    trace(
        current_app,
        'utils.openvpn_helpers.process_tls_crypt_key',
        {
            'master_key_pem': master_key_pem
        }
    )
    if not master_key_pem:
        return None, None

    lines = master_key_pem.strip().split('\n')
    header = lines[0]
    key_data = "".join(lines[1:-1])

    if header == '-----BEGIN OpenVPN Static key V1-----':
        return 1, master_key_pem
    
    if header == '-----BEGIN OpenVPN TLS Crypt V2 Server Key-----':
        server_key = TLSCryptV2Key(bytes.fromhex(key_data))
        client_key_data = server_key.generate_client_key()
        
        client_key_pem = "-----BEGIN OpenVPN TLS Crypt V2 Client Key-----\n"
        client_key_pem += client_key_data.hex()
        client_key_pem += "\n-----END OpenVPN TLS Crypt V2 Client Key-----\n"
        
        return 2, client_key_pem

    raise ValueError("Unrecognized TLS-Crypt key format.")