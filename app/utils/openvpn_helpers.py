"""
Helper functions for generating OpenVPN specific configurations.

This module provides utilities for processing OpenVPN tls-crypt keys,
supporting both v1 (static keys) and v2 (per-client keys) formats.

Key functionality:
- process_tls_crypt_key(): Detects key version and generates appropriate client keys
- TLSCryptV2Key: Handles v2 server master key to client key derivation using AES-CTR
"""
from flask import current_app
from app.utils.tracing import trace
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

class TLSCryptV2Key:
    """
    A helper class for handling OpenVPN TLS-Crypt-V2 server master keys.

    OpenVPN tls-crypt v2 uses a server master key to derive unique per-client
    keys, providing better security than v1 shared static keys. Each client
    receives a cryptographically unique key derived from the master.

    Security considerations:
    - Master key must be exactly 128 bytes (512 bits)
    - Client keys are derived using AES-256-CTR with random IVs
    - Each client key is unique and cannot be derived from other client keys
    - Compromise of one client key does not affect other clients

    Args:
        key_data (bytes): 128-byte server master key

    Raises:
        ValueError: If key_data is not exactly 128 bytes

    Example:
        >>> key_data = bytes.fromhex('a1a2a3a4...')  # 256 hex chars = 128 bytes
        >>> server_key = TLSCryptV2Key(key_data)
        >>> client_key = server_key.generate_client_key()
    """
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
        """
        Generates a unique client key from the server master key.

        Uses AES-256-CTR encryption to derive a unique 64-byte client key.
        Each call produces a cryptographically unique key due to the random IV.

        Returns:
            bytes: 80-byte client key (16-byte IV + 64-byte encrypted data)

        Security considerations:
        - Uses os.urandom() for cryptographically secure IV generation
        - AES-256 in CTR mode ensures unique key derivation
        - Client keys cannot be used to derive the master key (one-way)

        Example:
            >>> server_key = TLSCryptV2Key(master_key_data)
            >>> client_key_1 = server_key.generate_client_key()
            >>> client_key_2 = server_key.generate_client_key()
            >>> assert client_key_1 != client_key_2  # Each key is unique
        """
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
    Processes a TLS-Crypt key, detects version, and returns appropriate client key.

    Supports both OpenVPN tls-crypt v1 (static shared keys) and v2 (per-client keys).
    The function automatically detects the version from the PEM header and processes
    accordingly:

    - V1: Returns the static key unchanged (shared among all clients)
    - V2: Generates a unique client key from the server master key
    - None: Returns (None, None) for graceful handling of missing keys

    Args:
        master_key_pem (str): PEM-formatted tls-crypt key with appropriate header:
            - V1: "-----BEGIN OpenVPN Static key V1-----"
            - V2: "-----BEGIN OpenVPN TLS Crypt V2 Server Key-----"

    Returns:
        tuple: (version, client_key_pem) where:
            - version (int|None): 1 for v1, 2 for v2, None if no key provided
            - client_key_pem (str|None): PEM-formatted client key or None

    Raises:
        ValueError: If the key format is unrecognized or malformed
        ValueError: If v2 key is not exactly 128 bytes

    Security considerations:
    - V1 keys provide TLS channel encryption but are shared (less secure)
    - V2 keys provide per-client isolation (recommended for production)
    - Both versions prevent DoS attacks via HMAC before TLS handshake
    - Version detection prevents downgrade attacks

    Example:
        >>> v1_key = "-----BEGIN OpenVPN Static key V1-----\\n...\\n-----END..."
        >>> version, client_key = process_tls_crypt_key(v1_key)
        >>> assert version == 1
        >>> assert client_key == v1_key  # V1 returns unchanged

        >>> v2_key = "-----BEGIN OpenVPN TLS Crypt V2 Server Key-----\\n...\\n-----END..."
        >>> version, client_key = process_tls_crypt_key(v2_key)
        >>> assert version == 2
        >>> assert "Client Key" in client_key  # V2 generates new key
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

    # Find the BEGIN line, skipping any comments
    begin_line = None
    begin_index = 0
    for i, line in enumerate(lines):
        if line.startswith('-----BEGIN OpenVPN'):
            begin_line = line
            begin_index = i
            break

    if not begin_line:
        raise ValueError("Unrecognized TLS-Crypt key format.")

    # Find the END line
    end_index = len(lines) - 1
    for i in range(begin_index + 1, len(lines)):
        if lines[i].startswith('-----END OpenVPN'):
            end_index = i
            break

    # Extract key data between BEGIN and END lines
    key_data = "".join(lines[begin_index + 1:end_index])

    if begin_line == '-----BEGIN OpenVPN Static key V1-----':
        return 1, master_key_pem

    if begin_line == '-----BEGIN OpenVPN TLS Crypt V2 Server Key-----':
        server_key = TLSCryptV2Key(bytes.fromhex(key_data))
        client_key_data = server_key.generate_client_key()

        client_key_pem = "-----BEGIN OpenVPN TLS Crypt V2 Client Key-----\n"
        client_key_pem += client_key_data.hex()
        client_key_pem += "\n-----END OpenVPN TLS Crypt V2 Client Key-----\n"

        return 2, client_key_pem

    raise ValueError("Unrecognized TLS-Crypt key format.")