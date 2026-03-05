"""
Helper functions for generating OpenVPN specific configurations.

This module provides utilities for processing OpenVPN tls-crypt keys,
supporting both v1 (static keys) and v2 (per-client keys) formats.

Key functionality:
- process_tls_crypt_key(): Detects key version and generates appropriate client keys
- TLSCryptV2Key: Handles v2 server master key to client key derivation using AES-CTR

Supported key formats:
- V1 static keys: "-----BEGIN OpenVPN Static key V1-----"
- V2 server keys (standard OpenVPN format): "-----BEGIN OpenVPN tls-crypt-v2 server key-----"
- V2 server keys (legacy hex format): "-----BEGIN OpenVPN TLS Crypt V2 Server Key-----"
"""
from flask import current_app
from app.utils.tracing import trace
import base64
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.hashes import SHA256
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
        Generates a unique tls-crypt-v2 client key from the server master key.

        Produces a client key in the format expected by OpenVPN: the raw client
        key material followed by a wrapped (encrypted + authenticated) copy that
        the server can unwrap to verify the client.

        The output structure (560 bytes total):
        - Raw client key: 256 bytes (2 x 128-byte OpenVPN key structs)
        - Wrapped key:
          - HMAC-SHA256 tag: 32 bytes (over IV + ciphertext)
          - IV: 16 bytes (random AES-CTR nonce)
          - Ciphertext: 256 bytes (AES-256-CTR encrypted client key)

        Returns:
            bytes: 560-byte client key data

        Security considerations:
        - Uses os.urandom() for cryptographically secure key and IV generation
        - AES-256-CTR encrypts the client key for confidentiality
        - HMAC-SHA256 authenticates the wrapped key (encrypt-then-MAC)
        - Each client key is unique and cannot be derived from other client keys

        Example:
            >>> server_key = TLSCryptV2Key(master_key_data)
            >>> client_key_1 = server_key.generate_client_key()
            >>> client_key_2 = server_key.generate_client_key()
            >>> assert len(client_key_1) == 560
            >>> assert client_key_1 != client_key_2  # Each key is unique
        """
        trace(
            current_app,
            'utils.openvpn_helpers.TLSCryptV2Key.generate_client_key',
            {
                'self': 'SELF'
            }
        )
        # Generate random 256-byte client key (2 x 128-byte OpenVPN key structs)
        client_key_raw = os.urandom(256)

        # Encrypt client key with server's encrypt key using AES-256-CTR
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(self.master_key[:32]), modes.CTR(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(client_key_raw) + encryptor.finalize()

        # HMAC-SHA256 over (IV + ciphertext) using server's HMAC key
        h = HMAC(self.hmac_key, SHA256(), backend=default_backend())
        h.update(iv + ciphertext)
        tag = h.finalize()

        # Wrapped key: HMAC(32) + IV(16) + ciphertext(256)
        wrapped_key = tag + iv + ciphertext

        # Client key file contains: raw key + wrapped key
        return client_key_raw + wrapped_key

def _decode_key_data(key_data: str) -> bytes:
    """
    Decodes key data that may be hex-encoded or base64-encoded.

    Tries hex decoding first (legacy format), then falls back to base64
    (standard OpenVPN format).

    Args:
        key_data: The raw key data string (hex or base64 encoded)

    Returns:
        bytes: The decoded key bytes

    Raises:
        ValueError: If the data cannot be decoded as either hex or base64
    """
    try:
        return bytes.fromhex(key_data)
    except ValueError:
        pass
    try:
        return base64.b64decode(key_data)
    except Exception:
        raise ValueError("Key data is neither valid hex nor valid base64.")


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
            - V2 (standard): "-----BEGIN OpenVPN tls-crypt-v2 server key-----"
            - V2 (legacy): "-----BEGIN OpenVPN TLS Crypt V2 Server Key-----"

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

    begin_lower = begin_line.strip().lower()

    if begin_lower == '-----begin openvpn static key v1-----':
        return 1, master_key_pem

    if begin_lower in (
        '-----begin openvpn tls crypt v2 server key-----',
        '-----begin openvpn tls-crypt-v2 server key-----',
    ):
        key_bytes = _decode_key_data(key_data)
        server_key = TLSCryptV2Key(key_bytes)
        client_key_data = server_key.generate_client_key()

        client_key_pem = "-----BEGIN OpenVPN tls-crypt-v2 client key-----\n"
        client_key_pem += base64.b64encode(client_key_data).decode('ascii')
        client_key_pem += "\n-----END OpenVPN tls-crypt-v2 client key-----\n"

        return 2, client_key_pem

    raise ValueError("Unrecognized TLS-Crypt key format.")