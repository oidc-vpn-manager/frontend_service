"""
Helper functions for generating OpenVPN specific configurations.

This module provides utilities for processing OpenVPN tls-crypt keys,
supporting both v1 (static keys) and v2 (per-client keys) formats.

Key functionality:
- process_tls_crypt_key(): Detects key version and generates appropriate client keys
- _generate_v2_client_key(): Delegates to the openvpn binary for v2 key generation

Supported key formats:
- V1 static keys: "-----BEGIN OpenVPN Static key V1-----"
- V2 server keys: "-----BEGIN OpenVPN tls-crypt-v2 server key-----"
"""
from flask import current_app
from app.utils.tracing import trace
import os
import subprocess
import tempfile


def _generate_v2_client_key(server_key_pem: str) -> str:
    """
    Generates a tls-crypt-v2 client key using the openvpn binary.

    Delegates key generation to the reference OpenVPN implementation,
    ensuring full format compatibility with OpenVPN clients and servers.

    Args:
        server_key_pem: PEM-formatted tls-crypt-v2 server key

    Returns:
        str: PEM-formatted tls-crypt-v2 client key

    Raises:
        ValueError: If openvpn key generation fails (bad key, binary missing, etc.)

    Security considerations:
    - Each call produces a cryptographically unique client key
    - Key generation is performed by the reference OpenVPN implementation
    - Temporary files are created in a secure temporary directory and cleaned up
    """
    trace(
        current_app,
        'utils.openvpn_helpers._generate_v2_client_key',
        {
            'server_key_pem': '[REDACTED]'
        }
    )
    with tempfile.TemporaryDirectory() as tmpdir:
        server_key_path = os.path.join(tmpdir, 'server.key')
        client_key_path = os.path.join(tmpdir, 'client.key')

        with open(server_key_path, 'w') as f:
            f.write(server_key_pem)

        result = subprocess.run(
            [
                'openvpn',
                '--tls-crypt-v2', server_key_path,
                '--genkey', 'tls-crypt-v2-client', client_key_path,
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode != 0:
            raise ValueError(
                f"openvpn tls-crypt-v2 client key generation failed: {result.stderr.strip()}"
            )

        with open(client_key_path, 'r') as f:
            return f.read()


def process_tls_crypt_key(master_key_pem: str):
    """
    Processes a TLS-Crypt key, detects version, and returns appropriate client key.

    Supports both OpenVPN tls-crypt v1 (static shared keys) and v2 (per-client keys).
    The function automatically detects the version from the PEM header and processes
    accordingly:

    - V1: Returns the static key unchanged (shared among all clients)
    - V2: Generates a unique client key via the openvpn binary
    - None: Returns (None, None) for graceful handling of missing keys

    Args:
        master_key_pem (str): PEM-formatted tls-crypt key with appropriate header:
            - V1: "-----BEGIN OpenVPN Static key V1-----"
            - V2: "-----BEGIN OpenVPN tls-crypt-v2 server key-----"

    Returns:
        tuple: (version, client_key_pem) where:
            - version (int|None): 1 for v1, 2 for v2, None if no key provided
            - client_key_pem (str|None): PEM-formatted client key or None

    Raises:
        ValueError: If the key format is unrecognized or openvpn fails

    Security considerations:
    - V1 keys provide TLS channel encryption but are shared (less secure)
    - V2 keys provide per-client isolation (recommended for production)
    - Both versions prevent DoS attacks via HMAC before TLS handshake
    - V2 key generation uses the reference OpenVPN implementation

    Example:
        >>> v1_key = "-----BEGIN OpenVPN Static key V1-----\\n...\\n-----END..."
        >>> version, client_key = process_tls_crypt_key(v1_key)
        >>> assert version == 1
        >>> assert client_key == v1_key  # V1 returns unchanged

        >>> v2_key = "-----BEGIN OpenVPN tls-crypt-v2 server key-----\\n...\\n-----END..."
        >>> version, client_key = process_tls_crypt_key(v2_key)
        >>> assert version == 2
        >>> assert "tls-crypt-v2 client key" in client_key
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
    for i, line in enumerate(lines):
        if line.startswith('-----BEGIN OpenVPN'):
            begin_line = line
            break

    if not begin_line:
        raise ValueError("Unrecognized TLS-Crypt key format.")

    begin_lower = begin_line.strip().lower()

    if begin_lower == '-----begin openvpn static key v1-----':
        return 1, master_key_pem

    if 'tls-crypt-v2' in begin_lower or 'tls crypt v2' in begin_lower:
        client_key_pem = _generate_v2_client_key(master_key_pem)
        return 2, client_key_pem

    raise ValueError("Unrecognized TLS-Crypt key format.")
