"""
Core functions for key and Certificate Signing Request (CSR) generation.
"""

import re
from datetime import datetime, timezone
from flask import current_app
from app.utils.tracing import trace

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ed25519

EMAIL_REGEX = re.compile(r'[^@]+@[^@]+\.[^@]+')

def generate_key_and_csr(
    common_name: str,
    key_type: str = 'ed25519',
    country: str = None,
    state: str = None,
    locality: str = None,
    organization: str = None,
):
    """
    Generates a private key and a Certificate Signing Request (CSR).
    Pulls default subject fields from the application config if not provided.
    """
    trace(
        current_app,
        'utils.ca_core.generate_key_and_csr',
        {
            'common_name': common_name,
            'key_type': key_type,
            'country': country,
            'state': state,
            'locality': locality,
            'organization': organization
        }
    )
    signing_algorithm = None
    if key_type == 'ed25519':
        private_key = ed25519.Ed25519PrivateKey.generate()
        signing_algorithm = None
    elif key_type == 'rsa':
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        signing_algorithm = hashes.SHA256()
    else:
        raise ValueError("Unsupported key type specified.")

    final_common_name = common_name
    if EMAIL_REGEX.match(common_name):
        timestamp = int(datetime.now(timezone.utc).timestamp())
        final_common_name = f"{common_name}-{timestamp}"

    subject_fields = [
        x509.NameAttribute(NameOID.COUNTRY_NAME, country or current_app.config['CA_COUNTRY_NAME']),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state or current_app.config['CA_STATE_OR_PROVINCE_NAME']),
        x509.NameAttribute(NameOID.LOCALITY_NAME, locality or current_app.config['CA_LOCALITY_NAME']),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization or current_app.config['CA_ORGANIZATION_NAME']),
        x509.NameAttribute(NameOID.COMMON_NAME, final_common_name),
    ]
    subject_name = x509.Name(subject_fields)
    
    builder = x509.CertificateSigningRequestBuilder().subject_name(subject_name)
    csr = builder.sign(private_key, signing_algorithm)

    return private_key, csr
