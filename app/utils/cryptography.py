"""
Cryptographic utilities for secure data encryption in OpenVPN Manager.

This module provides Fernet-based symmetric encryption for sensitive data
stored in the database, such as encrypted model fields. It includes security
checks to prevent use of default keys in production environments.
"""

import os
from flask import current_app
from app.utils.tracing import trace
from cryptography.fernet import Fernet

def get_fernet():
    """
    Get or create a Fernet encryption instance for symmetric encryption.

    This function manages a singleton Fernet instance per Flask application
    context, used for encrypting and decrypting sensitive database fields.
    Includes security checks to prevent production use with default keys.

    The function:
    1. Checks for cached Fernet instance in app config
    2. Creates new instance from ENCRYPTION_KEY if not cached
    3. Validates that default key is not used in production
    4. Logs security warnings for development environments

    Returns:
        cryptography.fernet.Fernet: Configured Fernet instance for encryption/decryption

    Raises:
        RuntimeError: If ENCRYPTION_KEY is not configured
        RuntimeError: If default key is used in production environment

    Example:
        >>> fernet = get_fernet()
        >>> encrypted = fernet.encrypt(b"sensitive data")
        >>> decrypted = fernet.decrypt(encrypted)
        >>> assert decrypted == b"sensitive data"

    Security Notes:
        - ENCRYPTION_KEY must be a 44-character base64-encoded key
        - Default key triggers warnings in development
        - Default key blocks startup in production
        - Key should be generated with Fernet.generate_key()
    """
    trace(current_app, 'utils.cryptography.get_fernet')
    # Use a key on the app config to cache the object per-app-instance
    if 'fernet_instance' not in current_app.config:
        try:
            encryption_key = current_app.config['ENCRYPTION_KEY']
            current_app.config['fernet_instance'] = Fernet(encryption_key.encode('utf-8'))
        except KeyError:
            raise RuntimeError("ENCRYPTION_KEY must be set for data encryption.")

    # Security check: prevent production use of default development key
    default_key = 'YenxIAHqvrO7OHbNXvzAxEhthHCaitvnV9CALkQvvCc='
    if current_app.config.get('ENCRYPTION_KEY') == default_key:
        if os.environ.get('FLASK_ENV') == 'production':
            raise RuntimeError(
                "Cannot start in production with the default insecure ENCRYPTION_KEY. "
                "You MUST set the FERNET_ENCRYPTION_KEY environment variable."
            )

        # Log security warning once per application instance
        if 'fernet_warning' not in current_app.config:
            current_app.logger.critical(
                'You are using an untrusted and insecure key. '
                'You MUST define FERNET_ENCRYPTION_KEY before using this in production'
            )
            current_app.config['fernet_warning'] = 1

    return current_app.config['fernet_instance']
