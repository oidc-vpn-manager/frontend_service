import os
from flask import current_app
from app.utils.tracing import trace
from cryptography.fernet import Fernet

def get_fernet():
    """Gets the Fernet instance, creating it if it doesn't exist on the app context."""
    trace(current_app, 'utils.cryptography.get_fernet')
    # Use a key on the app config to cache the object per-app-instance
    if 'fernet_instance' not in current_app.config:
        try:
            encryption_key = current_app.config['ENCRYPTION_KEY']
            current_app.config['fernet_instance'] = Fernet(encryption_key.encode('utf-8'))
        except KeyError:
            raise RuntimeError("ENCRYPTION_KEY must be set for data encryption.")

    default_key = 'YenxIAHqvrO7OHbNXvzAxEhthHCaitvnV9CALkQvvCc='
    if current_app.config.get('ENCRYPTION_KEY') == default_key:
        if os.environ.get('FLASK_ENV') == 'production':
            raise RuntimeError(
                "Cannot start in production with the default insecure ENCRYPTION_KEY. "
                "You MUST set the FERNET_ENCRYPTION_KEY environment variable."
            )
        
        if 'fernet_warning' not in current_app.config:
            current_app.logger.critical(
                'You are using an untrusted and insecure key. '
                'You MUST define FERNET_ENCRYPTION_KEY before using this in production'
            )
            current_app.config['fernet_warning'] = 1
            
    return current_app.config['fernet_instance']
