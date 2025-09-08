"""
Defines a custom SQLAlchemy TypeDecorator for encrypting data at rest.
"""

from sqlalchemy.types import TypeDecorator, LargeBinary
from app.utils.cryptography import get_fernet

class EncryptedString(TypeDecorator):
    """
    A SQLAlchemy TypeDecorator that provides transparent encryption for string columns.
    It uses the application's Fernet instance for encryption and decryption.
    """
    impl = LargeBinary
    cache_ok = True

    def process_bind_param(self, value, dialect):
        """
        Called when a value is being sent to the database.
        Encrypts the plaintext string value.
        """
        if value is not None:
            fernet = get_fernet()
            return fernet.encrypt(value.encode('utf-8'))
        return None

    def process_result_value(self, value, dialect):
        """
        Called when a value is retrieved from the database.
        Decrypts the encrypted binary value.
        """
        if value is not None:
            fernet = get_fernet()
            return fernet.decrypt(value).decode('utf-8')
        return None