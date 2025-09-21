"""
Base model with mass assignment protection.

This module provides a secure base class for SQLAlchemy models that prevents
mass assignment vulnerabilities by only allowing explicitly defined attributes.
"""

from app.extensions import db


class SecureModelMixin:
    """
    Mixin class that provides mass assignment protection for SQLAlchemy models.

    This mixin overrides the __init__ method to only accept explicitly allowed
    attributes, preventing attackers from setting sensitive fields like 'id',
    'created_at', 'is_admin', etc. through form data or API requests.
    """

    # Subclasses must define this list of allowed attributes for mass assignment
    # This is None by default to force explicit definition

    def __init__(self, **kwargs):
        """
        Initialize model with mass assignment protection.

        Only attributes listed in _allowed_attributes can be set during initialization.
        All other attributes are ignored with a warning logged.
        """
        if not hasattr(self, '_allowed_attributes') or self._allowed_attributes is None:
            raise NotImplementedError(
                f"{self.__class__.__name__} must define _allowed_attributes for mass assignment protection"
            )

        # Filter kwargs to only include allowed attributes
        filtered_kwargs = {}
        ignored_attributes = []

        for key, value in kwargs.items():
            if key in self._allowed_attributes:
                filtered_kwargs[key] = value
            else:
                ignored_attributes.append(key)

        # Log ignored attributes for debugging (but not in production to avoid log spam)
        if ignored_attributes:
            import logging
            from flask import current_app
            if current_app and current_app.config.get('ENVIRONMENT') == 'development':
                current_app.logger.debug(
                    f"Mass assignment protection: ignored attributes {ignored_attributes} "
                    f"for {self.__class__.__name__}"
                )

        # Call parent constructor with filtered kwargs
        # SQLAlchemy will handle applying defaults during flush/commit
        super().__init__(**filtered_kwargs)

    @classmethod
    def create_safe(cls, **kwargs):
        """
        Create a new instance with only allowed attributes.

        This is a convenience method that provides explicit mass assignment protection
        and can be used in routes that accept user input.

        Returns:
            New instance of the model with filtered attributes
        """
        return cls(**kwargs)

    def update_safe(self, **kwargs):
        """
        Update model attributes with mass assignment protection.

        Only attributes listed in _allowed_attributes can be updated.
        Returns a list of ignored attributes for debugging.

        Returns:
            List of ignored attribute names
        """
        if not hasattr(self, '_allowed_attributes'):
            raise NotImplementedError(
                f"{self.__class__.__name__} must define _allowed_attributes for mass assignment protection"
            )

        ignored_attributes = []
        updated_attributes = []

        for key, value in kwargs.items():
            if key in self._allowed_attributes:
                if hasattr(self, key):
                    setattr(self, key, value)
                    updated_attributes.append(key)
                else:
                    ignored_attributes.append(key)
            else:
                ignored_attributes.append(key)

        # Log changes in development
        if updated_attributes or ignored_attributes:
            import logging
            from flask import current_app
            if current_app and current_app.config.get('ENVIRONMENT') == 'development':
                if updated_attributes:
                    current_app.logger.debug(
                        f"Mass assignment update: updated {updated_attributes} "
                        f"for {self.__class__.__name__} id={getattr(self, 'id', 'new')}"
                    )
                if ignored_attributes:
                    current_app.logger.debug(
                        f"Mass assignment protection: ignored attributes {ignored_attributes} "
                        f"for {self.__class__.__name__} id={getattr(self, 'id', 'new')}"
                    )

        return ignored_attributes


class SecureModel(SecureModelMixin, db.Model):
    """
    Base model class with mass assignment protection.

    All models that handle user input should inherit from this class
    and define their _allowed_attributes list.
    """
    __abstract__ = True