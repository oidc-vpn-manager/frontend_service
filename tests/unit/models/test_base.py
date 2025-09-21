"""
Tests for the SecureModelMixin and SecureModel base classes.

These tests ensure mass assignment protection works correctly.
"""

import pytest
from unittest.mock import patch, MagicMock
from app.models.base import SecureModelMixin, SecureModel
from app.extensions import db


class MockSQLAlchemyModel:
    """Mock base class to simulate SQLAlchemy Model behavior."""

    def __init__(self, **kwargs):
        # Simulate SQLAlchemy model behavior - accept any keyword arguments
        for key, value in kwargs.items():
            setattr(self, key, value)


class TestSecureModelMixin:
    """Test the SecureModelMixin functionality."""

    def test_init_without_allowed_attributes_raises_error(self):
        """Test that __init__ raises NotImplementedError when _allowed_attributes is not defined."""

        class TestModel(SecureModelMixin, MockSQLAlchemyModel):
            pass

        with pytest.raises(NotImplementedError) as exc_info:
            TestModel(test_attr='value')

        assert "must define _allowed_attributes for mass assignment protection" in str(exc_info.value)

    def test_update_safe_without_allowed_attributes_raises_error(self):
        """Test that update_safe raises NotImplementedError when _allowed_attributes is not defined (line 83)."""

        class TestModel(SecureModelMixin, MockSQLAlchemyModel):
            def __init__(self, **kwargs):
                # Skip parent init to avoid the first NotImplementedError
                MockSQLAlchemyModel.__init__(self, **kwargs)

        model = TestModel()

        with pytest.raises(NotImplementedError) as exc_info:
            model.update_safe(test_attr='value')

        assert "must define _allowed_attributes for mass assignment protection" in str(exc_info.value)

    def test_update_safe_with_nonexistent_attribute(self):
        """Test update_safe handles attributes that don't exist on the model (line 96)."""

        class TestModel(SecureModelMixin, MockSQLAlchemyModel):
            _allowed_attributes = ['name', 'nonexistent_attr']

            def __init__(self, **kwargs):
                self.name = None
                super().__init__(**kwargs)

        model = TestModel(name='test')

        # Try to update an allowed attribute that doesn't exist on the model
        ignored = model.update_safe(nonexistent_attr='value', name='updated')

        # nonexistent_attr should be ignored because it doesn't exist as an attribute
        assert 'nonexistent_attr' in ignored
        assert model.name == 'updated'

    def test_init_logs_ignored_attributes_in_development(self):
        """Test that ignored attributes are logged in development mode."""
        from flask import Flask

        app = Flask(__name__)
        app.config['ENVIRONMENT'] = 'development'

        with app.app_context():
            with patch.object(app.logger, 'debug') as mock_debug:
                class TestModel(SecureModelMixin, MockSQLAlchemyModel):
                    _allowed_attributes = ['name']

                    def __init__(self, **kwargs):
                        super().__init__(**kwargs)

                TestModel(name='allowed', ignored_attr='ignored')

                # Check that debug logging was called
                mock_debug.assert_called_once()
                call_args = mock_debug.call_args[0][0]
                assert 'Mass assignment protection' in call_args
                assert 'ignored_attr' in call_args

    def test_update_safe_logs_updated_attributes_in_development(self):
        """Test that updated attributes are logged in development mode (lines 105-109)."""
        from flask import Flask

        app = Flask(__name__)
        app.config['ENVIRONMENT'] = 'development'

        with app.app_context():
            with patch.object(app.logger, 'debug') as mock_debug:
                class TestModel(SecureModelMixin, MockSQLAlchemyModel):
                    _allowed_attributes = ['name']

                    def __init__(self, **kwargs):
                        self.name = None
                        super().__init__(**kwargs)

                model = TestModel(name='initial')

                # Update with allowed attribute
                model.update_safe(name='updated')

                # Check that debug logging was called for updated attributes
                mock_debug.assert_called()
                call_args = mock_debug.call_args[0][0]
                assert 'Mass assignment update: updated' in call_args
                assert 'name' in call_args

    def test_update_safe_logs_ignored_attributes_in_development(self):
        """Test that ignored attributes are logged in development mode (lines 110-114)."""
        from flask import Flask

        app = Flask(__name__)
        app.config['ENVIRONMENT'] = 'development'

        with app.app_context():
            with patch.object(app.logger, 'debug') as mock_debug:
                class TestModel(SecureModelMixin, MockSQLAlchemyModel):
                    _allowed_attributes = ['name']

                    def __init__(self, **kwargs):
                        self.name = None
                        super().__init__(**kwargs)

                model = TestModel(name='initial')

                # Update with ignored attribute
                model.update_safe(ignored_attr='ignored')

                # Check that debug logging was called for ignored attributes
                mock_debug.assert_called()
                call_args = mock_debug.call_args[0][0]
                assert 'Mass assignment protection: ignored attributes' in call_args
                assert 'ignored_attr' in call_args

    def test_create_safe_method(self):
        """Test the create_safe class method."""

        class TestModel(SecureModelMixin, MockSQLAlchemyModel):
            _allowed_attributes = ['name']

            def __init__(self, **kwargs):
                self.name = kwargs.get('name')
                super().__init__(**kwargs)

        model = TestModel.create_safe(name='test', ignored='ignored')
        assert model.name == 'test'

    def test_update_safe_returns_ignored_attributes(self):
        """Test that update_safe returns list of ignored attributes."""

        class TestModel(SecureModelMixin, MockSQLAlchemyModel):
            _allowed_attributes = ['name']

            def __init__(self, **kwargs):
                self.name = None
                super().__init__(**kwargs)

        model = TestModel(name='initial')

        ignored = model.update_safe(name='updated', ignored1='ignored', ignored2='ignored')

        assert model.name == 'updated'
        assert 'ignored1' in ignored
        assert 'ignored2' in ignored
        assert 'name' not in ignored


class TestSecureModel:
    """Test the SecureModel base class."""

    def test_secure_model_is_abstract(self):
        """Test that SecureModel is marked as abstract."""
        assert SecureModel.__abstract__ is True

    def test_secure_model_inherits_from_mixin_and_db_model(self):
        """Test that SecureModel properly inherits from both SecureModelMixin and db.Model."""
        assert issubclass(SecureModel, SecureModelMixin)
        assert issubclass(SecureModel, db.Model)