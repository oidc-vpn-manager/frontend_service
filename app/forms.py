from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, SelectField
from wtforms.validators import DataRequired, Length

class NewPskForm(FlaskForm):
    """Form for creating a new Pre-Shared Key."""
    description = StringField('Description', validators=[
        DataRequired(),
        Length(min=1, max=255, message="Description must be between 1 and 255 characters")
    ])
    template_set = SelectField('Server Template Set', validate_choice=False)
    submit = SubmitField('Create Key')

class GenerateProfileForm(FlaskForm):
    """
    Form for generating a user's VPN profile.
    The options are rendered dynamically, so this form is mainly for CSRF protection.
    """
    submit = SubmitField('Generate Profile')