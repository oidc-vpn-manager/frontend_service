from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, SelectField
from wtforms.validators import DataRequired, Length

class NewPskForm(FlaskForm):
    """Form for creating a new Pre-Shared Key."""
    description = StringField('Description', validators=[
        DataRequired(),
        Length(min=1, max=255, message="Description must be between 1 and 255 characters")
    ])
    psk_type = SelectField('PSK Type',
                          choices=[('server', 'Server Bundle (Hub-and-spoke VPN servers)'),
                                   ('computer', 'Computer Identity (Site-to-site, managed assets)')],
                          default='server',
                          validators=[DataRequired()])
    template_set = SelectField('Template Set', validate_choice=False)
    submit = SubmitField('Create Key')

class GenerateProfileForm(FlaskForm):
    """
    Form for generating a user's VPN profile.
    The options are rendered dynamically, so this form is mainly for CSRF protection.
    """
    submit = SubmitField('Generate Profile')