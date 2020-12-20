"""
forms.py

    Defines form models needed for authentication.
"""

from wtforms import Form, StringField, PasswordField
from wtforms.validators import DataRequired, Length, EqualTo


class LoginForm(Form):
    username = StringField("Username", [DataRequired()])
    password = PasswordField("Password", [DataRequired()])


class RegistrationForm(Form):
    """ Registration Form imposes char length requirements for signup """

    email = StringField("Email", [DataRequired(), Length(min=5, max=50)])
    username = StringField("Username", [DataRequired(), Length(min=3, max=25)])
    password = PasswordField(
        "Password",
        [
            DataRequired(),
            EqualTo("confirm", message="Passwords must match"),
            Length(min=8, max=100),
        ],
    )
    confirm = PasswordField(
        "Confirm Password", [DataRequired(), Length(min=8, max=100)]
    )
