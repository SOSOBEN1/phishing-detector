from urllib.parse import urlparse

from flask_wtf import FlaskForm
from wtforms import BooleanField, PasswordField, StringField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo, Length, Regexp, ValidationError

from .models import User


def strong_password(form, field):
    """Au moins une lettre et un chiffre (en plus des 8 caractères minimum)."""
    value = field.data or ""
    if not any(c.isalpha() for c in value) or not any(c.isdigit() for c in value):
        raise ValidationError("Utilisez au moins une lettre et un chiffre.")


class LoginForm(FlaskForm):
    email = StringField("Adresse e-mail", validators=[DataRequired(), Email()])
    password = PasswordField("Mot de passe", validators=[DataRequired()])
    remember = BooleanField("Se souvenir de moi")
    submit = SubmitField("Se connecter")


class RegisterForm(FlaskForm):
    name = StringField("Nom complet", validators=[DataRequired(), Length(2, 80)])
    email = StringField("Adresse e-mail", validators=[DataRequired(), Email(), Length(max=120)])
    password = PasswordField(
        "Mot de passe",
        validators=[DataRequired(), Length(min=8, message="8 caractères minimum."), strong_password],
    )
    confirm = PasswordField(
        "Confirmer le mot de passe",
        validators=[DataRequired(), EqualTo("password", message="Les mots de passe ne correspondent pas.")],
    )
    submit = SubmitField("Créer mon compte")

    def validate_email(self, field):
        if User.query.filter_by(email=field.data.lower().strip()).first():
            raise ValidationError("Cette adresse e-mail est déjà utilisée.")


class AnalyzeForm(FlaskForm):
    url = StringField(
        "URL",
        validators=[DataRequired(message="Saisissez une URL."), Length(max=2000)],
    )
    submit = SubmitField("Analyser l'URL")

    def validate_url(self, field):
        value = (field.data or "").strip()
        if " " in value:
            raise ValidationError("L'URL ne doit pas contenir d'espaces.")
        try:
            host = urlparse(value if "://" in value else "http://" + value).hostname
        except ValueError:
            host = None
        if not host or "." not in host:
            raise ValidationError("URL invalide (exemple : https://exemple.com).")


class OTPForm(FlaskForm):
    code = StringField(
        "Code à 6 chiffres",
        validators=[DataRequired(message="Saisissez le code."), Regexp(r"^\d{6}$", message="Le code contient 6 chiffres.")],
    )
    submit = SubmitField("Vérifier")


class ChangePasswordForm(FlaskForm):
    current = PasswordField("Mot de passe actuel", validators=[DataRequired()])
    password = PasswordField(
        "Nouveau mot de passe",
        validators=[DataRequired(), Length(min=8, message="8 caractères minimum."), strong_password],
    )
    confirm = PasswordField(
        "Confirmer le nouveau mot de passe",
        validators=[DataRequired(), EqualTo("password", message="Les mots de passe ne correspondent pas.")],
    )
    submit = SubmitField("Changer le mot de passe")


class ResetMFAForm(FlaskForm):
    password = PasswordField("Mot de passe actuel", validators=[DataRequired()])
    submit = SubmitField("Réinitialiser la double authentification")
