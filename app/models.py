from datetime import datetime, timezone

from flask_login import UserMixin
from werkzeug.security import check_password_hash, generate_password_hash

from .extensions import db, login_manager


def _now():
    return datetime.now(timezone.utc)


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="user")  # "user" | "admin"
    is_active = db.Column(db.Boolean, nullable=False, default=True)  # compte désactivable par l'admin
    # MFA (TOTP) : secret partagé avec l'application d'authentification
    otp_secret = db.Column(db.String(32))
    mfa_enabled = db.Column(db.Boolean, nullable=False, default=False)
    otp_last_counter = db.Column(db.Integer)  # dernier code accepté (anti-rejeu)
    created_at = db.Column(db.DateTime, default=_now)
    analyses = db.relationship(
        "Analysis", backref="user", lazy="dynamic", cascade="all, delete-orphan"
    )

    def set_password(self, password: str):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)

    @property
    def is_admin(self) -> bool:
        return self.role == "admin"


class Analysis(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    url = db.Column(db.Text, nullable=False)
    label = db.Column(db.String(30), nullable=False)  # "Phishing" | "Légitime"
    probability = db.Column(db.Float, nullable=False)
    created_at = db.Column(db.DateTime, default=_now, index=True)


class SecurityLog(db.Model):
    """Journal de sécurité consultable par l'administrateur."""
    id = db.Column(db.Integer, primary_key=True)
    created_at = db.Column(db.DateTime, default=_now, index=True)
    event = db.Column(db.String(40), nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id", ondelete="SET NULL"))
    email = db.Column(db.String(120))
    ip = db.Column(db.String(45))
    details = db.Column(db.String(255))


@login_manager.user_loader
def load_user(user_id):
    user = db.session.get(User, int(user_id))
    # Un compte désactivé perd immédiatement sa session
    return user if user and user.is_active else None