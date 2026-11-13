"""Briques de sécurité partagées : RBAC, journalisation, MFA, en-têtes HTTP."""
import time
from functools import wraps

import pyotp
from flask import abort, request
from flask_login import current_user, login_required

from .extensions import db
from .models import SecurityLog

OTP_WINDOW = 1  # tolère ±30 s de décalage d'horloge avec le téléphone


# ---------- Journalisation ----------
def log_event(event, user=None, email=None, details=""):
    """Enregistre un événement de sécurité (connexion, échec, action admin…)."""
    db.session.add(
        SecurityLog(
            event=event,
            user_id=user.id if user else None,
            email=email or (user.email if user else None),
            ip=request.remote_addr,
            details=(details or "")[:255],
        )
    )
    db.session.commit()


# ---------- RBAC ----------
def admin_required(view):
    """Réservé au rôle admin : 403 pour les autres (et tentative journalisée)."""

    @wraps(view)
    @login_required
    def wrapper(*args, **kwargs):
        if not current_user.is_admin:
            log_event("access_denied", current_user, details=request.path)
            abort(403)
        return view(*args, **kwargs)

    return wrapper


# ---------- MFA (TOTP) ----------
def verify_totp(secret, code, last_counter=None):
    """Vérifie un code TOTP. Renvoie le compteur accepté, ou None.

    Un code déjà utilisé (compteur <= last_counter) est refusé : un code
    intercepté ne peut pas être rejoué.
    """
    code = (code or "").strip()
    if not secret or not code.isdigit():
        return None
    totp = pyotp.TOTP(secret)
    now = int(time.time())
    for offset in range(-OTP_WINDOW, OTP_WINDOW + 1):
        t = now + offset * totp.interval
        if pyotp.utils.strings_equal(totp.at(t), code):
            counter = t // totp.interval
            if last_counter is not None and counter <= last_counter:
                return None
            return counter
    return None


# ---------- En-têtes HTTP ----------
CSP = (
    "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; "
    "object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'"
)


def set_security_headers(response):
    response.headers.setdefault("Content-Security-Policy", CSP)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "same-origin")
    if request.endpoint and not request.endpoint.startswith("static"):
        response.headers.setdefault("Cache-Control", "no-store")  # pas de pages privées en cache
    return response
