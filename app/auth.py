import base64
import io
import time

import pyotp
import qrcode
import qrcode.image.svg
from flask import Blueprint, flash, redirect, render_template, request, session, url_for
from flask_login import current_user, login_required, login_user, logout_user

from .extensions import db, limiter
from .forms import LoginForm, OTPForm, RegisterForm
from .models import User
from .security import log_event, verify_totp

bp = Blueprint("auth", __name__)

MFA_PENDING_TTL = 300  # 5 min pour saisir le code après le mot de passe
LOGIN_LIMIT = "5 per minute"  # anti force brute (par adresse IP)


def _safe_next(target):
    """N'accepte que des chemins internes (évite les redirections ouvertes)."""
    if target and target.startswith("/") and not target.startswith("//"):
        return target
    return None


# ---------- Étape intermédiaire : mot de passe OK, code MFA pas encore saisi ----------
def _start_mfa(user, remember, next_url):
    session.clear()  # nouvelle session : évite la fixation de session
    session["mfa_user_id"] = user.id
    session["mfa_remember"] = bool(remember)
    session["mfa_next"] = next_url
    session["mfa_started"] = int(time.time())


def _pending_user():
    """Utilisateur ayant validé son mot de passe il y a moins de 5 min."""
    uid, started = session.get("mfa_user_id"), session.get("mfa_started", 0)
    if not uid or time.time() - started > MFA_PENDING_TTL:
        return None
    user = db.session.get(User, uid)
    return user if user and user.is_active else None


def _finish_login(user):
    remember, next_url = session.get("mfa_remember", False), session.get("mfa_next")
    session.clear()
    login_user(user, remember=remember)
    log_event("login_success", user)
    return redirect(next_url or url_for("main.dashboard"))


def _qr_data_uri(text):
    """QR code en SVG, encodé en data: URI (affiché via <img>, compatible CSP)."""
    buf = io.BytesIO()
    qrcode.make(text, image_factory=qrcode.image.svg.SvgPathImage).save(buf)
    return "data:image/svg+xml;base64," + base64.b64encode(buf.getvalue()).decode()


@bp.route("/login", methods=["GET", "POST"])
@limiter.limit(LOGIN_LIMIT, methods=["POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("main.dashboard"))
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data.lower().strip()
        user = User.query.filter_by(email=email).first()
        if user and user.check_password(form.password.data):
            if not user.is_active:
                log_event("login_blocked", user, details="compte désactivé")
                flash("Ce compte est désactivé. Contactez un administrateur.", "error")
                return render_template("auth/login.html", form=form)
            log_event("login_password_ok", user)
            _start_mfa(user, form.remember.data, _safe_next(request.args.get("next")))
            # 1re connexion : configuration de la MFA, sinon saisie du code
            return redirect(url_for("auth.mfa_verify" if user.mfa_enabled else "auth.mfa_setup"))
        log_event("login_failed", email=email)
        flash("Adresse e-mail ou mot de passe incorrect.", "error")
    return render_template("auth/login.html", form=form)


@bp.route("/login/mfa", methods=["GET", "POST"])
@limiter.limit(LOGIN_LIMIT, methods=["POST"])
def mfa_verify():
    user = _pending_user()
    if user is None:
        flash("Session expirée, reconnectez-vous.", "error")
        return redirect(url_for("auth.login"))
    if not user.mfa_enabled:
        return redirect(url_for("auth.mfa_setup"))
    form = OTPForm()
    if form.validate_on_submit():
        counter = verify_totp(user.otp_secret, form.code.data, user.otp_last_counter)
        if counter is not None:
            user.otp_last_counter = counter
            db.session.commit()
            return _finish_login(user)
        log_event("mfa_failed", user)
        flash("Code incorrect ou expiré.", "error")
    return render_template("auth/mfa.html", form=form, setup=False)


@bp.route("/login/mfa/setup", methods=["GET", "POST"])
@limiter.limit(LOGIN_LIMIT, methods=["POST"])
def mfa_setup():
    user = _pending_user()
    if user is None:
        flash("Session expirée, reconnectez-vous.", "error")
        return redirect(url_for("auth.login"))
    if user.mfa_enabled:
        return redirect(url_for("auth.mfa_verify"))
    # Le secret n'est enregistré qu'après la saisie d'un premier code valide
    secret = session.get("mfa_setup_secret") or pyotp.random_base32()
    session["mfa_setup_secret"] = secret
    form = OTPForm()
    if form.validate_on_submit():
        counter = verify_totp(secret, form.code.data)
        if counter is not None:
            user.otp_secret, user.mfa_enabled, user.otp_last_counter = secret, True, counter
            db.session.commit()
            log_event("mfa_enabled", user)
            return _finish_login(user)
        log_event("mfa_failed", user, details="configuration")
        flash("Code incorrect. Vérifiez l'heure de votre téléphone et réessayez.", "error")
    uri = pyotp.TOTP(secret).provisioning_uri(name=user.email, issuer_name="SafeURL")
    return render_template("auth/mfa.html", form=form, setup=True, qr=_qr_data_uri(uri), secret=secret)


@bp.route("/register", methods=["GET", "POST"])
@limiter.limit(LOGIN_LIMIT, methods=["POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("main.dashboard"))
    form = RegisterForm()
    if form.validate_on_submit():
        user = User(name=form.name.data.strip(), email=form.email.data.lower().strip())
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        log_event("register", user)
        flash("Compte créé. Connectez-vous pour configurer la double authentification.", "success")
        return redirect(url_for("auth.login"))
    return render_template("auth/register.html", form=form)


@bp.route("/logout", methods=["POST"])
@login_required
def logout():
    log_event("logout", current_user)
    logout_user()
    session.clear()
    flash("Vous êtes déconnectée.", "success")
    return redirect(url_for("auth.login"))
