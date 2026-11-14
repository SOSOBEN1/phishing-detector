"""Gestion du compte : changement de mot de passe et réinitialisation de la MFA."""
from flask import Blueprint, flash, redirect, render_template, session, url_for
from flask_login import current_user, login_required, logout_user

from .extensions import db, limiter
from .forms import ChangePasswordForm, ResetMFAForm
from .security import log_event

bp = Blueprint("account", __name__, url_prefix="/account")


@bp.route("/", methods=["GET", "POST"])
@login_required
@limiter.limit("5 per minute", methods=["POST"])
def settings():
    pwd_form = ChangePasswordForm(prefix="pwd")
    mfa_form = ResetMFAForm(prefix="mfa")

    if pwd_form.submit.data and pwd_form.validate_on_submit():
        if not current_user.check_password(pwd_form.current.data):
            log_event("password_change_failed", current_user)
            flash("Mot de passe actuel incorrect.", "error")
        else:
            current_user.set_password(pwd_form.password.data)
            db.session.commit()
            log_event("password_changed", current_user)
            flash("Mot de passe modifié.", "success")
            return redirect(url_for("account.settings"))

    elif mfa_form.submit.data and mfa_form.validate_on_submit():
        if not current_user.check_password(mfa_form.password.data):
            log_event("mfa_reset_failed", current_user)
            flash("Mot de passe incorrect.", "error")
        else:
            current_user.otp_secret = None
            current_user.mfa_enabled = False
            current_user.otp_last_counter = None
            db.session.commit()
            log_event("mfa_reset", current_user)
            logout_user()
            session.clear()
            flash("Double authentification réinitialisée : reconnectez-vous pour la configurer.", "success")
            return redirect(url_for("auth.login"))

    return render_template("account.html", pwd_form=pwd_form, mfa_form=mfa_form)
