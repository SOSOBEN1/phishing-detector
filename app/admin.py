"""Espace administrateur : gestion des comptes et journaux de sécurité (RBAC)."""
from flask import Blueprint, abort, flash, redirect, render_template, request, url_for
from flask_login import current_user

from .extensions import db
from .models import SecurityLog, User
from .security import admin_required, log_event

bp = Blueprint("admin", __name__, url_prefix="/admin")

ROLES = ("user", "admin")


@bp.route("/users")
@admin_required
def users():
    return render_template("admin/users.html", users=User.query.order_by(User.created_at).all(), roles=ROLES)


@bp.route("/users/<int:user_id>/<action>", methods=["POST"])
@admin_required
def user_action(user_id, action):
    user = db.session.get(User, user_id) or abort(404)
    if user.id == current_user.id:
        # Évite qu'un admin se retire ses propres droits ou se bloque
        flash("Vous ne pouvez pas modifier votre propre compte depuis cette page.", "error")
        return redirect(url_for("admin.users"))

    if action == "role":
        role = request.form.get("role")
        if role not in ROLES:
            abort(400)
        user.role = role
        log_event("admin_role_change", current_user, details=f"{user.email} -> {role}")
        flash(f"Rôle de {user.email} : {role}.", "success")
    elif action == "toggle":
        user.is_active = not user.is_active
        state = "activé" if user.is_active else "désactivé"
        log_event("admin_toggle_active", current_user, details=f"{user.email} {state}")
        flash(f"Compte {user.email} {state}.", "success")
    elif action == "reset-mfa":
        user.otp_secret, user.mfa_enabled, user.otp_last_counter = None, False, None
        log_event("admin_mfa_reset", current_user, details=user.email)
        flash(f"MFA de {user.email} réinitialisée.", "success")
    elif action == "delete":
        email = user.email
        SecurityLog.query.filter_by(user_id=user.id).update({"user_id": None})  # garde l'historique
        db.session.delete(user)
        log_event("admin_delete_user", current_user, details=email)
        flash(f"Compte {email} supprimé.", "success")
    else:
        abort(404)
    db.session.commit()
    return redirect(url_for("admin.users"))


@bp.route("/logs")
@admin_required
def logs():
    page = request.args.get("page", 1, type=int)
    event = request.args.get("event", "")
    q = SecurityLog.query
    if event:
        q = q.filter_by(event=event)
    pagination = q.order_by(SecurityLog.created_at.desc()).paginate(page=page, per_page=25, error_out=False)
    events = [e for (e,) in db.session.query(SecurityLog.event).distinct().order_by(SecurityLog.event)]
    return render_template("admin/logs.html", pagination=pagination, events=events, event=event)
