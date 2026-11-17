"""Espace administrateur : tableau de bord, comptes, analyses, modèle IA et journaux (RBAC)."""
import csv
import io
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

from flask import Blueprint, Response, abort, flash, redirect, render_template, request, url_for
from flask_login import current_user
from sqlalchemy import or_

from .extensions import db
from .models import Analysis, SecurityLog, User
from .routes import ALGIERS
from .security import admin_required, log_event

bp = Blueprint("admin", __name__, url_prefix="/admin")

ROLES = ("user", "admin")
PER_PAGE = 15
ML_DIR = Path(__file__).resolve().parent / "ml"


def _like(text):
    """Motif LIKE sûr : les caractères % et _ saisis sont traités comme du texte."""
    text = text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{text}%"


def _local(dt):
    if dt.tzinfo is None:  # SQLite ne garde pas le fuseau : valeurs stockées en UTC
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(ALGIERS)


def _read_metrics():
    """Lit les résultats écrits par app/ml/03_training.py (None si absents)."""
    path = ML_DIR / "results" / "metrics.txt"
    if not path.exists():
        return None
    text = path.read_text(encoding="utf-8")

    def num(label):
        m = re.search(label + r"[^:\n]*:\s*([0-9.]+)", text)
        return float(m.group(1)) if m else None

    legit = re.search(r"^\s*Légitime\s+(\d+)\s+(\d+)\s*$", text, re.M)
    phish = re.search(r"^\s*Phishing\s+(\d+)\s+(\d+)\s*$", text, re.M)
    values = [num("Exactitude"), num("Précision"), num("Rappel"), num("F1-score")]
    if not (legit and phish) or None in values:
        return None
    lines = text.splitlines()
    model_file = ML_DIR / "model.joblib"
    trained = _local(datetime.fromtimestamp(model_file.stat().st_mtime, tz=timezone.utc)) if model_file.exists() else None
    return {
        "accuracy": values[0], "precision": values[1], "recall": values[2], "f1": values[3],
        "tn": int(legit.group(1)), "fp": int(legit.group(2)),
        "fn": int(phish.group(1)), "tp": int(phish.group(2)),
        "title": lines[0], "split": lines[1] if len(lines) > 1 else "", "trained": trained,
    }


# ---------- Tableau de bord ----------
@bp.route("/")
@admin_required
def dashboard():
    total = Analysis.query.count()
    phishing = Analysis.query.filter_by(label="Phishing").count()
    users = User.query.count()
    mfa = User.query.filter_by(mfa_enabled=True).count()

    today = datetime.now(timezone.utc).astimezone(ALGIERS).date()
    first = today - timedelta(days=6)
    since = datetime.combine(first, datetime.min.time(), tzinfo=ALGIERS).astimezone(timezone.utc).replace(tzinfo=None)
    counts = {first + timedelta(days=i): 0 for i in range(7)}
    for (created,) in db.session.query(Analysis.created_at).filter(Analysis.created_at >= since):
        day = _local(created).date()
        if day in counts:
            counts[day] += 1
    days = [(d.strftime("%d/%m"), n) for d, n in counts.items()]

    recent = Analysis.query.filter_by(label="Phishing").order_by(Analysis.created_at.desc()).limit(5).all()
    metrics = _read_metrics()
    return render_template(
        "admin/dashboard.html",
        total=total, phishing=phishing, users=users, mfa=mfa,
        pct=round(100 * phishing / total) if total else 0,
        days=days, peak=max([n for _, n in days] + [1]),
        recent=recent, accuracy=metrics["accuracy"] if metrics else None,
    )


# ---------- Comptes ----------
@bp.route("/users")
@admin_required
def users():
    f = {k: request.args.get(k, "").strip() for k in ("q", "role", "status", "mfa")}
    q = User.query
    if f["q"]:
        like = _like(f["q"])
        q = q.filter(or_(User.name.ilike(like, escape="\\"), User.email.ilike(like, escape="\\")))
    if f["role"] in ROLES:
        q = q.filter(User.role == f["role"])
    if f["status"] in ("active", "inactive"):
        q = q.filter(User.is_active == (f["status"] == "active"))
    if f["mfa"] in ("on", "off"):
        q = q.filter(User.mfa_enabled == (f["mfa"] == "on"))
    return render_template("admin/users.html", users=q.order_by(User.created_at).all(), roles=ROLES, f=f)


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


# ---------- Toutes les analyses ----------
def _analyses_query():
    q = Analysis.query.join(User, Analysis.user_id == User.id)
    s = request.args.get("q", "").strip()
    if s:
        like = _like(s)
        q = q.filter(or_(Analysis.url.ilike(like, escape="\\"), User.name.ilike(like, escape="\\"),
                         User.email.ilike(like, escape="\\")))
    result = request.args.get("result", "")
    if result == "phishing":
        q = q.filter(Analysis.label == "Phishing")
    elif result == "safe":
        q = q.filter(Analysis.label != "Phishing")
    return q.order_by(Analysis.created_at.desc()), s, result


@bp.route("/analyses")
@admin_required
def analyses():
    q, s, result = _analyses_query()
    page = request.args.get("page", 1, type=int)
    pagination = q.paginate(page=page, per_page=PER_PAGE, error_out=False)
    return render_template("admin/analyses.html", pagination=pagination, q=s, result=result)


def _csv_cell(value):
    """Neutralise les formules (=, +, -, @) pour qu'Excel n'exécute pas une URL saisie."""
    value = str(value)
    return "'" + value if value[:1] in ("=", "+", "-", "@", "\t", "\r") else value


@bp.route("/analyses.csv")
@admin_required
def analyses_csv():
    q, _, _ = _analyses_query()
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["Date", "Utilisateur", "E-mail", "URL", "Résultat", "Score (%)"])
    for a in q.all():
        writer.writerow([_local(a.created_at).strftime("%d/%m/%Y %H:%M"), _csv_cell(a.user.name),
                         _csv_cell(a.user.email), _csv_cell(a.url), a.label, round(a.probability * 100)])
    log_event("admin_export_csv", current_user)
    return Response("\ufeff" + buf.getvalue(), mimetype="text/csv; charset=utf-8",
                    headers={"Content-Disposition": "attachment; filename=analyses.csv"})


# ---------- Modèle IA (lecture seule) ----------
@bp.route("/model")
@admin_required
def model():
    return render_template("admin/model.html", m=_read_metrics())


# ---------- Journaux de sécurité ----------
@bp.route("/logs")
@admin_required
def logs():
    page = request.args.get("page", 1, type=int)
    event = request.args.get("event", "")
    s = request.args.get("q", "").strip()
    q = SecurityLog.query
    if event:
        q = q.filter_by(event=event)
    if s:
        like = _like(s)
        q = q.filter(or_(SecurityLog.email.ilike(like, escape="\\"), SecurityLog.ip.ilike(like, escape="\\"),
                         SecurityLog.details.ilike(like, escape="\\")))
    pagination = q.order_by(SecurityLog.created_at.desc()).paginate(page=page, per_page=25, error_out=False)
    events = [e for (e,) in db.session.query(SecurityLog.event).distinct().order_by(SecurityLog.event)]
    return render_template("admin/logs.html", pagination=pagination, events=events, event=event, q=s)
