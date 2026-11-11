from datetime import timedelta, timezone

from flask import Blueprint, abort, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from .analyzer import analyze_url, explain
from .extensions import db
from .forms import AnalyzeForm
from .models import Analysis

bp = Blueprint("main", __name__)

ALGIERS = timezone(timedelta(hours=1))  # UTC+1 toute l'année, pas d'heure d'été


@bp.app_template_filter("localdt")
def localdt(value, fmt="%d/%m/%Y %H:%M"):
    if value is None:
        return ""
    if value.tzinfo is None:  # SQLite ne garde pas le fuseau : on stocke en UTC
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(ALGIERS).strftime(fmt)


@bp.route("/")
def index():
    if current_user.is_authenticated:
        return redirect(url_for("main.dashboard"))
    return redirect(url_for("auth.login"))


@bp.route("/dashboard")
@login_required
def dashboard():
    q = Analysis.query.filter_by(user_id=current_user.id)
    total = q.count()
    phishing = q.filter_by(label="Phishing").count()
    recent = q.order_by(Analysis.created_at.desc()).limit(3).all()
    return render_template(
        "dashboard.html",
        form=AnalyzeForm(),
        total=total,
        phishing=phishing,
        safe=total - phishing,
        recent=recent,
    )


@bp.route("/analyze", methods=["GET", "POST"])
@login_required
def analyze():
    form = AnalyzeForm()
    if form.validate_on_submit():
        url = form.url.data.strip()
        try:
            result = analyze_url(url)
        except FileNotFoundError:
            flash("Modèle IA introuvable : lancez d'abord python app/ml/03_training.py.", "error")
            return render_template("analyze.html", form=form, analysis=None)
        a = Analysis(
            user_id=current_user.id,
            url=url,
            label=result["label"],
            probability=result["probability"],
        )
        db.session.add(a)
        db.session.commit()
        return redirect(url_for("main.analysis_detail", analysis_id=a.id))
    return render_template("analyze.html", form=form, analysis=None)


@bp.route("/analysis/<int:analysis_id>")
@login_required
def analysis_detail(analysis_id):
    a = db.session.get(Analysis, analysis_id)
    if a is None or a.user_id != current_user.id:
        abort(404)
    return render_template(
        "analyze.html",
        form=AnalyzeForm(url=a.url),
        analysis=a,
        is_phishing=(a.label == "Phishing"),
        score=round(a.probability * 100),
        reasons=explain(a.url),
    )


@bp.route("/history")
@login_required
def history():
    page = request.args.get("page", 1, type=int)
    pagination = (
        Analysis.query.filter_by(user_id=current_user.id)
        .order_by(Analysis.created_at.desc())
        .paginate(page=page, per_page=10, error_out=False)
    )
    return render_template("history.html", pagination=pagination)