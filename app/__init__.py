import os
from datetime import timedelta

import click
from dotenv import load_dotenv
from flask import Flask, flash, redirect, render_template, request

from .extensions import csrf, db, limiter, login_manager

load_dotenv()


def create_app():
    app = Flask(__name__)
    app.config["SECRET_KEY"] = os.environ["SECRET_KEY"]
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///app.db"  # -> instance/app.db
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    # Cookies : inaccessibles au JavaScript, non envoyés depuis un autre site,
    # et en HTTPS uniquement quand COOKIE_SECURE=1 (production)
    secure = os.environ.get("COOKIE_SECURE", "0") == "1"
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    app.config["SESSION_COOKIE_SECURE"] = secure
    app.config["REMEMBER_COOKIE_HTTPONLY"] = True
    app.config["REMEMBER_COOKIE_SAMESITE"] = "Lax"
    app.config["REMEMBER_COOKIE_SECURE"] = secure
    app.config["REMEMBER_COOKIE_DURATION"] = timedelta(days=7)

    os.makedirs(app.instance_path, exist_ok=True)

    db.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)
    limiter.init_app(app)

    from . import models  # noqa: F401  (enregistre les tables)
    from .account import bp as account_bp
    from .admin import bp as admin_bp
    from .auth import bp as auth_bp
    from .routes import bp as main_bp
    from .security import log_event, set_security_headers

    app.register_blueprint(auth_bp)
    app.register_blueprint(main_bp)
    app.register_blueprint(account_bp)
    app.register_blueprint(admin_bp)

    app.after_request(set_security_headers)

    @app.errorhandler(403)
    def forbidden(e):
        return render_template("403.html"), 403

    @app.errorhandler(429)
    def too_many_requests(e):
        log_event("rate_limited", details=request.path)
        flash("Trop de tentatives. Réessayez dans une minute.", "error")
        return redirect(request.path), 303

    @app.cli.command("create-admin")
    @click.argument("email")
    def create_admin(email):
        """Crée un administrateur, ou promeut un compte existant."""
        email = email.lower().strip()
        user = models.User.query.filter_by(email=email).first()
        if user is None:
            name = click.prompt("Nom")
            password = click.prompt("Mot de passe", hide_input=True, confirmation_prompt=True)
            if len(password) < 8:
                raise click.ClickException("8 caractères minimum.")
            user = models.User(name=name, email=email)
            user.set_password(password)
            db.session.add(user)
        user.role = "admin"
        db.session.commit()
        click.echo(f"{email} est administrateur. La MFA sera configurée à sa 1re connexion.")

    with app.app_context():
        db.create_all()

    return app
