from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_login import LoginManager
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect

db = SQLAlchemy()
csrf = CSRFProtect()
login_manager = LoginManager()
login_manager.login_view = "auth.login"
login_manager.login_message = "Veuillez vous connecter pour accéder à cette page."
login_manager.login_message_category = "error"
login_manager.session_protection = "strong"  # session invalidée si l'IP/le navigateur change
# Limitation du nombre de requêtes (anti force brute), en mémoire pour ce projet
limiter = Limiter(key_func=get_remote_address, storage_uri="memory://")