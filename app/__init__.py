import os

from dotenv import load_dotenv
from flask import Flask, redirect, url_for

from app.commands import register_commands
from app.extensions import db, limiter


def create_app():
    load_dotenv()

    app = Flask(__name__)

    app.config["SECRET_KEY"] = os.getenv("SECRET_KEY")
    app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv(
        "DATABASE_URL",
        "sqlite:///secureops.db",
    )
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["RATELIMIT_STORAGE_URI"] = os.getenv(
        "RATELIMIT_STORAGE_URI",
        "memory://",
    )

    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

    db.init_app(app)
    limiter.init_app(app)

    from app.models import SecurityEvent, User  # noqa: F401

    register_commands(app)

    with app.app_context():
        db.create_all()

    from app.auth.routes import auth_bp
    from app.dashboard.routes import dashboard_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)

    @app.get("/")
    def index():
        return redirect(url_for("auth.login"))

    return app
