import os

from dotenv import load_dotenv
from flask import Flask

from app.commands import register_commands
from app.extensions import db


def create_app():
    load_dotenv()

    app = Flask(__name__)

    app.config["SECRET_KEY"] = os.getenv("SECRET_KEY")
    app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv(
        "DATABASE_URL",
        "sqlite:///secureops.db",
    )
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    db.init_app(app)

    from app.models import User  # noqa: F401

    register_commands(app)

    with app.app_context():
        db.create_all()

    @app.get("/")
    def index():
        return {
            "application": "SecureOps",
            "status": "running",
        }

    return app