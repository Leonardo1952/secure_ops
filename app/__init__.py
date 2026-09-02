import os
from datetime import datetime, timezone

from dotenv import load_dotenv
from flask import Flask, jsonify, redirect, render_template, request, url_for
from flask_limiter.errors import RateLimitExceeded
from werkzeug.middleware.proxy_fix import ProxyFix

from app.commands import register_commands
from app.events.service import record_security_event
from app.extensions import csrf, db, limiter
from app.security import get_security_status
from app.version import APP_VERSION


def create_app():
    load_dotenv()

    app = Flask(__name__)
    app.wsgi_app = ProxyFix(
        app.wsgi_app,
        x_for=1,
        x_proto=1,
        x_host=1,
        x_prefix=0,
    )
    app_env = os.getenv("APP_ENV", "development")
    secret_key = os.getenv("SECRET_KEY")
    insecure_secret_placeholder = os.getenv(
        "INSECURE_SECRET_PLACEHOLDER",
        "change" + "-me",
    )

    if app_env == "production" and (
        not secret_key or secret_key == insecure_secret_placeholder
    ):
        raise RuntimeError("SECRET_KEY must be configured for production.")

    app.config["APP_ENV"] = app_env
    app.config["SECRET_KEY"] = secret_key
    app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv(
        "DATABASE_URL",
        "sqlite:///secureops.db",
    )
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["RATELIMIT_STORAGE_URI"] = os.getenv(
        "RATELIMIT_STORAGE_URI",
        "memory://",
    )
    app.config["APP_VERSION"] = APP_VERSION
    app.config["SECURITY_TLS"] = os.getenv("SECURITY_TLS", "TLS 1.2 / 1.3")
    app.config["SECURITY_PQC"] = os.getenv("SECURITY_PQC", "X25519MLKEM768")
    app.config["SECURITY_SSL_LABS"] = os.getenv("SECURITY_SSL_LABS", "A+")

    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    app.config["SESSION_COOKIE_SECURE"] = app_env == "production"

    db.init_app(app)
    csrf.init_app(app)
    limiter.init_app(app)

    from app.models import SecurityEvent, User  # noqa: F401

    register_commands(app)

    with app.app_context():
        db.create_all()

    from app.auth.routes import auth_bp
    from app.dashboard.routes import dashboard_bp
    from app.events.routes import events_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(events_bp)

    @app.get("/")
    def index():
        return redirect(url_for("auth.login"))

    @app.get("/health")
    def health():
        return jsonify(
            {
                "status": "healthy",
                "application": "SecureOps",
                "environment": app.config["APP_ENV"],
                "version": app.config["APP_VERSION"],
            }
        )

    @app.context_processor
    def inject_app_metadata():
        return {
            "app_version": app.config["APP_VERSION"],
            "current_time": datetime.now(timezone.utc),
            "security_status": get_security_status(app),
        }

    @app.after_request
    def add_security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self'; "
            "object-src 'none'; "
            "base-uri 'self'; "
            "frame-ancestors 'none'; "
            "form-action 'self'"
        )

        if app.config["APP_ENV"] == "production" and request.is_secure:
            response.headers["Strict-Transport-Security"] = (
                "max-age=31536000; includeSubDomains"
            )

        return response

    @app.errorhandler(403)
    def forbidden(error):
        return render_template("error.html", status_code=403, message="Forbidden"), 403

    @app.errorhandler(404)
    def not_found(error):
        return render_template("error.html", status_code=404, message="Not found"), 404

    @app.errorhandler(RateLimitExceeded)
    def rate_limit_exceeded(error):
        if request.endpoint == "auth.login" and request.method == "POST":
            record_security_event(
                event_type="RATE_LIMIT_EXCEEDED",
                severity="HIGH",
                description="Authentication rate limit exceeded.",
            )

        return (
            render_template(
                "error.html",
                status_code=429,
                message="Too many requests.",
            ),
            429,
        )

    return app
