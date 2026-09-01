from flask import Blueprint, flash, redirect, render_template, session, url_for

from app.auth.forms import LoginForm
from app.events.service import record_security_event
from app.extensions import limiter
from app.models import User


auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute", methods=["POST"])
def login():
    if session.get("user_id"):
        return redirect(url_for("dashboard.index"))

    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(
            username=form.username.data
        ).first()

        if user and user.check_password(form.password.data):
            session.clear()
            session["user_id"] = user.id
            record_security_event(
                event_type="AUTH_SUCCESS",
                severity="INFO",
                description="Successful authentication.",
            )

            return redirect(url_for("dashboard.index"))

        record_security_event(
            event_type="AUTH_FAILURE",
            severity="MEDIUM",
            description="Invalid authentication attempt.",
        )
        flash("Invalid username or password.", "error")

    return render_template("login.html", form=form)


@auth_bp.post("/logout")
def logout():
    session.clear()
    record_security_event(
        event_type="LOGOUT",
        severity="INFO",
        description="User session terminated.",
    )

    return redirect(url_for("auth.login"))
