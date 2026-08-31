from flask import Blueprint, flash, redirect, render_template, session, url_for

from app.auth.forms import LoginForm
from app.models import User


auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/login", methods=["GET", "POST"])
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

            return redirect(url_for("dashboard.index"))

        flash("Invalid username or password.", "error")

    return render_template("login.html", form=form)


@auth_bp.post("/logout")
def logout():
    session.clear()

    return redirect(url_for("auth.login"))