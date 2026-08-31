from flask import Blueprint, render_template

from app.auth.decorators import login_required


dashboard_bp = Blueprint("dashboard", __name__)


@dashboard_bp.get("/dashboard")
@login_required
def index():
    return render_template("dashboard.html")