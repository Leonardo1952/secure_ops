from flask import Blueprint, current_app, render_template

from app.auth.decorators import login_required
from app.dashboard.service import get_dashboard_metrics
from app.models import SecurityEvent
from app.security import get_security_status


dashboard_bp = Blueprint("dashboard", __name__)


@dashboard_bp.get("/dashboard")
@login_required
def index():
    metrics = get_dashboard_metrics()
    recent_events = (
        SecurityEvent.query.order_by(
            SecurityEvent.created_at.desc(),
            SecurityEvent.id.desc(),
        )
        .limit(10)
        .all()
    )

    return render_template(
        "dashboard.html",
        dashboard_metrics=metrics,
        total_events=metrics["total_events"],
        failed_logins=metrics["failed_logins"],
        access_denied=metrics["unauthorized_access"],
        high_critical_events=metrics["high_critical_events"],
        security_status=get_security_status(current_app),
        recent_events=recent_events,
        show_nav=True,
    )
