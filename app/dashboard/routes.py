from flask import Blueprint, render_template

from app.auth.decorators import login_required
from app.models import SecurityEvent


dashboard_bp = Blueprint("dashboard", __name__)


@dashboard_bp.get("/dashboard")
@login_required
def index():
    total_events = SecurityEvent.query.count()
    failed_logins = SecurityEvent.query.filter_by(
        event_type="AUTH_FAILURE",
    ).count()
    access_denied = SecurityEvent.query.filter_by(
        event_type="UNAUTHORIZED_ACCESS",
    ).count()
    high_critical_events = SecurityEvent.query.filter(
        SecurityEvent.severity.in_(("HIGH", "CRITICAL")),
    ).count()
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
        total_events=total_events,
        failed_logins=failed_logins,
        access_denied=access_denied,
        high_critical_events=high_critical_events,
        recent_events=recent_events,
    )
