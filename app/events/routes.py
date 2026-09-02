from flask import Blueprint, render_template, request
from sqlalchemy import or_

from app.auth.decorators import login_required
from app.models import SecurityEvent


events_bp = Blueprint("events", __name__)

VALID_SEVERITIES = ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL")
PER_PAGE = 10


@events_bp.get("/events")
@login_required
def index():
    selected_severity = request.args.get("severity", "").upper()
    selected_type = request.args.get("type", "")
    search = request.args.get("q", "").strip()
    page = request.args.get("page", 1, type=int)

    query = SecurityEvent.query

    if selected_severity in VALID_SEVERITIES:
        query = query.filter_by(severity=selected_severity)
    else:
        selected_severity = ""

    if selected_type:
        query = query.filter_by(event_type=selected_type)

    if search:
        search_term = f"%{search}%"
        query = query.filter(
            or_(
                SecurityEvent.event_type.ilike(search_term),
                SecurityEvent.source_ip.ilike(search_term),
                SecurityEvent.description.ilike(search_term),
            )
        )

    event_types = [
        event_type
        for event_type, in db_event_types_query()
    ]

    pagination = query.order_by(
        SecurityEvent.created_at.desc(),
        SecurityEvent.id.desc(),
    ).paginate(
        page=page,
        per_page=PER_PAGE,
        error_out=False,
    )

    return render_template(
        "events.html",
        events=pagination.items,
        pagination=pagination,
        severities=VALID_SEVERITIES,
        event_types=event_types,
        selected_severity=selected_severity,
        selected_type=selected_type,
        search=search,
        show_nav=True,
    )


def db_event_types_query():
    return (
        SecurityEvent.query.with_entities(SecurityEvent.event_type)
        .distinct()
        .order_by(SecurityEvent.event_type.asc())
        .all()
    )
