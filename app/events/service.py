from app.extensions import db
from app.models import SecurityEvent
from app.request_utils import get_client_ip


def record_security_event(
    event_type,
    severity,
    description,
    source_ip=None,
):
    event = SecurityEvent(
        event_type=event_type,
        severity=severity,
        source_ip=source_ip or get_client_ip(),
        description=description,
    )

    db.session.add(event)
    db.session.commit()

    return event
