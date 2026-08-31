from app.extensions import db
from app.models import SecurityEvent


def record_security_event(
    event_type,
    severity,
    source_ip,
    description,
):
    event = SecurityEvent(
        event_type=event_type,
        severity=severity,
        source_ip=source_ip,
        description=description,
    )

    db.session.add(event)
    db.session.commit()

    return event
