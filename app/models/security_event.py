from datetime import datetime, timezone

from app.extensions import db


class SecurityEvent(db.Model):
    __tablename__ = "security_events"

    id = db.Column(db.Integer, primary_key=True)

    event_type = db.Column(
        db.String(50),
        nullable=False,
    )

    severity = db.Column(
        db.String(20),
        nullable=False,
    )

    source_ip = db.Column(
        db.String(45),
        nullable=True,
    )

    description = db.Column(
        db.String(255),
        nullable=False,
    )

    created_at = db.Column(
        db.DateTime,
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
