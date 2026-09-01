from datetime import datetime, timedelta, timezone

from sqlalchemy import func

from app.models import SecurityEvent


SEVERITIES = ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL")


def get_dashboard_metrics(now=None):
    now = now or datetime.now(timezone.utc)
    last_24h = now - timedelta(hours=24)

    severity_counts = {
        severity: 0
        for severity in SEVERITIES
    }
    severity_counts.update(
        dict(
            SecurityEvent.query.with_entities(
                SecurityEvent.severity,
                func.count(SecurityEvent.id),
            )
            .group_by(SecurityEvent.severity)
            .all()
        )
    )

    event_type_distribution = [
        {"event_type": event_type, "count": count}
        for event_type, count in (
            SecurityEvent.query.with_entities(
                SecurityEvent.event_type,
                func.count(SecurityEvent.id),
            )
            .group_by(SecurityEvent.event_type)
            .order_by(SecurityEvent.event_type.asc())
            .all()
        )
    ]

    top_source_ips = [
        {"source_ip": source_ip, "count": count}
        for source_ip, count in (
            SecurityEvent.query.with_entities(
                SecurityEvent.source_ip,
                func.count(SecurityEvent.id),
            )
            .filter(SecurityEvent.source_ip.isnot(None))
            .group_by(SecurityEvent.source_ip)
            .order_by(func.count(SecurityEvent.id).desc(), SecurityEvent.source_ip.asc())
            .limit(5)
            .all()
        )
    ]

    events_over_time = [
        {"hour": hour, "count": count}
        for hour, count in (
            SecurityEvent.query.with_entities(
                func.strftime("%Y-%m-%d %H:00:00", SecurityEvent.created_at),
                func.count(SecurityEvent.id),
            )
            .filter(SecurityEvent.created_at >= last_24h)
            .group_by(func.strftime("%Y-%m-%d %H:00:00", SecurityEvent.created_at))
            .order_by(func.strftime("%Y-%m-%d %H:00:00", SecurityEvent.created_at).asc())
            .all()
        )
    ]

    return {
        "total_events": SecurityEvent.query.count(),
        "events_last_24h": SecurityEvent.query.filter(
            SecurityEvent.created_at >= last_24h,
        ).count(),
        "failed_logins": SecurityEvent.query.filter_by(
            event_type="AUTH_FAILURE",
        ).count(),
        "unauthorized_access": SecurityEvent.query.filter_by(
            event_type="UNAUTHORIZED_ACCESS",
        ).count(),
        "high_critical_events": SecurityEvent.query.filter(
            SecurityEvent.severity.in_(("HIGH", "CRITICAL")),
        ).count(),
        "unique_source_ips": SecurityEvent.query.with_entities(
            SecurityEvent.source_ip,
        )
        .filter(SecurityEvent.source_ip.isnot(None))
        .distinct()
        .count(),
        "rate_limit_hits": SecurityEvent.query.filter_by(
            event_type="RATE_LIMIT_EXCEEDED",
        ).count(),
        "severity_distribution": [
            {"severity": severity, "count": severity_counts[severity]}
            for severity in SEVERITIES
        ],
        "event_type_distribution": event_type_distribution,
        "top_source_ips": top_source_ips,
        "events_over_time": events_over_time,
    }
