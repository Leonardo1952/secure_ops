from datetime import datetime, timedelta, timezone

from app import create_app
from app.extensions import db
from app.models import SecurityEvent, User


def create_test_app(monkeypatch):
    monkeypatch.setenv("SECRET_KEY", "test-secret-key")
    monkeypatch.setenv("DATABASE_URL", "sqlite:///:memory:")

    app = create_app()
    app.config.update(
        TESTING=True,
        WTF_CSRF_ENABLED=False,
        RATELIMIT_ENABLED=False,
    )

    with app.app_context():
        db.drop_all()
        db.create_all()

    return app


def create_user():
    user = User(username="admin")
    user.set_password("SecurePassword123!")
    db.session.add(user)
    db.session.commit()

    return user.id


def authenticate(client, user_id):
    with client.session_transaction() as session:
        session["user_id"] = user_id


def create_event(
    event_type,
    severity,
    description,
    created_at=None,
    source_ip="127.0.0.1",
):
    event = SecurityEvent(
        event_type=event_type,
        severity=severity,
        source_ip=source_ip,
        description=description,
        created_at=created_at or datetime.now(timezone.utc),
    )
    db.session.add(event)
    db.session.commit()

    return event


def test_dashboard_without_events_renders_zero_indicators(monkeypatch):
    app = create_test_app(monkeypatch)
    client = app.test_client()

    with app.app_context():
        user_id = create_user()

    authenticate(client, user_id)

    response = client.get("/dashboard")

    assert response.status_code == 200
    assert b"Security Monitoring Dashboard" in response.data
    assert b'data-testid="total-events">0</strong>' in response.data
    assert b'data-testid="failed-logins">0</strong>' in response.data
    assert b'data-testid="access-denied">0</strong>' in response.data
    assert b'data-testid="high-critical-events">0</strong>' in response.data
    assert b"No security events recorded." in response.data


def test_dashboard_renders_security_events(monkeypatch):
    app = create_test_app(monkeypatch)
    client = app.test_client()

    with app.app_context():
        user_id = create_user()
        create_event("AUTH_FAILURE", "MEDIUM", "Invalid authentication attempt.")
        create_event("AUTH_SUCCESS", "INFO", "Successful authentication.")
        create_event(
            "UNAUTHORIZED_ACCESS",
            "HIGH",
            "Attempt to access protected resource.",
        )

    authenticate(client, user_id)
    response = client.get("/dashboard")

    assert response.status_code == 200
    assert b"AUTH_FAILURE" in response.data
    assert b"AUTH_SUCCESS" in response.data
    assert b"UNAUTHORIZED_ACCESS" in response.data
    assert b"Invalid authentication attempt." in response.data
    assert b"Successful authentication." in response.data
    assert b"Attempt to access protected resource." in response.data


def test_dashboard_renders_expected_counters(monkeypatch):
    app = create_test_app(monkeypatch)
    client = app.test_client()

    with app.app_context():
        user_id = create_user()
        create_event("AUTH_FAILURE", "MEDIUM", "Failed login 1.")
        create_event("AUTH_FAILURE", "HIGH", "Failed login 2.")
        create_event("AUTH_SUCCESS", "INFO", "Successful login.")
        create_event("UNAUTHORIZED_ACCESS", "HIGH", "Denied access.")
        create_event("LOGOUT", "CRITICAL", "Critical logout event.")

    authenticate(client, user_id)
    response = client.get("/dashboard")

    assert response.status_code == 200
    assert b'data-testid="total-events">5</strong>' in response.data
    assert b'data-testid="failed-logins">2</strong>' in response.data
    assert b'data-testid="access-denied">1</strong>' in response.data
    assert b'data-testid="high-critical-events">3</strong>' in response.data


def test_dashboard_limits_recent_events_to_ten(monkeypatch):
    app = create_test_app(monkeypatch)
    client = app.test_client()
    base_time = datetime(2026, 8, 31, 18, 0, 0, tzinfo=timezone.utc)

    with app.app_context():
        user_id = create_user()
        for index in range(12):
            create_event(
                "AUTH_FAILURE",
                "MEDIUM",
                f"Recent event {index}.",
                created_at=base_time + timedelta(minutes=index),
            )

    authenticate(client, user_id)
    response = client.get("/dashboard")

    assert response.status_code == 200
    assert b"Recent event 11." in response.data
    assert b"Recent event 10." in response.data
    assert b"Recent event 2." in response.data
    assert b"Recent event 1." not in response.data
    assert b"Recent event 0." not in response.data


def test_dashboard_remains_protected(monkeypatch):
    app = create_test_app(monkeypatch)
    client = app.test_client()

    response = client.get("/dashboard")

    assert response.status_code == 302
    assert response.headers["Location"] == "/login"
