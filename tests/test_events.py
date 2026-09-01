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


def test_events_without_authentication_redirects_to_login(monkeypatch):
    app = create_test_app(monkeypatch)
    client = app.test_client()

    response = client.get("/events")

    assert response.status_code == 302
    assert response.headers["Location"] == "/login"


def test_authenticated_user_can_access_events(monkeypatch):
    app = create_test_app(monkeypatch)
    client = app.test_client()

    with app.app_context():
        user_id = create_user()

    authenticate(client, user_id)
    response = client.get("/events")

    assert response.status_code == 200
    assert b"Security Events" in response.data


def test_events_list_renders_security_events(monkeypatch):
    app = create_test_app(monkeypatch)
    client = app.test_client()

    with app.app_context():
        user_id = create_user()
        create_event("AUTH_FAILURE", "MEDIUM", "Invalid authentication attempt.")
        create_event("AUTH_SUCCESS", "INFO", "Successful authentication.")

    authenticate(client, user_id)
    response = client.get("/events")

    assert response.status_code == 200
    assert b"AUTH_FAILURE" in response.data
    assert b"AUTH_SUCCESS" in response.data
    assert b"Invalid authentication attempt." in response.data
    assert b"Successful authentication." in response.data


def test_events_are_ordered_by_newest_first(monkeypatch):
    app = create_test_app(monkeypatch)
    client = app.test_client()
    older_time = datetime(2026, 8, 31, 18, 0, 0, tzinfo=timezone.utc)
    newer_time = older_time + timedelta(minutes=5)

    with app.app_context():
        user_id = create_user()
        create_event("AUTH_FAILURE", "MEDIUM", "Older event.", older_time)
        create_event("AUTH_SUCCESS", "INFO", "Newer event.", newer_time)

    authenticate(client, user_id)
    response = client.get("/events")
    html = response.data.decode()

    assert response.status_code == 200
    assert html.index("Newer event.") < html.index("Older event.")


def test_events_filter_by_severity(monkeypatch):
    app = create_test_app(monkeypatch)
    client = app.test_client()

    with app.app_context():
        user_id = create_user()
        create_event("AUTH_SUCCESS", "INFO", "Info event.")
        create_event("AUTH_FAILURE", "MEDIUM", "Medium event.")
        create_event("UNAUTHORIZED_ACCESS", "HIGH", "High event.")

    authenticate(client, user_id)
    response = client.get("/events?severity=HIGH")

    assert response.status_code == 200
    assert b"High event." in response.data
    assert b"Info event." not in response.data
    assert b"Medium event." not in response.data


def test_events_filter_by_type(monkeypatch):
    app = create_test_app(monkeypatch)
    client = app.test_client()

    with app.app_context():
        user_id = create_user()
        create_event("AUTH_SUCCESS", "INFO", "Success event.")
        create_event("AUTH_FAILURE", "MEDIUM", "Failure event.")

    authenticate(client, user_id)
    response = client.get("/events?type=AUTH_FAILURE")

    assert response.status_code == 200
    assert b"Failure event." in response.data
    assert b"Success event." not in response.data


def test_events_filter_by_severity_and_type(monkeypatch):
    app = create_test_app(monkeypatch)
    client = app.test_client()

    with app.app_context():
        user_id = create_user()
        create_event("UNAUTHORIZED_ACCESS", "HIGH", "Matching event.")
        create_event("UNAUTHORIZED_ACCESS", "MEDIUM", "Wrong severity.")
        create_event("AUTH_FAILURE", "HIGH", "Wrong type.")

    authenticate(client, user_id)
    response = client.get("/events?severity=HIGH&type=UNAUTHORIZED_ACCESS")

    assert response.status_code == 200
    assert b"Matching event." in response.data
    assert b"Wrong severity." not in response.data
    assert b"Wrong type." not in response.data


def test_events_invalid_severity_filter_does_not_error(monkeypatch):
    app = create_test_app(monkeypatch)
    client = app.test_client()

    with app.app_context():
        user_id = create_user()
        create_event("AUTH_SUCCESS", "INFO", "Visible event.")

    authenticate(client, user_id)
    response = client.get("/events?severity=INVALID")

    assert response.status_code == 200
    assert b"Visible event." in response.data


def test_events_empty_filtered_state(monkeypatch):
    app = create_test_app(monkeypatch)
    client = app.test_client()

    with app.app_context():
        user_id = create_user()
        create_event("AUTH_SUCCESS", "INFO", "Info event.")

    authenticate(client, user_id)
    response = client.get("/events?severity=CRITICAL")

    assert response.status_code == 200
    assert b"No security events found." in response.data


def test_events_pagination(monkeypatch):
    app = create_test_app(monkeypatch)
    client = app.test_client()
    base_time = datetime(2026, 8, 31, 18, 0, 0, tzinfo=timezone.utc)

    with app.app_context():
        user_id = create_user()
        for index in range(12):
            create_event(
                "AUTH_FAILURE",
                "MEDIUM",
                f"Paginated event {index}.",
                created_at=base_time + timedelta(minutes=index),
            )

    authenticate(client, user_id)
    first_page = client.get("/events?page=1")
    second_page = client.get("/events?page=2")

    assert first_page.status_code == 200
    assert first_page.data.count(b'data-testid="event-row"') == 10
    assert b"Paginated event 11." in first_page.data
    assert b"Paginated event 2." in first_page.data
    assert b"Paginated event 1." not in first_page.data

    assert second_page.status_code == 200
    assert second_page.data.count(b'data-testid="event-row"') == 2
    assert b"Paginated event 1." in second_page.data
    assert b"Paginated event 0." in second_page.data


def test_events_pagination_preserves_filters(monkeypatch):
    app = create_test_app(monkeypatch)
    client = app.test_client()
    base_time = datetime(2026, 8, 31, 18, 0, 0, tzinfo=timezone.utc)

    with app.app_context():
        user_id = create_user()
        for index in range(12):
            create_event(
                "AUTH_FAILURE",
                "HIGH",
                f"Filtered event {index}.",
                created_at=base_time + timedelta(minutes=index),
            )

    authenticate(client, user_id)
    response = client.get("/events?severity=HIGH&type=AUTH_FAILURE")

    assert response.status_code == 200
    assert b"page=2" in response.data
    assert b"severity=HIGH" in response.data
    assert b"type=AUTH_FAILURE" in response.data
