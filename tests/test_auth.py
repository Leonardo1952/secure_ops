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


def get_last_event():
    return SecurityEvent.query.order_by(SecurityEvent.id.desc()).first()


def create_user(username="admin", password="SecurePassword123!"):
    user = User(username=username)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()

    return user


def test_dashboard_without_authentication_records_unauthorized_access(monkeypatch):
    app = create_test_app(monkeypatch)
    client = app.test_client()

    response = client.get("/dashboard")

    assert response.status_code == 302
    assert response.headers["Location"] == "/login"

    with app.app_context():
        event = get_last_event()

        assert event.event_type == "UNAUTHORIZED_ACCESS"
        assert event.severity == "HIGH"
        assert event.description == "Attempt to access protected resource."


def test_valid_login_records_auth_success(monkeypatch):
    app = create_test_app(monkeypatch)

    with app.app_context():
        create_user()

    client = app.test_client()
    response = client.post(
        "/login",
        data={
            "username": "admin",
            "password": "SecurePassword123!",
        },
    )

    assert response.status_code == 302
    assert response.headers["Location"] == "/dashboard"

    with app.app_context():
        event = get_last_event()

        assert event.event_type == "AUTH_SUCCESS"
        assert event.severity == "INFO"
        assert event.description == "Successful authentication."


def test_invalid_login_records_auth_failure(monkeypatch):
    app = create_test_app(monkeypatch)
    client = app.test_client()

    response = client.post(
        "/login",
        data={
            "username": "admin",
            "password": "wrong-password",
        },
    )

    assert response.status_code == 200

    with app.app_context():
        event = get_last_event()

        assert event.event_type == "AUTH_FAILURE"
        assert event.severity == "MEDIUM"
        assert event.description == "Invalid authentication attempt."


def test_logout_clears_session_and_records_logout(monkeypatch):
    app = create_test_app(monkeypatch)
    client = app.test_client()

    with app.app_context():
        user = create_user()
        user_id = user.id

    with client.session_transaction() as session:
        session["user_id"] = user_id

    response = client.post("/logout")

    assert response.status_code == 302
    assert response.headers["Location"] == "/login"

    with client.session_transaction() as session:
        assert "user_id" not in session

    with app.app_context():
        event = get_last_event()

        assert event.event_type == "LOGOUT"
        assert event.severity == "INFO"
        assert event.description == "User session terminated."
