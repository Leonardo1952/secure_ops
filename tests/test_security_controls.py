from app import create_app
from app.extensions import db
from app.models import SecurityEvent, User


def create_test_app(monkeypatch, rate_limit_enabled=False, app_env="development"):
    monkeypatch.setenv("APP_ENV", app_env)
    monkeypatch.setenv("SECRET_KEY", "test-secret-key")
    monkeypatch.setenv("DATABASE_URL", "sqlite:///:memory:")
    monkeypatch.setenv("RATELIMIT_STORAGE_URI", "memory://")

    app = create_app()
    app.config.update(
        TESTING=True,
        WTF_CSRF_ENABLED=False,
        RATELIMIT_ENABLED=rate_limit_enabled,
    )

    with app.app_context():
        db.drop_all()
        db.create_all()

    return app


def create_user(username="admin", password="SecurePassword123!"):
    user = User(username=username)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()

    return user.id


def authenticate(client, user_id):
    with client.session_transaction() as session:
        session["user_id"] = user_id


def test_login_rate_limit_records_security_event(monkeypatch):
    app = create_test_app(monkeypatch, rate_limit_enabled=True)
    client = app.test_client()

    for _ in range(5):
        response = client.post(
            "/login",
            data={
                "username": "admin",
                "password": "WrongPassword123!",
            },
            environ_base={"REMOTE_ADDR": "198.51.100.10"},
        )
        assert response.status_code == 200

    response = client.post(
        "/login",
        data={
            "username": "admin",
            "password": "WrongPassword123!",
        },
        environ_base={"REMOTE_ADDR": "198.51.100.10"},
    )

    assert response.status_code == 429

    with app.app_context():
        event = SecurityEvent.query.filter_by(
            event_type="RATE_LIMIT_EXCEEDED",
        ).one()

        assert event.severity == "HIGH"
        assert event.source_ip == "198.51.100.10"
        assert event.description == "Authentication rate limit exceeded."
        assert "WrongPassword123!" not in event.description


def test_security_headers_are_present(monkeypatch):
    app = create_test_app(monkeypatch)
    client = app.test_client()

    response = client.get("/login")

    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["Referrer-Policy"] == "strict-origin-when-cross-origin"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert "default-src 'self'" in response.headers["Content-Security-Policy"]
    assert "script-src 'self'" in response.headers["Content-Security-Policy"]
    assert "Strict-Transport-Security" not in response.headers


def test_hsts_is_enabled_for_production_https(monkeypatch):
    app = create_test_app(monkeypatch, app_env="production")
    client = app.test_client()

    response = client.get("/login", base_url="https://secureops.local")

    assert response.headers["Strict-Transport-Security"] == (
        "max-age=31536000; includeSubDomains"
    )
    assert app.config["SESSION_COOKIE_SECURE"] is True


def test_production_requires_configured_secret_key(monkeypatch):
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.setenv("SECRET_KEY", "change-me")
    monkeypatch.setenv("DATABASE_URL", "sqlite:///:memory:")

    try:
        create_app()
    except RuntimeError as error:
        assert str(error) == "SECRET_KEY must be configured for production."
    else:
        raise AssertionError("create_app() should fail without a production secret.")


def test_successful_login_clears_existing_session_data(monkeypatch):
    app = create_test_app(monkeypatch)

    with app.app_context():
        create_user()

    client = app.test_client()
    with client.session_transaction() as session:
        session["pre_auth_value"] = "stale"

    response = client.post(
        "/login",
        data={
            "username": "admin",
            "password": "SecurePassword123!",
        },
    )

    assert response.status_code == 302
    assert response.headers["Location"] == "/dashboard"

    with client.session_transaction() as session:
        assert "user_id" in session
        assert "pre_auth_value" not in session


def test_internal_pages_remain_protected_after_logout(monkeypatch):
    app = create_test_app(monkeypatch)
    client = app.test_client()

    with app.app_context():
        user_id = create_user()

    authenticate(client, user_id)
    logout_response = client.post("/logout")

    assert logout_response.status_code == 302
    assert logout_response.headers["Location"] == "/login"

    dashboard_response = client.get("/dashboard")
    events_response = client.get("/events")

    assert dashboard_response.status_code == 302
    assert dashboard_response.headers["Location"] == "/login"
    assert events_response.status_code == 302
    assert events_response.headers["Location"] == "/login"


def test_security_event_description_does_not_store_login_password(monkeypatch):
    app = create_test_app(monkeypatch)
    client = app.test_client()

    response = client.post(
        "/login",
        data={
            "username": "admin",
            "password": "SuperSecretPassword123!",
        },
    )

    assert response.status_code == 200

    with app.app_context():
        event = SecurityEvent.query.filter_by(event_type="AUTH_FAILURE").one()

        assert "SuperSecretPassword123!" not in event.description


def test_security_event_description_is_escaped_in_events_page(monkeypatch):
    app = create_test_app(monkeypatch)
    client = app.test_client()

    with app.app_context():
        user_id = create_user()
        event = SecurityEvent(
            event_type="AUTH_FAILURE",
            severity="HIGH",
            source_ip="127.0.0.1",
            description="<script>alert(1)</script>",
        )
        db.session.add(event)
        db.session.commit()

    authenticate(client, user_id)
    response = client.get("/events")

    assert response.status_code == 200
    assert b"<script>alert(1)</script>" not in response.data
    assert b"&lt;script&gt;alert(1)&lt;/script&gt;" in response.data
