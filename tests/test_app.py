from app import create_app
from app.extensions import db
from app.models import SecurityEvent, User


def make_app(tmp_path, monkeypatch):
    monkeypatch.setenv("SECRET_KEY", "test-secret-key")
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'test.db'}")

    app = create_app()
    app.config.update(
        TESTING=True,
        WTF_CSRF_ENABLED=False,
    )

    with app.app_context():
        db.drop_all()
        db.create_all()

    return app


def test_root_redirects_to_login(tmp_path, monkeypatch):
    app = make_app(tmp_path, monkeypatch)
    client = app.test_client()

    response = client.get("/")

    assert response.status_code == 302
    assert response.headers["Location"] == "/login"


def test_health_returns_public_application_status(tmp_path, monkeypatch):
    app = make_app(tmp_path, monkeypatch)
    client = app.test_client()

    response = client.get("/health")

    assert response.status_code == 200
    assert response.json["status"] == "healthy"
    assert response.json["application"] == "SecureOps"
    assert response.json["version"] == "1.1.0"


def test_proxy_fix_uses_forwarded_for_for_remote_addr(tmp_path, monkeypatch):
    app = make_app(tmp_path, monkeypatch)

    @app.get("/remote-addr-test")
    def remote_addr_test():
        from flask import request

        return {"remote_addr": request.remote_addr, "secure": request.is_secure}

    client = app.test_client()
    response = client.get(
        "/remote-addr-test",
        headers={
            "X-Forwarded-For": "203.0.113.10",
            "X-Forwarded-Proto": "https",
        },
    )

    assert response.status_code == 200
    assert response.json["remote_addr"] == "203.0.113.10"
    assert response.json["secure"] is True


def test_events_record_forwarded_source_ip(tmp_path, monkeypatch):
    app = make_app(tmp_path, monkeypatch)
    client = app.test_client()

    client.get(
        "/dashboard",
        headers={"X-Forwarded-For": "198.51.100.25"},
    )

    with app.app_context():
        event = SecurityEvent.query.one()

        assert event.event_type == "UNAUTHORIZED_ACCESS"
        assert event.source_ip == "198.51.100.25"


def test_login_page_renders_html_form(tmp_path, monkeypatch):
    app = make_app(tmp_path, monkeypatch)
    client = app.test_client()

    response = client.get("/login")

    assert response.status_code == 200
    assert b"SecureOps" in response.data
    assert b"Username" in response.data
    assert b"Password" in response.data
    assert b"Sign in" in response.data
    assert b"from flask import Flask" not in response.data


def test_dashboard_requires_authentication(tmp_path, monkeypatch):
    app = make_app(tmp_path, monkeypatch)
    client = app.test_client()

    response = client.get("/dashboard")

    assert response.status_code == 302
    assert response.headers["Location"] == "/login"


def test_valid_login_redirects_to_dashboard(tmp_path, monkeypatch):
    app = make_app(tmp_path, monkeypatch)

    with app.app_context():
        user = User(username="admin")
        user.set_password("SecurePassword123!")
        db.session.add(user)
        db.session.commit()

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

    with client.session_transaction() as session:
        assert session["user_id"] == 1


def test_logout_clears_session_and_redirects_to_login(tmp_path, monkeypatch):
    app = make_app(tmp_path, monkeypatch)
    client = app.test_client()

    with client.session_transaction() as session:
        session["user_id"] = 1

    response = client.post("/logout")

    assert response.status_code == 302
    assert response.headers["Location"] == "/login"

    with client.session_transaction() as session:
        assert "user_id" not in session
