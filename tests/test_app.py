from app import create_app
from app.extensions import db
from app.models import User


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
