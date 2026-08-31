from app import create_app


def test_application_is_running():
    app = create_app()
    client = app.test_client()

    response = client.get("/")

    assert response.status_code == 200

    data = response.get_json()

    assert data["application"] == "SecureOps"
    assert data["status"] == "running"