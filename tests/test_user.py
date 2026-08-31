from app import create_app
from app.extensions import db
from app.models import User


def test_user_password_is_hashed():
    app = create_app()

    with app.app_context():
        db.drop_all()
        db.create_all()

        user = User(username="testuser")
        user.set_password("SecurePassword123!")

        db.session.add(user)
        db.session.commit()

        assert user.password_hash != "SecurePassword123!"
        assert user.check_password("SecurePassword123!") is True
        assert user.check_password("wrong-password") is False