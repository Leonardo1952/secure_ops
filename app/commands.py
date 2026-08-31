import os

import click
from flask import Flask

from app.extensions import db
from app.models import User


def register_commands(app: Flask):
    @app.cli.command("init-admin")
    def init_admin():
        username = os.getenv("SECUREOPS_ADMIN_USER")
        password = os.getenv("SECUREOPS_ADMIN_PASSWORD")

        if not username or not password:
            raise click.ClickException(
                "SECUREOPS_ADMIN_USER and SECUREOPS_ADMIN_PASSWORD must be configured."
            )

        existing_user = User.query.filter_by(username=username).first()

        if existing_user:
            click.echo("Admin user already exists.")
            return

        user = User(username=username)
        user.set_password(password)

        db.session.add(user)
        db.session.commit()

        click.echo("Admin user created successfully.")