from functools import wraps

from flask import redirect, session, url_for

from app.events.service import record_security_event


def login_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if not session.get("user_id"):
            record_security_event(
                event_type="UNAUTHORIZED_ACCESS",
                severity="HIGH",
                description="Attempt to access protected resource.",
            )
            return redirect(url_for("auth.login"))

        return view(*args, **kwargs)

    return wrapped_view
