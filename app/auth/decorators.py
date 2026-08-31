from functools import wraps

from flask import redirect, request, session, url_for

from app.events.service import record_security_event


def login_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if not session.get("user_id"):
            record_security_event(
                event_type="UNAUTHORIZED_ACCESS",
                severity="HIGH",
                source_ip=request.remote_addr,
                description="Attempt to access protected resource.",
            )
            return redirect(url_for("auth.login"))

        return view(*args, **kwargs)

    return wrapped_view
