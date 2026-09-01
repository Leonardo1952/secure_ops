def get_security_status(app):
    return {
        "environment": app.config["APP_ENV"],
        "https": app.config["SESSION_COOKIE_SECURE"],
        "tls": app.config["SECURITY_TLS"],
        "pqc": app.config["SECURITY_PQC"],
        "ssl_labs": app.config["SECURITY_SSL_LABS"],
    }
