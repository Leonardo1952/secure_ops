from app import create_app
from app.collectors.nginx import (
    collect_nginx_events,
    parse_combined_log_line,
)
from app.extensions import db
from app.models import SecurityEvent


def create_test_app(tmp_path, monkeypatch):
    monkeypatch.setenv("SECRET_KEY", "test-secret-key")
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'test.db'}")

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


def write_log(path, lines):
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def append_log(path, line):
    with path.open("a", encoding="utf-8") as log_file:
        log_file.write(line + "\n")


def get_events():
    return SecurityEvent.query.order_by(SecurityEvent.id.asc()).all()


def test_nginx_200_is_ignored(tmp_path, monkeypatch):
    app = create_test_app(tmp_path, monkeypatch)
    log_path = tmp_path / "access.log"
    state_path = tmp_path / "state.json"
    write_log(
        log_path,
        [
            '200.10.10.10 - - [02/Sep/2026:10:00:00 +0000] '
            '"GET / HTTP/1.1" 200 123 "-" "Mozilla"',
        ],
    )

    with app.app_context():
        result = collect_nginx_events(log_path, state_path)

        assert result.processed == 1
        assert result.created == 0
        assert result.ignored == 1
        assert SecurityEvent.query.count() == 0


def test_nginx_404_creates_low_event(tmp_path, monkeypatch):
    app = create_test_app(tmp_path, monkeypatch)
    log_path = tmp_path / "access.log"
    state_path = tmp_path / "state.json"
    write_log(
        log_path,
        [
            '200.10.10.11 - - [02/Sep/2026:10:01:00 +0000] '
            '"GET /missing HTTP/1.1" 404 123 "-" "Mozilla"',
        ],
    )

    with app.app_context():
        result = collect_nginx_events(log_path, state_path)
        event = SecurityEvent.query.one()

        assert result.created == 1
        assert event.event_type == "NGINX_404"
        assert event.severity == "LOW"
        assert event.source_ip == "200.10.10.11"
        assert event.description == "HTTP 404 on /missing"


def test_nginx_403_creates_medium_event(tmp_path, monkeypatch):
    app = create_test_app(tmp_path, monkeypatch)
    log_path = tmp_path / "access.log"
    state_path = tmp_path / "state.json"
    write_log(
        log_path,
        [
            '200.10.10.12 - - [02/Sep/2026:10:02:00 +0000] '
            '"GET /private HTTP/1.1" 403 123 "-" "Mozilla"',
        ],
    )

    with app.app_context():
        collect_nginx_events(log_path, state_path)
        event = SecurityEvent.query.one()

        assert event.event_type == "NGINX_403"
        assert event.severity == "MEDIUM"
        assert event.source_ip == "200.10.10.12"
        assert event.description == "HTTP 403 on /private"


def test_suspicious_path_takes_precedence_over_404(tmp_path, monkeypatch):
    app = create_test_app(tmp_path, monkeypatch)
    log_path = tmp_path / "access.log"
    state_path = tmp_path / "state.json"
    write_log(
        log_path,
        [
            '200.10.10.13 - - [02/Sep/2026:10:03:00 +0000] '
            '"GET /.env HTTP/1.1" 404 123 "-" "curl"',
        ],
    )

    with app.app_context():
        result = collect_nginx_events(log_path, state_path)
        event = SecurityEvent.query.one()

        assert result.created == 1
        assert event.event_type == "SUSPICIOUS_PATH"
        assert event.severity == "HIGH"
        assert event.source_ip == "200.10.10.13"
        assert event.description == "Requested suspicious path: /.env"


def test_query_string_is_not_stored_in_description(tmp_path, monkeypatch):
    app = create_test_app(tmp_path, monkeypatch)
    log_path = tmp_path / "access.log"
    state_path = tmp_path / "state.json"
    write_log(
        log_path,
        [
            '200.10.10.14 - - [02/Sep/2026:10:04:00 +0000] '
            '"GET /login?token=SECRET123 HTTP/1.1" 404 123 "-" "Mozilla"',
        ],
    )

    with app.app_context():
        collect_nginx_events(log_path, state_path)
        event = SecurityEvent.query.one()

        assert event.description == "HTTP 404 on /login"
        assert "SECRET123" not in event.description


def test_malformed_line_is_ignored(tmp_path, monkeypatch):
    app = create_test_app(tmp_path, monkeypatch)
    log_path = tmp_path / "access.log"
    state_path = tmp_path / "state.json"
    write_log(log_path, ["invalid nginx log line"])

    with app.app_context():
        result = collect_nginx_events(log_path, state_path)

        assert result.processed == 1
        assert result.created == 0
        assert result.ignored == 1
        assert SecurityEvent.query.count() == 0
        assert parse_combined_log_line("invalid nginx log line") is None


def test_checkpoint_prevents_duplicate_events_and_reads_only_new_lines(tmp_path, monkeypatch):
    app = create_test_app(tmp_path, monkeypatch)
    log_path = tmp_path / "access.log"
    state_path = tmp_path / "state.json"
    write_log(
        log_path,
        [
            '200.10.10.15 - - [02/Sep/2026:10:05:00 +0000] '
            '"GET /first HTTP/1.1" 404 123 "-" "Mozilla"',
        ],
    )

    with app.app_context():
        first_result = collect_nginx_events(log_path, state_path)
        second_result = collect_nginx_events(log_path, state_path)
        append_log(
            log_path,
            '200.10.10.16 - - [02/Sep/2026:10:06:00 +0000] '
            '"GET /second HTTP/1.1" 404 123 "-" "Mozilla"',
        )
        third_result = collect_nginx_events(log_path, state_path)
        events = get_events()

        assert first_result.created == 1
        assert second_result.processed == 0
        assert second_result.created == 0
        assert third_result.processed == 1
        assert third_result.created == 1
        assert [event.description for event in events] == [
            "HTTP 404 on /first",
            "HTTP 404 on /second",
        ]


def test_truncated_log_restarts_from_beginning(tmp_path, monkeypatch):
    app = create_test_app(tmp_path, monkeypatch)
    log_path = tmp_path / "access.log"
    state_path = tmp_path / "state.json"
    write_log(
        log_path,
        [
            '200.10.10.17 - - [02/Sep/2026:10:07:00 +0000] '
            '"GET /before-truncate HTTP/1.1" 404 123 "-" "Mozilla"',
        ],
    )

    with app.app_context():
        collect_nginx_events(log_path, state_path)
        write_log(
            log_path,
            [
                '200.10.10.18 - - [02/Sep/2026:10:08:00 +0000] '
                '"GET /after-truncate HTTP/1.1" 404 1 "-" "Mozilla"',
            ],
        )
        result = collect_nginx_events(log_path, state_path)
        events = get_events()

        assert result.processed == 1
        assert result.created == 1
        assert [event.description for event in events] == [
            "HTTP 404 on /before-truncate",
            "HTTP 404 on /after-truncate",
        ]


def test_rotated_log_with_new_inode_restarts_from_beginning(tmp_path, monkeypatch):
    app = create_test_app(tmp_path, monkeypatch)
    log_path = tmp_path / "access.log"
    state_path = tmp_path / "state.json"
    write_log(
        log_path,
        [
            '200.10.10.19 - - [02/Sep/2026:10:09:00 +0000] '
            '"GET /before-rotate HTTP/1.1" 404 123 "-" "Mozilla"',
        ],
    )

    with app.app_context():
        collect_nginx_events(log_path, state_path)
        log_path.rename(tmp_path / "access.log.1")
        write_log(
            log_path,
            [
                '200.10.10.20 - - [02/Sep/2026:10:10:00 +0000] '
                '"GET /after-rotate HTTP/1.1" 404 123 "-" "Mozilla"',
            ],
        )
        result = collect_nginx_events(log_path, state_path)

        assert result.processed == 1
        assert result.created == 1
        assert SecurityEvent.query.count() == 2


def test_dry_run_does_not_write_events_or_checkpoint(tmp_path, monkeypatch):
    app = create_test_app(tmp_path, monkeypatch)
    log_path = tmp_path / "access.log"
    state_path = tmp_path / "state.json"
    write_log(
        log_path,
        [
            '200.10.10.21 - - [02/Sep/2026:10:11:00 +0000] '
            '"GET /.git/config HTTP/1.1" 404 123 "-" "curl"',
        ],
    )

    with app.app_context():
        result = collect_nginx_events(log_path, state_path, dry_run=True)

        assert result.processed == 1
        assert result.created == 1
        assert result.event_counts == {"SUSPICIOUS_PATH": 1}
        assert SecurityEvent.query.count() == 0
        assert not state_path.exists()
