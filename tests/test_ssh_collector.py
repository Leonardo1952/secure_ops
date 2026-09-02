from app import create_app
from app.collectors.ssh import collect_ssh_events, parse_ssh_line
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


def test_failed_password_creates_ssh_auth_failure(tmp_path, monkeypatch):
    app = create_test_app(tmp_path, monkeypatch)
    log_path = tmp_path / "auth.log"
    state_path = tmp_path / "state.json"
    write_log(
        log_path,
        [
            "Sep  2 00:40:21 server sshd[1234]: "
            "Failed password for root from 203.0.113.10 port 51234 ssh2",
        ],
    )

    with app.app_context():
        result = collect_ssh_events(log_path, state_path)
        event = SecurityEvent.query.one()

        assert result.processed == 1
        assert result.created == 1
        assert event.event_type == "SSH_AUTH_FAILURE"
        assert event.severity == "MEDIUM"
        assert event.source_ip == "203.0.113.10"
        assert event.description == "SSH authentication failure"


def test_failed_publickey_creates_ssh_auth_failure(tmp_path, monkeypatch):
    app = create_test_app(tmp_path, monkeypatch)
    log_path = tmp_path / "auth.log"
    state_path = tmp_path / "state.json"
    write_log(
        log_path,
        [
            "Sep  2 00:40:21 server sshd[1234]: "
            "Failed publickey for root from 203.0.113.11 port 51234 ssh2",
        ],
    )

    with app.app_context():
        collect_ssh_events(log_path, state_path)
        event = SecurityEvent.query.one()

        assert event.event_type == "SSH_AUTH_FAILURE"
        assert event.severity == "MEDIUM"
        assert event.source_ip == "203.0.113.11"


def test_invalid_user_creates_high_event(tmp_path, monkeypatch):
    app = create_test_app(tmp_path, monkeypatch)
    log_path = tmp_path / "auth.log"
    state_path = tmp_path / "state.json"
    write_log(
        log_path,
        [
            "Sep  2 00:41:15 server sshd[1235]: "
            "Invalid user admin from 203.0.113.20 port 55123",
        ],
    )

    with app.app_context():
        collect_ssh_events(log_path, state_path)
        event = SecurityEvent.query.one()

        assert event.event_type == "SSH_INVALID_USER"
        assert event.severity == "HIGH"
        assert event.source_ip == "203.0.113.20"
        assert event.description == "SSH login attempt with invalid user"


def test_invalid_user_takes_precedence_over_failed_password(tmp_path, monkeypatch):
    app = create_test_app(tmp_path, monkeypatch)
    log_path = tmp_path / "auth.log"
    state_path = tmp_path / "state.json"
    write_log(
        log_path,
        [
            "Sep  2 00:42:00 server sshd[1236]: "
            "Failed password for invalid user oracle from 203.0.113.30 port 55124 ssh2",
        ],
    )

    with app.app_context():
        result = collect_ssh_events(log_path, state_path)
        event = SecurityEvent.query.one()

        assert result.created == 1
        assert event.event_type == "SSH_INVALID_USER"
        assert event.severity == "HIGH"
        assert event.source_ip == "203.0.113.30"


def test_failed_publickey_invalid_user_takes_precedence(tmp_path, monkeypatch):
    app = create_test_app(tmp_path, monkeypatch)
    log_path = tmp_path / "auth.log"
    state_path = tmp_path / "state.json"
    write_log(
        log_path,
        [
            "Sep  2 00:42:00 server sshd[1236]: "
            "Failed publickey for invalid user test from 203.0.113.31 port 55124 ssh2",
        ],
    )

    with app.app_context():
        collect_ssh_events(log_path, state_path)
        event = SecurityEvent.query.one()

        assert event.event_type == "SSH_INVALID_USER"
        assert event.severity == "HIGH"
        assert event.source_ip == "203.0.113.31"


def test_failed_publickey_supports_ipv6(tmp_path, monkeypatch):
    app = create_test_app(tmp_path, monkeypatch)
    log_path = tmp_path / "auth.log"
    state_path = tmp_path / "state.json"
    write_log(
        log_path,
        [
            "Sep  2 00:43:00 server sshd[1237]: "
            "Failed publickey for root from 2001:db8::10 port 50000 ssh2",
        ],
    )

    with app.app_context():
        collect_ssh_events(log_path, state_path)
        event = SecurityEvent.query.one()

        assert event.event_type == "SSH_AUTH_FAILURE"
        assert event.source_ip == "2001:db8::10"


def test_accepted_publickey_is_ignored(tmp_path, monkeypatch):
    app = create_test_app(tmp_path, monkeypatch)
    log_path = tmp_path / "auth.log"
    state_path = tmp_path / "state.json"
    write_log(
        log_path,
        [
            "Sep  2 00:44:00 server sshd[1238]: "
            "Accepted publickey for ubuntu from 203.0.113.99 port 50000 ssh2",
        ],
    )

    with app.app_context():
        result = collect_ssh_events(log_path, state_path)

        assert result.processed == 1
        assert result.created == 0
        assert result.ignored == 1
        assert SecurityEvent.query.count() == 0


def test_irrelevant_lines_are_ignored(tmp_path, monkeypatch):
    app = create_test_app(tmp_path, monkeypatch)
    log_path = tmp_path / "auth.log"
    state_path = tmp_path / "state.json"
    write_log(
        log_path,
        [
            "Sep  2 00:45:00 server sshd[1239]: Connection closed by 203.0.113.10 port 22",
            "Sep  2 00:45:01 server sshd[1240]: Received disconnect from 203.0.113.10",
            "Sep  2 00:45:02 server sudo: pam_unix(sudo:session): session opened",
            "Sep  2 00:45:03 server CRON[1241]: pam_unix(cron:session): session closed",
        ],
    )

    with app.app_context():
        result = collect_ssh_events(log_path, state_path)

        assert result.processed == 4
        assert result.created == 0
        assert result.ignored == 4
        assert SecurityEvent.query.count() == 0


def test_malformed_lines_and_invalid_ips_are_ignored(tmp_path, monkeypatch):
    app = create_test_app(tmp_path, monkeypatch)
    log_path = tmp_path / "auth.log"
    state_path = tmp_path / "state.json"
    write_log(
        log_path,
        [
            "",
            "Sep  2 00:46:00 server sshd[1242]: Failed password for root port 51234 ssh2",
            "Sep  2 00:46:01 server sshd[1243]: Invalid user admin port 55123",
            "Sep  2 00:46:02 server sshd[1244]: Failed password for root from not-an-ip port 51234 ssh2",
            "broken line",
        ],
    )

    with app.app_context():
        result = collect_ssh_events(log_path, state_path)

        assert result.processed == 5
        assert result.created == 0
        assert result.ignored == 5
        assert SecurityEvent.query.count() == 0
        assert parse_ssh_line("broken line") is None


def test_description_minimizes_user_port_pid_and_original_line(tmp_path, monkeypatch):
    app = create_test_app(tmp_path, monkeypatch)
    log_path = tmp_path / "auth.log"
    state_path = tmp_path / "state.json"
    original_line = (
        "Sep  2 00:47:00 server sshd[9999]: "
        "Invalid user admin from 203.0.113.20 port 55123"
    )
    write_log(log_path, [original_line])

    with app.app_context():
        collect_ssh_events(log_path, state_path)
        event = SecurityEvent.query.one()

        assert event.description == "SSH login attempt with invalid user"
        assert "admin" not in event.description
        assert "55123" not in event.description
        assert "9999" not in event.description
        assert original_line not in event.description


def test_checkpoint_prevents_duplicate_events_and_reads_only_new_lines(tmp_path, monkeypatch):
    app = create_test_app(tmp_path, monkeypatch)
    log_path = tmp_path / "auth.log"
    state_path = tmp_path / "state.json"
    write_log(
        log_path,
        [
            "Sep  2 00:48:00 server sshd[1245]: "
            "Failed password for root from 203.0.113.40 port 51234 ssh2",
        ],
    )

    with app.app_context():
        first_result = collect_ssh_events(log_path, state_path)
        second_result = collect_ssh_events(log_path, state_path)
        append_log(
            log_path,
            "Sep  2 00:49:00 server sshd[1246]: "
            "Invalid user admin from 203.0.113.41 port 55123",
        )
        third_result = collect_ssh_events(log_path, state_path)
        events = get_events()

        assert first_result.created == 1
        assert second_result.processed == 0
        assert second_result.created == 0
        assert third_result.processed == 1
        assert third_result.created == 1
        assert [event.event_type for event in events] == [
            "SSH_AUTH_FAILURE",
            "SSH_INVALID_USER",
        ]


def test_truncated_log_restarts_from_beginning(tmp_path, monkeypatch):
    app = create_test_app(tmp_path, monkeypatch)
    log_path = tmp_path / "auth.log"
    state_path = tmp_path / "state.json"
    write_log(
        log_path,
        [
            "Sep  2 00:50:00 server sshd[1247]: "
            "Failed password for root from 203.0.113.50 port 51234 ssh2",
        ],
    )

    with app.app_context():
        collect_ssh_events(log_path, state_path)
        write_log(
            log_path,
            [
                "Sep  2 00:51:00 s sshd[1]: Failed publickey for r from ::1 port 1 ssh2",
            ],
        )
        result = collect_ssh_events(log_path, state_path)

        assert result.processed == 1
        assert result.created == 1
        assert SecurityEvent.query.count() == 2


def test_rotated_log_with_new_inode_restarts_from_beginning(tmp_path, monkeypatch):
    app = create_test_app(tmp_path, monkeypatch)
    log_path = tmp_path / "auth.log"
    state_path = tmp_path / "state.json"
    write_log(
        log_path,
        [
            "Sep  2 00:52:00 server sshd[1248]: "
            "Failed password for root from 203.0.113.60 port 51234 ssh2",
        ],
    )

    with app.app_context():
        collect_ssh_events(log_path, state_path)
        log_path.rename(tmp_path / "auth.log.1")
        write_log(
            log_path,
            [
                "Sep  2 00:53:00 server sshd[1249]: "
                "Invalid user admin from 203.0.113.61 port 55123",
            ],
        )
        result = collect_ssh_events(log_path, state_path)

        assert result.processed == 1
        assert result.created == 1
        assert SecurityEvent.query.count() == 2


def test_dry_run_does_not_write_events_or_checkpoint(tmp_path, monkeypatch):
    app = create_test_app(tmp_path, monkeypatch)
    log_path = tmp_path / "auth.log"
    state_path = tmp_path / "state.json"
    write_log(
        log_path,
        [
            "Sep  2 00:54:00 server sshd[1250]: "
            "Failed password for root from 203.0.113.70 port 51234 ssh2",
            "Sep  2 00:55:00 server sshd[1251]: "
            "Invalid user admin from 203.0.113.71 port 55123",
        ],
    )

    with app.app_context():
        result = collect_ssh_events(log_path, state_path, dry_run=True)

        assert result.processed == 2
        assert result.created == 2
        assert result.event_counts == {
            "SSH_AUTH_FAILURE": 1,
            "SSH_INVALID_USER": 1,
        }
        assert SecurityEvent.query.count() == 0
        assert not state_path.exists()
