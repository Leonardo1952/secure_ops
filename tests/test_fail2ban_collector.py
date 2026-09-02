from app import create_app
from app.collectors.fail2ban import (
    collect_fail2ban_events,
    parse_fail2ban_line,
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


def test_fail2ban_ban_creates_high_event(tmp_path, monkeypatch):
    app = create_test_app(tmp_path, monkeypatch)
    log_path = tmp_path / "fail2ban.log"
    state_path = tmp_path / "state.json"
    write_log(
        log_path,
        [
            "2026-09-02 01:22:10,123 fail2ban.actions [1234]: "
            "NOTICE [sshd] Ban 203.0.113.50",
        ],
    )

    with app.app_context():
        result = collect_fail2ban_events(log_path, state_path)
        event = SecurityEvent.query.one()

        assert result.processed == 1
        assert result.created == 1
        assert event.event_type == "IP_BANNED"
        assert event.severity == "HIGH"
        assert event.source_ip == "203.0.113.50"
        assert event.description == "IP banned by Fail2Ban jail: sshd"


def test_fail2ban_unban_creates_info_event(tmp_path, monkeypatch):
    app = create_test_app(tmp_path, monkeypatch)
    log_path = tmp_path / "fail2ban.log"
    state_path = tmp_path / "state.json"
    write_log(
        log_path,
        [
            "2026-09-02 02:22:10,123 fail2ban.actions [1234]: "
            "NOTICE [sshd] Unban 203.0.113.50",
        ],
    )

    with app.app_context():
        collect_fail2ban_events(log_path, state_path)
        event = SecurityEvent.query.one()

        assert event.event_type == "IP_UNBANNED"
        assert event.severity == "INFO"
        assert event.source_ip == "203.0.113.50"
        assert event.description == "IP unbanned by Fail2Ban jail: sshd"


def test_fail2ban_parser_accepts_other_jails(tmp_path, monkeypatch):
    app = create_test_app(tmp_path, monkeypatch)
    log_path = tmp_path / "fail2ban.log"
    state_path = tmp_path / "state.json"
    write_log(
        log_path,
        [
            "2026-09-02 03:22:10,123 fail2ban.actions [1234]: "
            "NOTICE [recidive] Ban 198.51.100.20",
        ],
    )

    with app.app_context():
        collect_fail2ban_events(log_path, state_path)
        event = SecurityEvent.query.one()

        assert event.event_type == "IP_BANNED"
        assert event.severity == "HIGH"
        assert event.source_ip == "198.51.100.20"
        assert "recidive" in event.description


def test_fail2ban_parser_supports_ipv6(tmp_path, monkeypatch):
    app = create_test_app(tmp_path, monkeypatch)
    log_path = tmp_path / "fail2ban.log"
    state_path = tmp_path / "state.json"
    write_log(
        log_path,
        [
            "2026-09-02 04:22:10,123 fail2ban.actions [1234]: "
            "NOTICE [sshd] Ban 2001:db8::1",
        ],
    )

    with app.app_context():
        collect_fail2ban_events(log_path, state_path)
        event = SecurityEvent.query.one()

        assert event.event_type == "IP_BANNED"
        assert event.source_ip == "2001:db8::1"


def test_fail2ban_ignores_irrelevant_lines(tmp_path, monkeypatch):
    app = create_test_app(tmp_path, monkeypatch)
    log_path = tmp_path / "fail2ban.log"
    state_path = tmp_path / "state.json"
    write_log(
        log_path,
        [
            "2026-09-02 01:00:00,123 fail2ban.filter [1234]: INFO [sshd] Found 203.0.113.50",
            "2026-09-02 01:00:01,123 fail2ban.jail [1234]: INFO Jail 'sshd' started",
            "2026-09-02 01:00:02,123 fail2ban.actions [1234]: NOTICE [sshd] Restore Ban 203.0.113.51",
            "2026-09-02 01:00:03,123 fail2ban.server [1234]: DEBUG Added logfile",
        ],
    )

    with app.app_context():
        result = collect_fail2ban_events(log_path, state_path)

        assert result.processed == 4
        assert result.created == 0
        assert result.ignored == 4
        assert SecurityEvent.query.count() == 0


def test_fail2ban_ignores_malformed_lines(tmp_path, monkeypatch):
    app = create_test_app(tmp_path, monkeypatch)
    log_path = tmp_path / "fail2ban.log"
    state_path = tmp_path / "state.json"
    write_log(
        log_path,
        [
            "",
            "2026-09-02 01:22:10,123 fail2ban.actions [1234]: NOTICE Ban 203.0.113.50",
            "2026-09-02 01:22:10,123 fail2ban.actions [1234]: NOTICE [sshd] Ban",
            "2026-09-02 01:22:10,123 fail2ban.actions [1234]: NOTICE [sshd] Ban not-an-ip",
            "broken line",
        ],
    )

    with app.app_context():
        result = collect_fail2ban_events(log_path, state_path)

        assert result.processed == 5
        assert result.created == 0
        assert result.ignored == 5
        assert SecurityEvent.query.count() == 0
        assert parse_fail2ban_line("broken line") is None


def test_fail2ban_ban_and_unban_same_ip_are_separate_events(tmp_path, monkeypatch):
    app = create_test_app(tmp_path, monkeypatch)
    log_path = tmp_path / "fail2ban.log"
    state_path = tmp_path / "state.json"
    write_log(
        log_path,
        [
            "2026-09-02 01:00:00,123 fail2ban.actions [1234]: NOTICE [sshd] Ban 203.0.113.50",
            "2026-09-02 02:00:00,123 fail2ban.actions [1234]: NOTICE [sshd] Unban 203.0.113.50",
        ],
    )

    with app.app_context():
        result = collect_fail2ban_events(log_path, state_path)
        events = get_events()

        assert result.created == 2
        assert [event.event_type for event in events] == ["IP_BANNED", "IP_UNBANNED"]


def test_checkpoint_prevents_duplicate_events_and_reads_only_new_lines(tmp_path, monkeypatch):
    app = create_test_app(tmp_path, monkeypatch)
    log_path = tmp_path / "fail2ban.log"
    state_path = tmp_path / "state.json"
    write_log(
        log_path,
        [
            "2026-09-02 01:00:00,123 fail2ban.actions [1234]: NOTICE [sshd] Ban 203.0.113.60",
        ],
    )

    with app.app_context():
        first_result = collect_fail2ban_events(log_path, state_path)
        second_result = collect_fail2ban_events(log_path, state_path)
        append_log(
            log_path,
            "2026-09-02 02:00:00,123 fail2ban.actions [1234]: NOTICE [sshd] Unban 203.0.113.60",
        )
        third_result = collect_fail2ban_events(log_path, state_path)
        events = get_events()

        assert first_result.created == 1
        assert second_result.processed == 0
        assert second_result.created == 0
        assert third_result.processed == 1
        assert third_result.created == 1
        assert [event.event_type for event in events] == ["IP_BANNED", "IP_UNBANNED"]


def test_truncated_log_restarts_from_beginning(tmp_path, monkeypatch):
    app = create_test_app(tmp_path, monkeypatch)
    log_path = tmp_path / "fail2ban.log"
    state_path = tmp_path / "state.json"
    write_log(
        log_path,
        [
            "2026-09-02 01:00:00,123 fail2ban.actions [1234]: NOTICE [sshd] Ban 203.0.113.70",
        ],
    )

    with app.app_context():
        collect_fail2ban_events(log_path, state_path)
        write_log(
            log_path,
            [
                "2026-09-02 02:00:00,123 fail2ban.actions [1]: NOTICE [s] Ban ::1",
            ],
        )
        result = collect_fail2ban_events(log_path, state_path)

        assert result.processed == 1
        assert result.created == 1
        assert SecurityEvent.query.count() == 2


def test_rotated_log_with_new_inode_restarts_from_beginning(tmp_path, monkeypatch):
    app = create_test_app(tmp_path, monkeypatch)
    log_path = tmp_path / "fail2ban.log"
    state_path = tmp_path / "state.json"
    write_log(
        log_path,
        [
            "2026-09-02 01:00:00,123 fail2ban.actions [1234]: NOTICE [sshd] Ban 203.0.113.80",
        ],
    )

    with app.app_context():
        collect_fail2ban_events(log_path, state_path)
        log_path.rename(tmp_path / "fail2ban.log.1")
        write_log(
            log_path,
            [
                "2026-09-02 02:00:00,123 fail2ban.actions [1234]: NOTICE [sshd] Ban 203.0.113.81",
            ],
        )
        result = collect_fail2ban_events(log_path, state_path)

        assert result.processed == 1
        assert result.created == 1
        assert SecurityEvent.query.count() == 2


def test_dry_run_does_not_write_events_or_checkpoint(tmp_path, monkeypatch):
    app = create_test_app(tmp_path, monkeypatch)
    log_path = tmp_path / "fail2ban.log"
    state_path = tmp_path / "state.json"
    write_log(
        log_path,
        [
            "2026-09-02 01:00:00,123 fail2ban.actions [1234]: NOTICE [sshd] Ban 203.0.113.90",
            "2026-09-02 02:00:00,123 fail2ban.actions [1234]: NOTICE [sshd] Unban 203.0.113.90",
        ],
    )

    with app.app_context():
        result = collect_fail2ban_events(log_path, state_path, dry_run=True)

        assert result.processed == 2
        assert result.created == 2
        assert result.event_counts == {"IP_BANNED": 1, "IP_UNBANNED": 1}
        assert SecurityEvent.query.count() == 0
        assert not state_path.exists()
