import argparse
import ipaddress
import json
import logging
import os
import re
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

from app import create_app
from app.events.service import record_security_event


LOGGER = logging.getLogger(__name__)

SSHD_MESSAGE_RE = re.compile(r"\bsshd\[\d+\]:\s+(?P<message>.+)$")

INVALID_USER_RE = re.compile(
    r"(?:Invalid user \S+ from|Failed (?:password|publickey) for invalid user \S+ from)\s+"
    r"(?P<source_ip>\S+)"
)

AUTH_FAILURE_RE = re.compile(
    r"Failed (?:password|publickey) for \S+ from\s+(?P<source_ip>\S+)"
)


@dataclass(frozen=True)
class ParsedSshLog:
    event_type: str
    severity: str
    source_ip: str
    description: str


@dataclass(frozen=True)
class CollectorResult:
    processed: int
    created: int
    ignored: int
    event_counts: dict


def parse_ssh_line(line):
    match = SSHD_MESSAGE_RE.search(line.strip())

    if not match:
        return None

    message = match.group("message")
    invalid_user_match = INVALID_USER_RE.search(message)

    if invalid_user_match:
        source_ip = invalid_user_match.group("source_ip")

        if not is_valid_ip(source_ip):
            LOGGER.debug("Ignored SSH invalid user line with invalid IP.")
            return None

        return ParsedSshLog(
            event_type="SSH_INVALID_USER",
            severity="HIGH",
            source_ip=source_ip,
            description="SSH login attempt with invalid user",
        )

    auth_failure_match = AUTH_FAILURE_RE.search(message)

    if auth_failure_match:
        source_ip = auth_failure_match.group("source_ip")

        if not is_valid_ip(source_ip):
            LOGGER.debug("Ignored SSH auth failure line with invalid IP.")
            return None

        return ParsedSshLog(
            event_type="SSH_AUTH_FAILURE",
            severity="MEDIUM",
            source_ip=source_ip,
            description="SSH authentication failure",
        )

    return None


def is_valid_ip(source_ip):
    try:
        ipaddress.ip_address(source_ip)
    except ValueError:
        return False

    return True


def load_checkpoint(state_path):
    try:
        with state_path.open("r", encoding="utf-8") as state_file:
            return json.load(state_file)
    except FileNotFoundError:
        return {}
    except json.JSONDecodeError:
        LOGGER.warning("Ignoring SSH collector checkpoint.")
        return {}


def save_checkpoint(state_path, inode, offset):
    state_path.parent.mkdir(parents=True, exist_ok=True)
    with state_path.open("w", encoding="utf-8") as state_file:
        json.dump({"inode": inode, "offset": offset}, state_file)


def get_start_offset(log_path, checkpoint):
    stat_result = log_path.stat()
    checkpoint_inode = checkpoint.get("inode")
    checkpoint_offset = int(checkpoint.get("offset", 0) or 0)

    if checkpoint_inode == stat_result.st_ino and stat_result.st_size >= checkpoint_offset:
        return checkpoint_offset

    return 0


def collect_ssh_events(log_path, state_path, dry_run=False):
    log_path = Path(log_path)
    state_path = Path(state_path)
    checkpoint = load_checkpoint(state_path)
    start_offset = get_start_offset(log_path, checkpoint)
    stat_result = log_path.stat()
    processed = 0
    created = 0
    ignored = 0
    event_counts = {}

    with log_path.open("r", encoding="utf-8", errors="replace") as log_file:
        log_file.seek(start_offset)

        for line in log_file:
            processed += 1
            parsed_log = parse_ssh_line(line)

            if not parsed_log:
                ignored += 1
                LOGGER.debug("Ignored malformed or irrelevant SSH log line.")
                continue

            event_counts[parsed_log.event_type] = event_counts.get(parsed_log.event_type, 0) + 1

            if not dry_run:
                record_security_event(
                    event_type=parsed_log.event_type,
                    severity=parsed_log.severity,
                    source_ip=parsed_log.source_ip,
                    description=parsed_log.description,
                )

            created += 1

        end_offset = log_file.tell()

    if not dry_run:
        save_checkpoint(state_path, stat_result.st_ino, end_offset)

    return CollectorResult(
        processed=processed,
        created=created,
        ignored=ignored,
        event_counts=event_counts,
    )


def default_log_path():
    return os.getenv("SSH_AUTH_LOG", "/var/log/auth.log")


def default_state_path():
    return os.getenv(
        "SSH_COLLECTOR_STATE",
        str(Path("instance") / "ssh_collector_state.json"),
    )


def build_parser():
    parser = argparse.ArgumentParser(description="Collect SecureOps events from SSH auth logs.")
    parser.add_argument("--log-path", default=default_log_path())
    parser.add_argument("--state-path", default=default_state_path())
    parser.add_argument("--dry-run", action="store_true")
    return parser


def main(argv=None):
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    load_dotenv()
    args = build_parser().parse_args(argv)

    try:
        app = create_app()

        with app.app_context():
            result = collect_ssh_events(
                log_path=args.log_path,
                state_path=args.state_path,
                dry_run=args.dry_run,
            )
    except FileNotFoundError:
        print(f"SSH auth log not found: {args.log_path}")
        return 1
    except PermissionError:
        print(f"Permission denied reading SSH auth log: {args.log_path}")
        return 1

    print(f"Processed: {result.processed} lines")
    print(f"Security events created: {result.created}")
    print(f"Ignored: {result.ignored}")

    if args.dry_run and result.event_counts:
        for event_type, count in sorted(result.event_counts.items()):
            print(f"{event_type}: {count}")

    return 0
