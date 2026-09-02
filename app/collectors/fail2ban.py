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

FAIL2BAN_ACTION_RE = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3})\s+"
    r"fail2ban\.actions\s+\[\d+\]:\s+NOTICE\s+"
    r"\[(?P<jail>[^\]]+)\]\s+"
    r"(?P<action>Ban|Unban)\s+"
    r"(?P<source_ip>\S+)\s*$"
)


@dataclass(frozen=True)
class ParsedFail2BanLog:
    timestamp: str
    jail: str
    action: str
    source_ip: str


@dataclass(frozen=True)
class CollectorResult:
    processed: int
    created: int
    ignored: int
    event_counts: dict


def parse_fail2ban_line(line):
    match = FAIL2BAN_ACTION_RE.match(line.strip())

    if not match:
        return None

    source_ip = match.group("source_ip")

    try:
        ipaddress.ip_address(source_ip)
    except ValueError:
        LOGGER.debug("Ignored Fail2Ban log line with invalid IP.")
        return None

    return ParsedFail2BanLog(
        timestamp=match.group("timestamp"),
        jail=match.group("jail").strip(),
        action=match.group("action"),
        source_ip=source_ip,
    )


def classify_log(log):
    if log.action == "Ban":
        return {
            "event_type": "IP_BANNED",
            "severity": "HIGH",
            "source_ip": log.source_ip,
            "description": f"IP banned by Fail2Ban jail: {log.jail}",
        }

    if log.action == "Unban":
        return {
            "event_type": "IP_UNBANNED",
            "severity": "INFO",
            "source_ip": log.source_ip,
            "description": f"IP unbanned by Fail2Ban jail: {log.jail}",
        }

    return None


def load_checkpoint(state_path):
    try:
        with state_path.open("r", encoding="utf-8") as state_file:
            return json.load(state_file)
    except FileNotFoundError:
        return {}
    except json.JSONDecodeError:
        LOGGER.warning("Ignoring invalid Fail2Ban collector checkpoint.")
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


def collect_fail2ban_events(log_path, state_path, dry_run=False):
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
            parsed_log = parse_fail2ban_line(line)

            if not parsed_log:
                ignored += 1
                LOGGER.debug("Ignored malformed or irrelevant Fail2Ban log line.")
                continue

            event = classify_log(parsed_log)

            if not event:
                ignored += 1
                continue

            event_counts[event["event_type"]] = event_counts.get(event["event_type"], 0) + 1

            if not dry_run:
                record_security_event(**event)

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
    return os.getenv("FAIL2BAN_LOG", "/var/log/fail2ban.log")


def default_state_path():
    return os.getenv(
        "FAIL2BAN_COLLECTOR_STATE",
        str(Path("instance") / "fail2ban_collector_state.json"),
    )


def build_parser():
    parser = argparse.ArgumentParser(description="Collect SecureOps events from Fail2Ban logs.")
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
            result = collect_fail2ban_events(
                log_path=args.log_path,
                state_path=args.state_path,
                dry_run=args.dry_run,
            )
    except FileNotFoundError:
        print(f"Fail2Ban log not found: {args.log_path}")
        return 1
    except PermissionError:
        print(f"Permission denied reading Fail2Ban log: {args.log_path}")
        return 1

    print(f"Processed: {result.processed} lines")
    print(f"Security events created: {result.created}")
    print(f"Ignored: {result.ignored}")

    if args.dry_run and result.event_counts:
        for event_type, count in sorted(result.event_counts.items()):
            print(f"{event_type}: {count}")

    return 0
