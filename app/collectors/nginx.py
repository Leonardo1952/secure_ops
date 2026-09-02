import argparse
import json
import logging
import os
import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from dotenv import load_dotenv

from app import create_app
from app.events.service import record_security_event


LOGGER = logging.getLogger(__name__)

COMBINED_LOG_RE = re.compile(
    r'^(?P<remote_addr>\S+) \S+ \S+ '
    r'\[(?P<time_local>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<target>[^"]*) HTTP/(?P<http_version>[^"]+)" '
    r'(?P<status>\d{3}) (?P<body_bytes_sent>\S+) '
    r'"[^"]*" "[^"]*"$'
)

SUSPICIOUS_PATHS = (
    "/.env",
    "/.git",
    "/.git/config",
    "/wp-admin",
    "/wp-login.php",
    "/phpmyadmin",
    "/admin.php",
    "/config.php",
    "/server-status",
    "/actuator",
    "/vendor/phpunit",
)

EVENT_PRECEDENCE = {
    "SUSPICIOUS_PATH": 3,
    "NGINX_403": 2,
    "NGINX_404": 1,
}

IGNORED_PATH_SUFFIXES = (
    ".css",
    ".js",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".ico",
    ".webp",
    ".map",
    ".woff",
    ".woff2",
)

IGNORED_PATHS = (
    "/favicon.ico",
    "/health",
)


@dataclass(frozen=True)
class ParsedNginxLog:
    remote_addr: str
    method: str
    path: str
    status: int


@dataclass(frozen=True)
class CollectorResult:
    processed: int
    created: int
    ignored: int
    event_counts: dict


def parse_combined_log_line(line):
    match = COMBINED_LOG_RE.match(line.strip())

    if not match:
        return None

    target = match.group("target").strip()
    path = urlsplit(target).path or "/"

    try:
        status = int(match.group("status"))
    except ValueError:
        return None

    return ParsedNginxLog(
        remote_addr=match.group("remote_addr"),
        method=match.group("method"),
        path=path,
        status=status,
    )


def classify_log(log):
    if is_suspicious_path(log.path):
        return {
            "event_type": "SUSPICIOUS_PATH",
            "severity": "HIGH",
            "source_ip": log.remote_addr,
            "description": f"Requested suspicious path: {log.path}",
        }

    if is_noise_path(log.path):
        return None

    if log.status == 403:
        return {
            "event_type": "NGINX_403",
            "severity": "MEDIUM",
            "source_ip": log.remote_addr,
            "description": f"HTTP 403 on {log.path}",
        }

    if log.status == 404:
        return {
            "event_type": "NGINX_404",
            "severity": "LOW",
            "source_ip": log.remote_addr,
            "description": f"HTTP 404 on {log.path}",
        }

    return None


def is_suspicious_path(path):
    normalized_path = path.rstrip("/") or "/"
    return any(
        normalized_path == suspicious_path
        or normalized_path.startswith(f"{suspicious_path}/")
        for suspicious_path in SUSPICIOUS_PATHS
    )


def is_noise_path(path):
    normalized_path = path.lower()
    return normalized_path in IGNORED_PATHS or normalized_path.endswith(IGNORED_PATH_SUFFIXES)


def load_checkpoint(state_path):
    try:
        with state_path.open("r", encoding="utf-8") as state_file:
            return json.load(state_file)
    except FileNotFoundError:
        return {}
    except json.JSONDecodeError:
        LOGGER.warning("Ignoring invalid Nginx collector checkpoint.")
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


def collect_nginx_events(log_path, state_path, dry_run=False):
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
            parsed_log = parse_combined_log_line(line)

            if not parsed_log:
                ignored += 1
                LOGGER.debug("Ignored malformed Nginx log line.")
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
    return os.getenv("NGINX_ACCESS_LOG", "/var/log/nginx/access.log")


def default_state_path():
    return os.getenv(
        "NGINX_COLLECTOR_STATE",
        str(Path("instance") / "nginx_collector_state.json"),
    )


def build_parser():
    parser = argparse.ArgumentParser(description="Collect SecureOps events from Nginx logs.")
    parser.add_argument("--log-path", default=default_log_path())
    parser.add_argument("--state-path", default=default_state_path())
    parser.add_argument("--dry-run", action="store_true")
    return parser


def main(argv=None):
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    load_dotenv()
    args = build_parser().parse_args(argv)
    app = create_app()

    with app.app_context():
        result = collect_nginx_events(
            log_path=args.log_path,
            state_path=args.state_path,
            dry_run=args.dry_run,
        )

    print(f"Processed: {result.processed} lines")
    print(f"Security events created: {result.created}")
    print(f"Ignored: {result.ignored}")

    if args.dry_run and result.event_counts:
        for event_type, count in sorted(result.event_counts.items()):
            print(f"{event_type}: {count}")

    return 0
