from __future__ import annotations
# Todo: comentar codigo
import argparse
import datetime as dt
import json
import logging
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Callable, Iterable, TextIO

LOGGER = logging.getLogger("ssh_brute_force_detector")

MONTHS = {
    "Jan": 1,
    "Feb": 2,
    "Mar": 3,
    "Apr": 4,
    "May": 5,
    "Jun": 6,
    "Jul": 7,
    "Aug": 8,
    "Sep": 9,
    "Oct": 10,
    "Nov": 11,
    "Dec": 12,
}

MODERN_LINE_RE = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}"
    r"(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2}))\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<process>[A-Za-z0-9_.-]+)(?:\[(?P<pid>\d+)\])?:\s?"
    r"(?P<message>.*)$"
)

LEGACY_LINE_RE = re.compile(
    r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<process>[A-Za-z0-9_.-]+)(?:\[(?P<pid>\d+)\])?:\s?"
    r"(?P<message>.*)$"
)

SSHD_PROCESSES = {"sshd", "sshd-session"}
IP_PATTERN = r"(?P<ip>[0-9A-Fa-f:.]+)"

MESSAGE_PATTERNS: tuple[tuple[str, str, re.Pattern[str]], ...] = (
    (
        "failed_password",
        "failure",
        re.compile(
            rf"^Failed password for (?:invalid user )?(?P<user>\S+) "
            rf"from {IP_PATTERN} port \d+ ssh2"
        ),
    ),
    (
        "failed_publickey",
        "failure",
        re.compile(
            rf"^Failed publickey for (?:invalid user )?(?P<user>\S+) "
            rf"from {IP_PATTERN} port \d+ ssh2"
        ),
    ),
    (
        "failed_keyboard_interactive",
        "failure",
        re.compile(
            rf"^Failed keyboard-interactive/pam for (?:invalid user )?(?P<user>\S+) "
            rf"from {IP_PATTERN} port \d+ ssh2"
        ),
    ),
    (
        "accepted",
        "success",
        re.compile(
            rf"^Accepted (?:password|publickey|keyboard-interactive/pam|gssapi-with-mic) "
            rf"for (?P<user>\S+) from {IP_PATTERN} port \d+ ssh2"
        ),
    ),
    (
        "invalid_user",
        "invalid_user",
        re.compile(rf"^Invalid user (?P<user>\S+) from {IP_PATTERN}(?: port \d+)?$"),
    ),
    (
        "max_attempts",
        "max_attempts",
        re.compile(
            rf"^maximum authentication attempts exceeded for "
            rf"(?:invalid user )?(?P<user>\S+) from {IP_PATTERN} "
            rf"port \d+ ssh2(?: \[preauth\])?$"
        ),
    ),
    (
        "disconnected",
        "disconnected",
        re.compile(
            rf"^Disconnected from (?:invalid |authenticating )?user "
            rf"(?P<user>\S+) {IP_PATTERN} port \d+"
        ),
    ),
    (
        "received_disconnect",
        "disconnected",
        re.compile(rf"^Received disconnect from {IP_PATTERN} port \d+"),
    ),
    (
        "connection_closed",
        "disconnected",
        re.compile(rf"^Connection closed by {IP_PATTERN} port \d+"),
    ),
    (
        "pam_failure",
        "failure_detail",
        re.compile(
            rf"^pam_unix\(sshd:auth\): authentication failure;.*"
            rf"\brhost={IP_PATTERN}\s+user=(?P<user>\S+)"
        ),
    ),
)


def _legacy_datetime(value: str, reference: dt.datetime) -> dt.datetime:
    month_name, day_text, time_text = value.split()
    month = MONTHS[month_name]
    hour, minute, second = (int(part) for part in time_text.split(":"))
    zone = reference.tzinfo or dt.datetime.now().astimezone().tzinfo
    parsed = dt.datetime(
        reference.year, month, int(day_text), hour, minute, second, tzinfo=zone
    )
    if parsed - reference > dt.timedelta(days=1):
        parsed = parsed.replace(year=parsed.year - 1)
    return parsed


def _parse_timestamp(value: str, reference: dt.datetime | None = None) -> dt.datetime:
    if "T" in value:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=(reference or dt.datetime.now()).astimezone().tzinfo)
        return parsed
    return _legacy_datetime(value, reference or dt.datetime.now().astimezone())


@dataclass(frozen=True)
class AuthEvent:
    timestamp: dt.datetime
    source_ip: str | None
    username: str | None
    status: str
    event_type: str
    process: str
    raw: str

    def to_record(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp.isoformat(),
            "source_ip": self.source_ip,
            "username": self.username,
            "status": self.status,
            "event_type": self.event_type,
            "process": self.process,
        }


class LogParser:
    def __init__(self, reference_time: Callable[[], dt.datetime] | None = None) -> None:
        self._reference_time = reference_time or (lambda: dt.datetime.now().astimezone())

    def parse_line(self, line: str) -> AuthEvent | None:
        stripped = line.rstrip("\r\n")
        if not stripped or "\x00" in stripped:
            return None

        match = MODERN_LINE_RE.match(stripped) or LEGACY_LINE_RE.match(stripped)
        if not match:
            return None

        process = match.group("process")
        if process not in SSHD_PROCESSES:
            return None

        try:
            timestamp = _parse_timestamp(match.group("timestamp"), self._reference_time())
        except (ValueError, KeyError):
            return None

        message = match.group("message")
        for event_type, status, pattern in MESSAGE_PATTERNS:
            event_match = pattern.match(message)
            if not event_match:
                continue
            groups = event_match.groupdict()
            return AuthEvent(
                timestamp=timestamp,
                source_ip=groups.get("ip"),
                username=groups.get("user"),
                status=status,
                event_type=event_type,
                process=process,
                raw=stripped,
            )

        return AuthEvent(
            timestamp=timestamp,
            source_ip=None,
            username=None,
            status="other",
            event_type="sshd_other",
            process=process,
            raw=stripped,
        )


class JsonlEventLogger:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def append(self, record: dict[str, Any]) -> None:
        line = json.dumps(record, ensure_ascii=True, sort_keys=True)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")
            handle.flush()


def iter_log_lines(path: str | Path) -> Iterable[str]:
    source = Path(path)
    if source.suffix == ".gz":
        import gzip

        with gzip.open(source, "rt", encoding="utf-8", errors="replace") as handle:
            yield from handle
        return
    with source.open("r", encoding="utf-8", errors="replace") as handle:
        yield from handle


def cmd_parse(args: argparse.Namespace) -> int:
    parser = LogParser()
    output = JsonlEventLogger(args.output) if args.output else None
    counts: dict[str, int] = {}
    parsed = 0
    for line in iter_log_lines(args.path):
        event = parser.parse_line(line)
        if event is None:
            continue
        parsed += 1
        counts[event.status] = counts.get(event.status, 0) + 1
        record = event.to_record()
        if output:
            output.append(record)
        else:
            print(json.dumps(record, ensure_ascii=True, sort_keys=True))
    print(json.dumps({"parsed": parsed, "statuses": counts}, sort_keys=True), file=sys.stderr)
    return 0


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="SSH brute force detector")
    subparsers = parser.add_subparsers(dest="command", required=True)

    parse_parser = subparsers.add_parser("parse", help="Parse an auth log file")
    parse_parser.add_argument("path")
    parse_parser.add_argument("-o", "--output")
    parse_parser.set_defaults(func=cmd_parse)
    return parser


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
