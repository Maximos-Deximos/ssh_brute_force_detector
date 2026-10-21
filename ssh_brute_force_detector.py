from __future__ import annotations
# Todo: comentar codigo
import argparse
import datetime as dt
import json
import logging
import os
import re
import sys
import time
from collections import deque
from dataclasses import asdict, dataclass, field
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Callable, Iterable, TextIO
from typing import Any, BinaryIO, Callable, Iterable

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

@dataclass(frozen=True)
class DetectionConfig:
    window_seconds: int = 600
    alert_threshold: int = 5
    rate_limit_threshold: int = 8
    block_threshold: int = 12
    reset_on_success: bool = True

    def __post_init__(self) -> None:
        if self.window_seconds <= 0:
            raise ValueError("window_seconds must be positive")
        if min(self.alert_threshold, self.rate_limit_threshold, self.block_threshold) <= 0:
            raise ValueError("detection thresholds must be positive")
        if not (
            self.alert_threshold
            <= self.rate_limit_threshold
            <= self.block_threshold
        ):
            raise ValueError("thresholds must be ordered alert <= rate_limit <= block")


@dataclass(frozen=True)
class Detection:
    ip: str
    failure_count: int
    window_seconds: int
    first_failure: dt.datetime
    last_failure: dt.datetime
    usernames: tuple[str, ...]
    stage: str
    is_new_attack: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "ip": self.ip,
            "failure_count": self.failure_count,
            "window_seconds": self.window_seconds,
            "first_failure": self.first_failure.isoformat(),
            "last_failure": self.last_failure.isoformat(),
            "usernames": list(self.usernames),
            "stage": self.stage,
            "is_new_attack": self.is_new_attack,
        }


@dataclass
class _IPWindow:
    failures: deque[tuple[dt.datetime, str | None]] = field(default_factory=deque)
    last_milestone: int = 0
    ever_emitted: bool = False


class DetectionEngine:
    def __init__(self, config: DetectionConfig | None = None) -> None:
        self.config = config or DetectionConfig()
        self._windows: dict[str, _IPWindow] = {}

    def _prune(self, state: _IPWindow, reference: dt.datetime) -> None:
        cutoff = reference - dt.timedelta(seconds=self.config.window_seconds)
        while state.failures and state.failures[0][0] < cutoff:
            state.failures.popleft()

    def _stage_for(self, count: int) -> str:
        if count >= self.config.block_threshold:
            return "block"
        if count >= self.config.rate_limit_threshold:
            return "rate_limit"
        return "alert"

    def record(self, event: AuthEvent) -> Detection | None:
        if event.source_ip is None:
            return None
        if event.status == "success":
            if self.config.reset_on_success:
                self._windows.pop(event.source_ip, None)
            return None
        if event.status != "failure":
            return None

        state = self._windows.setdefault(event.source_ip, _IPWindow())
        self._prune(state, event.timestamp)
        state.failures.append((event.timestamp, event.username))
        count = len(state.failures)
        if count < self.config.alert_threshold:
            state.last_milestone = 0
            state.ever_emitted = False
            return None

        milestone = max(
            threshold
            for threshold in (
                self.config.alert_threshold,
                self.config.rate_limit_threshold,
                self.config.block_threshold,
            )
            if count >= threshold
        )
        if milestone <= state.last_milestone:
            return None

        is_new_attack = not state.ever_emitted
        state.last_milestone = milestone
        state.ever_emitted = True
        first_failure = state.failures[0][0]
        usernames = tuple(
            sorted({username for _, username in state.failures if username})
        )
        return Detection(
            ip=event.source_ip,
            failure_count=count,
            window_seconds=self.config.window_seconds,
            first_failure=first_failure,
            last_failure=event.timestamp,
            usernames=usernames,
            stage=self._stage_for(milestone),
            is_new_attack=is_new_attack,
        )

    def current_count(self, ip: str, reference: dt.datetime | None = None) -> int:
        state = self._windows.get(ip)
        if state is None:
            return 0
        if reference is not None:
            self._prune(state, reference)
        return len(state.failures)

class JsonlEventLogger:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def append(self, record: dict[str, Any]) -> None:
        line = json.dumps(record, ensure_ascii=True, sort_keys=True)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")
            handle.flush()


@dataclass
class MonitorState:
    path: str
    inode: int
    device: int
    offset: int
    last_timestamp: str | None = None
    updated_at: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> MonitorState:
        return cls(
            path=str(value["path"]),
            inode=int(value["inode"]),
            device=int(value["device"]),
            offset=max(0, int(value["offset"])),
            last_timestamp=value.get("last_timestamp"),
            updated_at=value.get("updated_at"),
        )


class MonitorStateStore:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def load(self) -> MonitorState | None:
        if not self.path.exists():
            return None
        try:
            value = json.loads(self.path.read_text(encoding="utf-8"))
            return MonitorState.from_dict(value)
        except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError):
            LOGGER.warning("Ignoring invalid monitor state at %s", self.path)
            return None

    def save(self, state: MonitorState) -> None:
        state.updated_at = dt.datetime.now().astimezone().isoformat()
        temporary = self.path.with_name(f".{self.path.name}.{os.getpid()}.tmp")
        payload = json.dumps(state.to_dict(), sort_keys=True)
        with temporary.open("w", encoding="utf-8") as handle:
            handle.write(payload + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, self.path)


class LogMonitor:
    def __init__(
        self,
        path: str | Path,
        parser: LogParser,
        state_store: MonitorStateStore,
        on_event: Callable[[AuthEvent], None],
        from_end: bool = False,
        poll_interval: float = 1.0,
        read_chunk_size: int = 65536,
        max_partial_bytes: int = 1048576,
    ) -> None:
        self.path = Path(path)
        self.parser = parser
        self.state_store = state_store
        self.on_event = on_event
        self.from_end = from_end
        self.poll_interval = max(0.05, poll_interval)
        self.read_chunk_size = max(1, read_chunk_size)
        self.max_partial_bytes = max(4096, max_partial_bytes)
        self._handle: BinaryIO | None = None
        self._buffer = bytearray()
        self._processed_offset = 0
        self._read_position = 0
        self._identity: tuple[int, int] | None = None
        self._last_timestamp: str | None = None
        self._started = False

    def start(self) -> None:
        stat = self.path.stat()
        saved = self.state_store.load()
        offset = 0
        if (
            saved is not None
            and saved.path == str(self.path)
            and saved.inode == stat.st_ino
            and saved.device == stat.st_dev
            and saved.offset <= stat.st_size
        ):
            offset = saved.offset
            self._last_timestamp = saved.last_timestamp
            LOGGER.info("Resuming %s at byte %d", self.path, offset)
        elif saved is not None:
            LOGGER.warning("Log rotated while stopped; starting %s at byte 0", self.path)
        elif self.from_end:
            offset = stat.st_size

        self._open_at(offset)
        self._started = True
        self._save_state(force=True)

    def _open(self) -> None:
        if self._handle is not None:
            self._handle.close()
        self._handle = self.path.open("rb", buffering=0)
        stat = os.fstat(self._handle.fileno())
        self._identity = (stat.st_dev, stat.st_ino)

    def _open_at(self, offset: int) -> None:
        self._open()
        assert self._handle is not None
        self._handle.seek(offset)
        self._processed_offset = offset
        self._read_position = offset
        self._buffer.clear()

    def _save_state(self, force: bool = False) -> None:
        if self._identity is None:
            return
        if not force and self._handle is None:
            return
        state = MonitorState(
            path=str(self.path),
            inode=self._identity[1],
            device=self._identity[0],
            offset=self._processed_offset,
            last_timestamp=self._last_timestamp,
        )
        self.state_store.save(state)

    def _process_line(self, raw: bytes) -> None:
        text = raw.decode("utf-8", errors="replace")
        if not text.strip():
            return
        event = self.parser.parse_line(text)
        if event is None:
            return
        self._last_timestamp = event.timestamp.isoformat()
        try:
            self.on_event(event)
        except Exception:
            LOGGER.exception("Event handler failed for a parsed SSH event")

    def _flush_partial(self) -> None:
        if not self._buffer:
            return
        raw = bytes(self._buffer)
        self._buffer.clear()
        self._processed_offset += len(raw)
        self._process_line(raw)

    def _drain(self) -> bool:
        if self._handle is None:
            return False
        changed = False
        while True:
            data = self._handle.read(self.read_chunk_size)
            if not data:
                break
            self._buffer.extend(data)
            self._read_position = self._handle.tell()
            changed = True
            while True:
                newline = self._buffer.find(b"\n")
                if newline < 0:
                    break
                raw = bytes(self._buffer[:newline])
                del self._buffer[: newline + 1]
                line_size = newline + 1
                self._process_line(raw)
                self._processed_offset += line_size
            if len(self._buffer) > self.max_partial_bytes:
                LOGGER.warning("Discarding oversized partial log line from %s", self.path)
                self._buffer.clear()
                self._processed_offset = self._read_position
        return changed

    def _handle_rotation(self) -> bool:
        self._drain()
        self._flush_partial()
        self._save_state(force=True)
        LOGGER.info("Log rotation detected for %s", self.path)
        self._open_at(0)
        return True

    def poll_once(self) -> bool:
        if not self._started:
            self.start()
        try:
            stat = self.path.stat()
        except FileNotFoundError:
            return False
        if self._identity != (stat.st_dev, stat.st_ino):
            changed = self._handle_rotation()
        else:
            if self._handle is None:
                self._open_at(self._processed_offset)
            if stat.st_size < self._read_position:
                LOGGER.info("Log truncation detected for %s", self.path)
                if self._handle is not None:
                    self._handle.close()
                self._open_at(0)
                changed = True
            else:
                changed = False
        changed = self._drain() or changed
        if changed:
            self._save_state()
        return changed

    def run_forever(self, tick: Callable[[], None] | None = None) -> None:
        if not self._started:
            self.start()
        while True:
            self.poll_once()
            if tick is not None:
                tick()
            time.sleep(self.poll_interval)

    def stop(self) -> None:
        if self._handle is not None:
            self._drain()
            self._flush_partial()
            self._save_state(force=True)
            self._handle.close()
            self._handle = None
        self._started = False

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
