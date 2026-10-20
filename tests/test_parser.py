from __future__ import annotations

import datetime as dt
import json
import tempfile
import unittest
from pathlib import Path

from tests.helpers import FIXTURES

import ssh_brute_force_detector as detector


class ParserTests(unittest.TestCase):
    def setUp(self) -> None:
        self.parser = detector.LogParser(
            reference_time=lambda: dt.datetime(2026, 10, 20, 15, 30, tzinfo=dt.timezone(dt.timedelta(hours=-3)))
        )

    def test_parses_accepted_password(self) -> None:
        line = (
            "2026-10-20T14:56:18.442272-03:00 urubu sshd-session[13009]: "
            "Accepted password for alice from 192.168.122.10 port 37160 ssh2"
        )
        event = self.parser.parse_line(line)
        self.assertIsNotNone(event)
        assert event is not None
        self.assertEqual(event.status, "success")
        self.assertEqual(event.event_type, "accepted")
        self.assertEqual(event.source_ip, "192.168.122.10")
        self.assertEqual(event.username, "alice")
        self.assertEqual(event.process, "sshd-session")
        self.assertEqual(event.timestamp.utcoffset(), dt.timedelta(hours=-3))

    def test_parses_failed_password_invalid_user(self) -> None:
        line = (
            "2026-10-20T15:01:00.000000-03:00 host sshd[10]: "
            "Failed password for invalid user admin from 203.0.113.50 port 50000 ssh2"
        )
        event = self.parser.parse_line(line)
        assert event is not None
        self.assertEqual(event.status, "failure")
        self.assertEqual(event.event_type, "failed_password")
        self.assertEqual(event.username, "admin")
        self.assertEqual(event.source_ip, "203.0.113.50")

    def test_parses_ipv6_and_publickey_failure(self) -> None:
        line = (
            "2026-10-20T15:01:10.000000-03:00 host sshd-session[10]: "
            "Failed publickey for root from 2001:db8::10 port 50002 ssh2"
        )
        event = self.parser.parse_line(line)
        assert event is not None
        self.assertEqual(event.source_ip, "2001:db8::10")
        self.assertEqual(event.username, "root")
        self.assertEqual(event.status, "failure")

    def test_parses_invalid_user_and_max_attempts(self) -> None:
        invalid = self.parser.parse_line(
            "2026-10-20T15:01:05.000000-03:00 host sshd-session[10]: "
            "Invalid user oracle from 203.0.113.50 port 50001"
        )
        maximum = self.parser.parse_line(
            "2026-10-20T15:01:15.000000-03:00 host sshd-session[10]: "
            "maximum authentication attempts exceeded for invalid user test "
            "from 198.51.100.8 port 50003 ssh2 [preauth]"
        )
        assert invalid is not None and maximum is not None
        self.assertEqual(invalid.status, "invalid_user")
        self.assertEqual(maximum.status, "max_attempts")
        self.assertEqual(maximum.source_ip, "198.51.100.8")

    def test_parses_legacy_timestamp(self) -> None:
        event = self.parser.parse_line(
            "Oct 20 14:56:18 host sshd[1234]: "
            "Failed password for bob from 198.51.100.7 port 22 ssh2"
        )
        assert event is not None
        self.assertEqual(event.timestamp.year, 2026)
        self.assertEqual(event.timestamp.month, 10)
        self.assertEqual(event.timestamp.day, 20)
        self.assertEqual(event.source_ip, "198.51.100.7")

    def test_ignores_non_ssh_and_irrelevant_lines(self) -> None:
        ignored = [
            "2026-10-20T15:02:00-03:00 host sudo: session opened",
            "2026-10-20T15:02:01-03:00 host CRON[1]: session opened",
            "2026-10-20T15:02:02-03:00 host dbus-daemon[1]: Failed to activate",
            "not a syslog line",
            "",
            "\x00binary",
        ]
        for line in ignored:
            with self.subTest(line=line):
                self.assertIsNone(self.parser.parse_line(line))

    def test_other_sshd_events_are_preserved_without_credentials(self) -> None:
        event = self.parser.parse_line(
            "2026-10-20T15:02:03-03:00 host sshd-session[1]: Server listening on 0.0.0.0 port 22."
        )
        assert event is not None
        self.assertEqual(event.status, "other")
        self.assertIsNone(event.source_ip)
        self.assertNotIn("password", event.to_record())

    def test_fixture_and_jsonl_output(self) -> None:
        parser = detector.LogParser()
        events = []
        with (FIXTURES / "auth.log").open(encoding="utf-8") as handle:
            for line in handle:
                event = parser.parse_line(line)
                if event is not None:
                    events.append(event)
        self.assertEqual(len(events), 8)
        self.assertEqual(sum(event.status == "failure" for event in events), 3)
        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "events.jsonl"
            writer = detector.JsonlEventLogger(output)
            for event in events:
                writer.append(event.to_record())
            records = [json.loads(line) for line in output.read_text().splitlines()]
            self.assertEqual(len(records), 8)
            self.assertEqual(set(records[0]), {
                "timestamp", "source_ip", "username", "status", "event_type", "process"
            })


if __name__ == "__main__":
    unittest.main()
