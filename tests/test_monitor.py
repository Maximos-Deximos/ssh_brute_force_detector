from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import ssh_brute_force_detector as detector


def failure_line(timestamp: str, user: str, ip: str) -> str:
    return (
        f"{timestamp} host sshd-session[1]: Failed password for {user} "
        f"from {ip} port 50000 ssh2\n"
    )


class MonitorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.log_path = self.root / "auth.log"
        self.state_path = self.root / "state.json"
        self.events: list[detector.AuthEvent] = []

    def tearDown(self) -> None:
        self.temp.cleanup()

    def monitor(self, from_end: bool = False) -> detector.LogMonitor:
        return detector.LogMonitor(
            self.log_path,
            detector.LogParser(),
            detector.MonitorStateStore(self.state_path),
            self.events.append,
            from_end=from_end,
            poll_interval=0.05,
            read_chunk_size=7,
        )

    def append(self, text: str) -> None:
        with self.log_path.open("a", encoding="utf-8") as handle:
            handle.write(text)

    def test_reads_new_lines_and_restart_does_not_duplicate(self) -> None:
        self.log_path.write_text(
            failure_line("2026-10-20T15:00:00-03:00", "alice", "203.0.113.1"),
            encoding="utf-8",
        )
        monitor = self.monitor()
        monitor.start()
        self.assertTrue(monitor.poll_once())
        self.assertEqual(len(self.events), 1)
        self.assertEqual(self.events[0].username, "alice")
        monitor.stop()

        restarted = self.monitor()
        restarted.start()
        self.assertFalse(restarted.poll_once())
        self.assertEqual(len(self.events), 1)
        self.append(failure_line("2026-10-20T15:01:00-03:00", "bob", "203.0.113.2"))
        self.assertTrue(restarted.poll_once())
        self.assertEqual(len(self.events), 2)
        self.assertEqual(self.events[1].username, "bob")
        restarted.stop()

        second_restart = self.monitor()
        second_restart.start()
        self.assertFalse(second_restart.poll_once())
        self.assertEqual(len(self.events), 2)
        second_restart.stop()

    def test_from_end_ignores_existing_lines(self) -> None:
        self.log_path.write_text(
            failure_line("2026-10-20T15:00:00-03:00", "old", "203.0.113.1"),
            encoding="utf-8",
        )
        monitor = self.monitor(from_end=True)
        monitor.start()
        self.assertFalse(monitor.poll_once())
        self.assertEqual(self.events, [])
        self.append(failure_line("2026-10-20T15:01:00-03:00", "new", "203.0.113.2"))
        self.assertTrue(monitor.poll_once())
        self.assertEqual(len(self.events), 1)
        self.assertEqual(self.events[0].username, "new")
        monitor.stop()

    def test_rotation_drains_old_file_and_reads_new_file(self) -> None:
        self.log_path.write_text(
            failure_line("2026-10-20T15:00:00-03:00", "alice", "203.0.113.1"),
            encoding="utf-8",
        )
        monitor = self.monitor()
        monitor.start()
        monitor.poll_once()
        self.assertEqual(len(self.events), 1)

        self.append(failure_line("2026-10-20T15:00:10-03:00", "alice", "203.0.113.1"))
        rotated = self.root / "auth.log.1"
        self.log_path.rename(rotated)
        self.log_path.write_text(
            failure_line("2026-10-20T15:00:20-03:00", "bob", "203.0.113.2"),
            encoding="utf-8",
        )
        self.assertTrue(monitor.poll_once())
        self.assertEqual([event.username for event in self.events], ["alice", "alice", "bob"])
        monitor.stop()

    def test_truncation_is_detected(self) -> None:
        self.log_path.write_text(
            failure_line("2026-10-20T15:00:00-03:00", "long-username", "203.0.113.1"),
            encoding="utf-8",
        )
        monitor = self.monitor()
        monitor.start()
        monitor.poll_once()
        self.assertEqual(len(self.events), 1)

        self.log_path.write_text(
            failure_line("2026-10-20T15:01:00-03:00", "x", "203.0.113.2"),
            encoding="utf-8",
        )
        self.assertTrue(monitor.poll_once())
        self.assertEqual(len(self.events), 2)
        self.assertEqual(self.events[-1].username, "x")
        monitor.stop()

    def test_partial_line_is_buffered_until_newline(self) -> None:
        self.log_path.write_text("", encoding="utf-8")
        monitor = self.monitor()
        monitor.start()
        self.append("2026-10-20T15:00:00-03:00 host sshd[1]: Failed password for")
        monitor.poll_once()
        self.assertEqual(self.events, [])
        self.append(" carol from 203.0.113.3 port 22 ssh2\n")
        self.assertTrue(monitor.poll_once())
        self.assertEqual(len(self.events), 1)
        self.assertEqual(self.events[0].username, "carol")
        monitor.stop()

    def test_resumes_after_rotation_while_stopped(self) -> None:
        self.log_path.write_text(
            failure_line("2026-10-20T15:00:00-03:00", "alice", "203.0.113.1"),
            encoding="utf-8",
        )
        monitor = self.monitor()
        monitor.start()
        monitor.poll_once()
        monitor.stop()
        rotated = self.root / "auth.log.1"
        self.log_path.rename(rotated)
        self.log_path.write_text(
            failure_line("2026-10-20T15:02:00-03:00", "new-user", "203.0.113.4"),
            encoding="utf-8",
        )
        restarted = self.monitor()
        restarted.start()
        restarted.poll_once()
        self.assertEqual([event.username for event in self.events], ["alice", "new-user"])
        restarted.stop()


if __name__ == "__main__":
    unittest.main()