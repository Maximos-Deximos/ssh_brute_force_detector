from __future__ import annotations

import datetime as dt
import unittest

import ssh_brute_force_detector as detector

ZONE = dt.timezone(dt.timedelta(hours=-3))
BASE = dt.datetime(2026, 10, 20, 15, 0, tzinfo=ZONE)


def event(seconds: int, user: str = "root", ip: str = "203.0.113.42", status: str = "failure") -> detector.AuthEvent:
    return detector.AuthEvent(
        timestamp=BASE + dt.timedelta(seconds=seconds),
        source_ip=ip,
        username=user,
        status=status,
        event_type="failed_password" if status == "failure" else "accepted",
        process="sshd-session",
        raw="fixture",
    )


class DetectionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = detector.DetectionEngine(
            detector.DetectionConfig(
                window_seconds=600,
                alert_threshold=5,
                rate_limit_threshold=8,
                block_threshold=12,
            )
        )

    def test_four_failures_do_not_trigger(self) -> None:
        results = [self.engine.record(event(i)) for i in range(4)]
        self.assertTrue(all(result is None for result in results))

    def test_fifth_failure_triggers_alert(self) -> None:
        for i in range(4):
            self.engine.record(event(i))
        detection = self.engine.record(event(4))
        assert detection is not None
        self.assertEqual(detection.failure_count, 5)
        self.assertEqual(detection.stage, "alert")
        self.assertTrue(detection.is_new_attack)
        self.assertEqual(detection.ip, "203.0.113.42")
        self.assertEqual(detection.usernames, ("root",))

    def test_escalation_milestones_fire_once(self) -> None:
        detections = [self.engine.record(event(i)) for i in range(12)]
        non_null = [item for item in detections if item is not None]
        self.assertEqual([item.failure_count for item in non_null], [5, 8, 12])
        self.assertEqual([item.stage for item in non_null], ["alert", "rate_limit", "block"])
        self.assertEqual([item.is_new_attack for item in non_null], [True, False, False])

    def test_failures_spread_beyond_window_do_not_trigger(self) -> None:
        for i in range(5):
            self.assertIsNone(self.engine.record(event(i * 700)))

    def test_ips_are_tracked_independently(self) -> None:
        for i in range(4):
            self.engine.record(event(i, ip="203.0.113.1"))
        self.assertIsNone(self.engine.record(event(4, ip="203.0.113.2")))
        detection = self.engine.record(event(5, ip="203.0.113.1"))
        assert detection is not None
        self.assertEqual(detection.ip, "203.0.113.1")
        self.assertEqual(detection.failure_count, 5)

    def test_success_resets_failure_streak(self) -> None:
        for i in range(5):
            self.engine.record(event(i))
        self.engine.record(event(5, status="success"))
        for i in range(6, 10):
            self.assertIsNone(self.engine.record(event(i)))
        detection = self.engine.record(event(10))
        assert detection is not None
        self.assertEqual(detection.failure_count, 5)

    def test_new_attack_after_window_expires(self) -> None:
        first = None
        for i in range(5):
            first = self.engine.record(event(i)) or first
        assert first is not None
        for i in range(4):
            self.assertIsNone(self.engine.record(event(1000 + i)))
        second = self.engine.record(event(1004))
        assert second is not None
        self.assertTrue(second.is_new_attack)
        self.assertEqual(second.failure_count, 5)

    def test_usernames_are_deduplicated(self) -> None:
        for i in range(4):
            self.engine.record(event(i, user="admin"))
        detection = self.engine.record(event(4, user="root"))
        assert detection is not None
        self.assertEqual(detection.usernames, ("admin", "root"))

    def test_non_failures_and_missing_ip_are_ignored(self) -> None:
        self.assertIsNone(self.engine.record(event(0, status="invalid_user")))
        self.assertIsNone(self.engine.record(event(0, status="disconnected")))
        missing = event(0)
        missing = detector.AuthEvent(
            timestamp=missing.timestamp,
            source_ip=None,
            username="root",
            status="failure",
            event_type="failed_password",
            process="sshd",
            raw="fixture",
        )
        self.assertIsNone(self.engine.record(missing))

    def test_invalid_threshold_order_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            detector.DetectionConfig(alert_threshold=10, rate_limit_threshold=8)


if __name__ == "__main__":
    unittest.main()