from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import ssh_brute_force_detector as detector


class ReputationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp.name) / "reputation.db"
        self.config = detector.ReputationConfig(
            whitelist=("10.0.0.0/8", "192.168.0.0/16"),
            blacklist=("198.51.100.0/24",),
            admin_ips=("203.0.113.200",),
            critical_ips=("203.0.113.201",),
        )
        self.store = detector.ReputationStore(
            self.db_path,
            self.config,
            local_ips=("192.0.2.10",),
            environ={},
        )

    def tearDown(self) -> None:
        self.store.close()
        self.temp.cleanup()

    def test_internal_networks_are_whitelisted(self) -> None:
        self.assertTrue(self.store.is_whitelisted("10.4.5.6"))
        self.assertTrue(self.store.is_whitelisted("192.168.1.20"))
        self.assertFalse(self.store.is_whitelisted("203.0.113.10"))
        self.assertTrue(self.store.is_protected("10.4.5.6"))

    def test_configured_blacklist_is_matched(self) -> None:
        self.assertTrue(self.store.is_blacklisted("198.51.100.8"))
        self.assertFalse(self.store.is_blacklisted("198.51.101.8"))

    def test_whitelist_overrides_blacklist(self) -> None:
        self.assertTrue(self.store.add_bad("203.0.113.42", "attack"))
        self.assertTrue(self.store.is_blacklisted("203.0.113.42"))
        self.store.add_good("203.0.113.0/24", "trusted partner")
        self.assertFalse(self.store.is_blacklisted("203.0.113.42"))
        self.assertTrue(self.store.is_whitelisted("203.0.113.42"))

    def test_protected_ips_cannot_be_marked_bad(self) -> None:
        for ip in (
            "127.0.0.1",
            "203.0.113.200",
            "203.0.113.201",
            "192.0.2.10",
            "10.0.0.5",
            "::1",
            "not-an-ip",
        ):
            with self.subTest(ip=ip):
                self.assertFalse(self.store.add_bad(ip, "should not be stored"))
                self.assertFalse(self.store.is_blacklisted(ip))

    def test_admin_ssh_and_local_addresses_are_protected(self) -> None:
        peer = detector.discover_ssh_peers(
            {"SSH_CONNECTION": "198.51.100.77 5555 192.0.2.10 22"}
        )
        self.assertIn("198.51.100.77", peer)
        store = detector.ReputationStore(
            ":memory:",
            detector.ReputationConfig(),
            local_ips=("192.0.2.10", "2001:db8::10"),
            environ={"SSH_CONNECTION": "198.51.100.77 5555 192.0.2.10 22"},
        )
        try:
            self.assertTrue(store.is_protected("198.51.100.77"))
            self.assertTrue(store.is_protected("192.0.2.10"))
            self.assertTrue(store.is_protected("2001:db8::10"))
        finally:
            store.close()

    def test_entries_persist_across_reopen(self) -> None:
        self.store.add_bad("203.0.113.50", "brute force", source="auto")
        self.store.add_good("203.0.114.0/24", "remote office")
        self.store.close()
        self.store = detector.ReputationStore(
            self.db_path,
            self.config,
            local_ips=("192.0.2.10",),
            environ={},
        )
        self.assertTrue(self.store.is_blacklisted("203.0.113.50"))
        self.assertTrue(self.store.is_whitelisted("203.0.114.9"))

    def test_ipv6_and_cidr_support(self) -> None:
        self.store.add_good("2001:db8:1::/48", "partner")
        self.store.add_bad("2001:db8:2::42", "attacker")
        self.assertTrue(self.store.is_whitelisted("2001:db8:1::99"))
        self.assertTrue(self.store.is_blacklisted("2001:db8:2::42"))

    def test_remove_entries_and_snapshot(self) -> None:
        self.store.add_bad("203.0.113.60", "test")
        self.store.remove_bad("203.0.113.60")
        self.assertFalse(self.store.is_blacklisted("203.0.113.60"))
        snapshot = self.store.snapshot()
        self.assertEqual(snapshot["bad"], [])
        self.assertIn("203.0.113.200", snapshot["protected"]["admin_ips"])

    def test_classification(self) -> None:
        self.assertEqual(self.store.classify("10.1.1.1"), "protected")
        self.assertEqual(self.store.classify("198.51.100.1"), "bad")
        self.assertEqual(self.store.classify("203.0.113.1"), "unknown")
        self.store.add_good("203.0.113.1", "trusted")
        self.assertEqual(self.store.classify("203.0.113.1"), "protected")


if __name__ == "__main__":
    unittest.main()
