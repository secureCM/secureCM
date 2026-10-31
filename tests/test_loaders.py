import json
import unittest
from datetime import datetime, timezone
from pathlib import Path

FIXTURE_PATH = Path(__file__).parent.parent / "fixtures" / "synthetic.json"


class TestLoaders(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(FIXTURE_PATH) as f:
            cls.data = json.load(f)

    def _loaders(self):
        from gcp_policy_analyzer.loaders import (
            load_iam_policies,
            load_vpc_firewall_rules,
            load_network_firewall_policies,
            load_audit_changes,
            _parse_ts,
        )
        return load_iam_policies, load_vpc_firewall_rules, load_network_firewall_policies, load_audit_changes, _parse_ts

    def test_load_iam_policies_from_fixture(self):
        load_iam_policies, *_ = self._loaders()
        policies = load_iam_policies(self.data)
        self.assertGreaterEqual(len(policies), 1)
        self.assertTrue(policies[0].bindings[0].role.startswith("roles/"))

    def test_load_vpc_rules_parses_fields(self):
        _, load_vpc_firewall_rules, *_ = self._loaders()
        rules = load_vpc_firewall_rules(self.data)
        world_open = [r for r in rules if "0.0.0.0/0" in r.source_ranges]
        self.assertTrue(len(world_open) >= 1)
        self.assertIsInstance(world_open[0].labels, dict)

    def test_load_audit_changes_window_filter(self):
        *_, load_audit_changes, _ = self._loaders()
        # naive datetimes → treated UTC; anchor is 2026-10-31T00:00:00Z
        start = datetime(2026, 10, 24, 0, 0, 0)   # 7 days before anchor
        end   = datetime(2026, 10, 31, 23, 59, 59)
        changes = load_audit_changes(self.data, start=start, end=end)
        timestamps = [c.timestamp for c in changes]
        # the 10-day-old change (2026-10-21T08:00:00Z) must be excluded
        for ts in timestamps:
            self.assertGreaterEqual(ts, datetime(2026, 10, 24, tzinfo=timezone.utc))

    def test_partial_envelope_returns_empty(self):
        load_iam_policies, load_vpc_firewall_rules, load_network_firewall_policies, load_audit_changes, _ = self._loaders()
        self.assertEqual(load_iam_policies({}), [])
        self.assertEqual(load_vpc_firewall_rules({}), [])
        self.assertEqual(load_network_firewall_policies({}), [])
        self.assertEqual(load_audit_changes({}), [])

    def test_timestamp_z_suffix_parsed_aware(self):
        *_, _parse_ts = self._loaders()
        ts = _parse_ts("2026-10-29T14:03:11Z")
        self.assertIsNotNone(ts.tzinfo)


if __name__ == "__main__":
    unittest.main()
