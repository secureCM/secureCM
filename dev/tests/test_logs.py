import json
import unittest
from datetime import datetime, timezone
from pathlib import Path

FIXTURE_PATH = Path(__file__).parent.parent / "fixtures" / "synthetic.json"


class TestLogsModule(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(FIXTURE_PATH) as f:
            cls.data = json.load(f)

    def _import_logs(self):
        from gcp_policy_analyzer.logs import filter_log_entries, correlate_changes_with_logs
        return filter_log_entries, correlate_changes_with_logs

    def test_filter_by_principal_and_window(self):
        """Test filter_log_entries with principal and time window.

        Uses flat entries (load_log_entries flattens native protoPayload form).
        """
        filter_log_entries, _ = self._import_logs()
        from gcp_policy_analyzer.loaders import load_log_entries

        # Flatten native log_entries before filtering
        entries = load_log_entries(self.data)

        # Filter by principal — terraform-deployer has multiple change entries in new fixture
        terraform_entries = filter_log_entries(
            entries,
            principal="terraform-deployer@example-prod-project.iam.gserviceaccount.com"
        )
        self.assertGreaterEqual(len(terraform_entries), 1)

        # Filter by nonexistent principal
        no_entries = filter_log_entries(
            entries,
            principal="nobody@nowhere.example.com"
        )
        self.assertEqual(len(no_entries), 0)

        # Filter by time window: 16:22:00–16:23:00 should include the patch at 16:22:41
        start = datetime(2026, 10, 30, 16, 22, 0, tzinfo=timezone.utc)
        end = datetime(2026, 10, 30, 16, 23, 0, tzinfo=timezone.utc)
        window_entries = filter_log_entries(entries, start=start, end=end)
        # patch at 16:22:41 should be included; insert at 16:22:40 too
        self.assertGreaterEqual(len(window_entries), 1)
        timestamps = {e["timestamp"] for e in window_entries}
        self.assertIn("2026-10-30T16:22:41Z", timestamps)

        # Filter by methods — compute.firewalls.patch entries exist in fixture
        methods_entries = filter_log_entries(
            entries,
            methods=["compute.firewalls.patch"]
        )
        self.assertGreaterEqual(len(methods_entries), 1)
        for e in methods_entries:
            self.assertEqual(e["methodName"], "compute.firewalls.patch")

    def test_correlate_attaches_matching_entry(self):
        """Test correlate_changes_with_logs attaches evidence to matching changes.

        Uses flat entries from load_log_entries (native protoPayload flattened).
        """
        _, correlate_changes_with_logs = self._import_logs()

        from gcp_policy_analyzer.loaders import load_audit_changes, load_log_entries
        changes = load_audit_changes(self.data)
        # Use flat entries (required by correlate_changes_with_logs)
        entries = load_log_entries(self.data)

        # Correlate
        correlated = correlate_changes_with_logs(changes, entries)

        # Should return list of dicts with "change" and "evidence" keys
        self.assertIsInstance(correlated, list)
        self.assertGreater(len(correlated), 0)

        # Check structure of each result
        for result in correlated:
            self.assertIn("change", result)
            self.assertIn("evidence", result)
            self.assertIsInstance(result["evidence"], list)

        # Firewall changes by terraform-deployer should exist and have evidence
        firewall_changes = [
            r for r in correlated
            if r["change"].resource_type == "firewall_rule"
            and r["change"].principal == "terraform-deployer@example-prod-project.iam.gserviceaccount.com"
        ]
        self.assertGreaterEqual(len(firewall_changes), 1)

        # At least one firewall change should have evidence
        changes_with_evidence = [r for r in firewall_changes if len(r["evidence"]) > 0]
        self.assertGreater(len(changes_with_evidence), 0,
                           "At least one terraform-deployer firewall change should have evidence")

        # Each evidence entry should be a dict with the log entry fields
        for result in changes_with_evidence:
            for entry in result["evidence"]:
                self.assertIn("methodName", entry)
                self.assertIn("principalEmail", entry)
                self.assertIn("timestamp", entry)
                self.assertIn("resourceName", entry)

        # IAM change should not have evidence (no matching log entries for IAM resource paths)
        iam_changes = [r for r in correlated if r["change"].resource_type == "iam_policy"]
        self.assertGreater(len(iam_changes), 0)

    def test_filter_skips_missing_timestamps(self):
        """Test that entries with missing or empty timestamps are skipped in windowed filters."""
        filter_log_entries, _ = self._import_logs()

        # Create entries, some with missing/empty timestamps
        entries = [
            {
                "methodName": "v1.compute.firewalls.patch",
                "principalEmail": "user@example.com",
                "timestamp": "2026-10-30T16:22:41Z",
                "resourceName": "projects/p/global/firewalls/rule1"
            },
            {
                "methodName": "v1.compute.firewalls.patch",
                "principalEmail": "user@example.com",
                "timestamp": "",  # empty timestamp
                "resourceName": "projects/p/global/firewalls/rule2"
            },
            {
                "methodName": "v1.compute.firewalls.patch",
                "principalEmail": "user@example.com",
                # missing timestamp key
                "resourceName": "projects/p/global/firewalls/rule3"
            }
        ]

        # Filter with time window
        start = datetime(2026, 10, 30, 16, 22, 0, tzinfo=timezone.utc)
        end = datetime(2026, 10, 30, 16, 23, 0, tzinfo=timezone.utc)
        result = filter_log_entries(entries, start=start, end=end)

        # Only the entry with valid timestamp should pass
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["resourceName"], "projects/p/global/firewalls/rule1")

    def test_correlate_matching_rules(self):
        """Test the specific matching rules for evidence correlation."""
        _, correlate_changes_with_logs = self._import_logs()

        from gcp_policy_analyzer.diff import Change
        from gcp_policy_analyzer.loaders import _parse_ts

        # Create a synthetic change at a specific time
        change_time = _parse_ts("2026-10-30T16:22:41Z")
        change = Change(
            resource="projects/example-prod-project/global/firewalls/prod-allow-tcp-8080",
            resource_type="firewall_rule",
            action="UPDATE",
            before={},
            after={},
            timestamp=change_time,
            principal="terraform-deployer@example-prod-project.iam.gserviceaccount.com",
            labels={}
        )

        # Log entry with exact timestamp match and resource match
        matching_entry = {
            "methodName": "v1.compute.firewalls.patch",
            "principalEmail": "terraform-deployer@example-prod-project.iam.gserviceaccount.com",
            "callerIp": "203.0.113.10",
            "timestamp": "2026-10-30T16:22:41Z",
            "resourceName": "projects/example-prod-project/global/firewalls/prod-allow-tcp-8080"
        }

        # Entry with wrong principal
        wrong_principal = {
            "methodName": "v1.compute.firewalls.patch",
            "principalEmail": "other@example.com",
            "callerIp": "203.0.113.10",
            "timestamp": "2026-10-30T16:22:41Z",
            "resourceName": "projects/example-prod-project/global/firewalls/prod-allow-tcp-8080"
        }

        # Entry with too large time delta (> 300s)
        too_old = {
            "methodName": "v1.compute.firewalls.patch",
            "principalEmail": "terraform-deployer@example-prod-project.iam.gserviceaccount.com",
            "callerIp": "203.0.113.10",
            "timestamp": "2026-10-30T16:16:00Z",  # 5+ minutes before change
            "resourceName": "projects/example-prod-project/global/firewalls/prod-allow-tcp-8080"
        }

        # Entry with wrong resource (last 2 segments don't match)
        wrong_resource = {
            "methodName": "v1.compute.firewalls.patch",
            "principalEmail": "terraform-deployer@example-prod-project.iam.gserviceaccount.com",
            "callerIp": "203.0.113.10",
            "timestamp": "2026-10-30T16:22:41Z",
            "resourceName": "projects/example-prod-project/global/firewalls/other-rule"
        }

        # Test with all entries
        entries = [matching_entry, wrong_principal, too_old, wrong_resource]
        results = correlate_changes_with_logs([change], entries)

        self.assertEqual(len(results), 1)
        result = results[0]
        self.assertEqual(len(result["evidence"]), 1)
        self.assertEqual(result["evidence"][0]["timestamp"], "2026-10-30T16:22:41Z")

    def test_correlate_suffix_boundary_match(self):
        """Test that suffix matching respects segment boundaries."""
        _, correlate_changes_with_logs = self._import_logs()

        from gcp_policy_analyzer.diff import Change
        from gcp_policy_analyzer.loaders import _parse_ts

        change_time = _parse_ts("2026-10-30T16:22:41Z")
        # Change resource ends with "firewalls/allow-x"
        change = Change(
            resource="projects/p/global/firewalls/allow-x",
            resource_type="firewall_rule",
            action="UPDATE",
            before={},
            after={},
            timestamp=change_time,
            principal="user@example.com",
            labels={}
        )

        # Entry with correct boundary-aware match
        correct = {
            "methodName": "v1.compute.firewalls.patch",
            "principalEmail": "user@example.com",
            "timestamp": "2026-10-30T16:22:41Z",
            "resourceName": "projects/p/global/firewalls/allow-x"
        }

        # Entry with correct last 2 segments via "/" boundary
        correct_nested = {
            "methodName": "v1.compute.firewalls.patch",
            "principalEmail": "user@example.com",
            "timestamp": "2026-10-30T16:22:41Z",
            "resourceName": "projects/other-project/zones/us-central1-a/firewalls/allow-x"
        }

        # Entry with false-positive suffix match (crosses segment boundary)
        # "sillyfirewalls/allow-x" ends with "firewalls/allow-x" but wrong boundary
        false_positive = {
            "methodName": "v1.compute.firewalls.patch",
            "principalEmail": "user@example.com",
            "timestamp": "2026-10-30T16:22:41Z",
            "resourceName": "projects/p/global/sillyfirewalls/allow-x"
        }

        entries = [correct, correct_nested, false_positive]
        results = correlate_changes_with_logs([change], entries)

        self.assertEqual(len(results), 1)
        result = results[0]
        # Only correct and correct_nested should match, not false_positive
        self.assertEqual(len(result["evidence"]), 2)
        evidence_resources = {e["resourceName"] for e in result["evidence"]}
        self.assertEqual(evidence_resources, {
            "projects/p/global/firewalls/allow-x",
            "projects/other-project/zones/us-central1-a/firewalls/allow-x"
        })


    def test_filter_accepts_naive_datetime(self):
        """I6: filter_log_entries must not raise TypeError when start/end are naive datetimes."""
        filter_log_entries, _ = self._import_logs()

        entries = [
            {
                "methodName": "v1.compute.firewalls.patch",
                "principalEmail": "user@example.com",
                "timestamp": "2026-10-30T16:22:41Z",
                "resourceName": "projects/p/global/firewalls/rule1",
            }
        ]
        # naive datetimes (no tzinfo) — must not raise
        start = datetime(2026, 10, 30, 16, 22, 0)   # naive
        end = datetime(2026, 10, 30, 16, 23, 0)     # naive
        try:
            result = filter_log_entries(entries, start=start, end=end)
        except TypeError as exc:
            self.fail(f"filter_log_entries raised TypeError with naive datetimes: {exc}")
        self.assertEqual(len(result), 1)

    def test_correlate_by_actor_flags_shared_and_anomalous_ips(self):
        """correlate_by_actor groups activity per principal and surfaces the join signal:
        an IP used by more than one actor, and an IP that is a minority for an actor."""
        from gcp_policy_analyzer.logs import correlate_by_actor

        # alice uses one IP normally; sa-bot uses .10 for 4 events and .99 once (anomalous);
        # attacker uses .99 (its only event). .99 is shared across sa-bot and attacker.
        entries = [
            {"principalEmail": "alice@corp.example", "callerIp": "10.0.0.1",
             "methodName": "m1", "timestamp": "2026-11-01T10:00:00Z", "resourceName": "r"},
            {"principalEmail": "sa-bot@p.iam.gserviceaccount.com", "callerIp": "10.0.0.2",
             "methodName": "m2", "timestamp": "2026-11-02T10:00:00Z", "resourceName": "r"},
            {"principalEmail": "sa-bot@p.iam.gserviceaccount.com", "callerIp": "10.0.0.2",
             "methodName": "m2", "timestamp": "2026-11-02T11:00:00Z", "resourceName": "r"},
            {"principalEmail": "sa-bot@p.iam.gserviceaccount.com", "callerIp": "10.0.0.2",
             "methodName": "m2", "timestamp": "2026-11-02T12:00:00Z", "resourceName": "r"},
            {"principalEmail": "sa-bot@p.iam.gserviceaccount.com", "callerIp": "10.0.0.2",
             "methodName": "m2", "timestamp": "2026-11-02T13:00:00Z", "resourceName": "r"},
            {"principalEmail": "sa-bot@p.iam.gserviceaccount.com", "callerIp": "198.51.100.99",
             "methodName": "firewalls.patch", "timestamp": "2026-11-03T02:00:00Z", "resourceName": "r"},
            {"principalEmail": "attacker@evil.example", "callerIp": "198.51.100.99",
             "methodName": "keys.create", "timestamp": "2026-11-01T02:00:00Z", "resourceName": "r"},
        ]
        report = correlate_by_actor([], entries)

        # shared_ips surfaces the smoking gun: 198.51.100.99 used by two distinct actors
        self.assertIn("198.51.100.99", report["shared_ips"])
        self.assertEqual(
            set(report["shared_ips"]["198.51.100.99"]),
            {"sa-bot@p.iam.gserviceaccount.com", "attacker@evil.example"},
        )
        self.assertNotIn("10.0.0.1", report["shared_ips"])  # single-actor IP not shared

        # per-actor anomalous IP: sa-bot's .99 is a 1-of-5 minority → flagged
        by_actor = {a["actor"]: a for a in report["actors"]}
        self.assertIn("198.51.100.99", by_actor["sa-bot@p.iam.gserviceaccount.com"]["anomalous_ips"])
        self.assertNotIn("10.0.0.2", by_actor["sa-bot@p.iam.gserviceaccount.com"]["anomalous_ips"])

    def test_correlate_by_actor_deterministic_order_on_ties(self):
        """Actors with equal sort keys must order deterministically (by actor name),
        not by set-iteration order — this output is model-facing and cached across turns."""
        from gcp_policy_analyzer.logs import correlate_by_actor
        # three actors, identical activity (1 log each, no anomalies) → all keys tie
        entries = [
            {"principalEmail": p, "callerIp": "10.0.0.1", "methodName": "m",
             "timestamp": "2026-11-01T10:00:00Z", "resourceName": "r"}
            for p in ("zeta@x", "alpha@x", "mu@x")
        ]
        order = [a["actor"] for a in correlate_by_actor([], entries)["actors"]]
        self.assertEqual(order, ["alpha@x", "mu@x", "zeta@x"])  # ascending actor name on ties

    def test_correlate_by_actor_empty(self):
        """No entries → empty actors list and empty shared_ips."""
        from gcp_policy_analyzer.logs import correlate_by_actor
        report = correlate_by_actor([], [])
        self.assertEqual(report["actors"], [])
        self.assertEqual(report["shared_ips"], {})


if __name__ == "__main__":
    unittest.main()
