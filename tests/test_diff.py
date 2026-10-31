import json
import unittest
import copy
from datetime import datetime, timezone
from pathlib import Path

FIXTURE_PATH = Path(__file__).parent.parent / "fixtures" / "synthetic.json"


class TestDiffPolicies(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(FIXTURE_PATH) as f:
            cls.data = json.load(f)

    def _diff_policies(self):
        from gcp_policy_analyzer.diff import diff_policies
        return diff_policies

    def test_diff_detects_create_update_delete(self):
        """Test that diff_policies emits CREATE, UPDATE, DELETE actions."""
        diff_policies = self._diff_policies()

        # Start with a copy of vpc firewall rules from fixture
        old_rules = copy.deepcopy(self.data["vpc_firewall_rules"])
        new_rules = copy.deepcopy(self.data["vpc_firewall_rules"])

        # old_rules: ["prod-allow-tcp-8080", "prod-deny-all-egress"]
        # new_rules: modify to have 1 existing (modified), 1 deleted, 1 created

        # Modify the first rule (UPDATE)
        new_rules[0]["sourceRanges"] = ["192.168.0.0/16"]

        # Remove the second rule (DELETE)
        new_rules = new_rules[:1]

        # Add a new rule (CREATE)
        new_rule = {
            "name": "prod-allow-https",
            "network": "projects/example-prod-project/global/networks/prod-network",
            "direction": "INGRESS",
            "priority": 1001,
            "sourceRanges": ["0.0.0.0/0"],
            "allowed": [{"IPProtocol": "tcp", "ports": ["443"]}],
            "denied": [],
            "disabled": False,
            "logConfig": {"enable": False},
            "labels": {"env": "prod"}
        }
        new_rules.append(new_rule)

        # Call diff_policies
        changes = diff_policies(old_rules, new_rules, "firewall_rule")

        # Verify we have 3 changes
        self.assertEqual(len(changes), 3)

        # Extract actions
        actions = {c.action for c in changes}
        self.assertEqual(actions, {"CREATE", "UPDATE", "DELETE"})

        # Verify each change type
        create_changes = [c for c in changes if c.action == "CREATE"]
        update_changes = [c for c in changes if c.action == "UPDATE"]
        delete_changes = [c for c in changes if c.action == "DELETE"]

        self.assertEqual(len(create_changes), 1)
        self.assertEqual(len(update_changes), 1)
        self.assertEqual(len(delete_changes), 1)

        # Verify properties
        for change in changes:
            self.assertEqual(change.resource_type, "firewall_rule")
            self.assertIsInstance(change.timestamp, datetime)
            self.assertTrue(change.timestamp.tzinfo is not None)
            self.assertEqual(change.principal, "")
            self.assertIsInstance(change.before, dict)
            self.assertIsInstance(change.after, dict)

    def test_diff_identical_lists_empty(self):
        """Test that diffing identical lists returns empty."""
        diff_policies = self._diff_policies()

        rules = copy.deepcopy(self.data["vpc_firewall_rules"])
        changes = diff_policies(rules, copy.deepcopy(rules), "firewall_rule")

        self.assertEqual(len(changes), 0)

    def test_diff_iam_policies(self):
        """Test diffing IAM policies (keyed by resource, not name)."""
        diff_policies = self._diff_policies()

        old_policies = copy.deepcopy(self.data["iam_policies"])
        new_policies = copy.deepcopy(self.data["iam_policies"])

        # Modify bindings in existing policy (UPDATE)
        new_policies[0]["bindings"].append({
            "role": "roles/viewer",
            "members": ["user:viewer@example.com"]
        })

        # Add a new policy (CREATE)
        new_policies.append({
            "resource": "projects/other-project",
            "labels": {"env": "dev"},
            "bindings": [
                {
                    "role": "roles/editor",
                    "members": ["serviceAccount:editor@other-project.iam.gserviceaccount.com"]
                }
            ]
        })

        changes = diff_policies(old_policies, new_policies, "iam_policy")

        # Should have 1 UPDATE and 1 CREATE
        self.assertEqual(len(changes), 2)
        actions = {c.action for c in changes}
        self.assertEqual(actions, {"CREATE", "UPDATE"})


if __name__ == "__main__":
    unittest.main()
