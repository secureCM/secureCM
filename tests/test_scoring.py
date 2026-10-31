"""Tests for scoring.py — TDD, Task 3."""
import json
import pathlib
import unittest
from datetime import datetime, timezone

FIXTURE = json.loads(
    (pathlib.Path(__file__).parent.parent / "fixtures" / "synthetic.json").read_text()
)

from gcp_policy_analyzer.scoring import (
    ExposureScore,
    RiskScore,
    ChangeClass,
    score_rule_exposure,
    score_iam_binding,
    classify_change,
)
from gcp_policy_analyzer.diff import Change
from gcp_policy_analyzer.loaders import load_vpc_firewall_rules, load_audit_changes


def _ts(s: str) -> datetime:
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


class TestScoreRuleExposure(unittest.TestCase):
    def setUp(self):
        self.rules = load_vpc_firewall_rules(FIXTURE)
        # prod-allow-tcp-8080: 0.0.0.0/0, logging disabled
        self.world_open = next(r for r in self.rules if r.name == "prod-allow-tcp-8080")

    def test_world_open_rule_flags_and_score(self):
        result = score_rule_exposure(self.world_open)
        self.assertIsInstance(result, ExposureScore)
        self.assertIn("open_to_world", result.flags)
        self.assertGreaterEqual(result.score, 40)

    def test_logging_disabled_flag(self):
        result = score_rule_exposure(self.world_open)
        self.assertIn("logging_disabled", result.flags)

    def test_dict_input_accepted(self):
        rule_dict = {
            "source_ranges": ["0.0.0.0/0"],
            "allowed": [],
            "denied": [],
            "log_enabled": False,
            "priority": 500,
        }
        result = score_rule_exposure(rule_dict)
        self.assertIn("open_to_world", result.flags)
        self.assertIn("high_priority", result.flags)

    def test_all_ports_flag(self):
        # No ports listed → all_ports
        rule_dict = {
            "source_ranges": ["10.0.0.0/8"],
            "allowed": [{"IPProtocol": "tcp"}],
            "denied": [],
            "log_enabled": True,
            "priority": 1000,
        }
        result = score_rule_exposure(rule_dict)
        self.assertIn("all_ports", result.flags)

    def test_broad_protocol_flag(self):
        rule_dict = {
            "source_ranges": ["10.0.0.0/8"],
            "allowed": [{"IPProtocol": "all"}],
            "denied": [],
            "log_enabled": True,
            "priority": 1000,
        }
        result = score_rule_exposure(rule_dict)
        self.assertIn("broad_protocol", result.flags)

    def test_high_priority_flag(self):
        rule_dict = {
            "source_ranges": ["10.0.0.0/8"],
            "allowed": [],
            "denied": [],
            "log_enabled": True,
            "priority": 999,
        }
        result = score_rule_exposure(rule_dict)
        self.assertIn("high_priority", result.flags)


class TestScoreIamBinding(unittest.TestCase):
    def test_roles_owner_is_high_privilege(self):
        from gcp_policy_analyzer.loaders import IamBinding
        binding = IamBinding(role="roles/owner", members=["user:alice@example.com"])
        result = score_iam_binding(binding)
        self.assertIsInstance(result, RiskScore)
        self.assertTrue(result.is_high_privilege)

    def test_toxic_combination(self):
        from gcp_policy_analyzer.loaders import IamBinding
        binding = IamBinding(
            role="roles/iam.serviceAccountTokenCreator",
            members=["serviceAccount:sa@project.iam.gserviceaccount.com"],
        )
        result = score_iam_binding(binding)
        self.assertTrue(result.toxic_combination)
        self.assertTrue(result.service_account_member)

    def test_dict_input_accepted(self):
        result = score_iam_binding({"role": "roles/owner", "members": []})
        self.assertTrue(result.is_high_privilege)

    def test_low_privilege_role_not_flagged(self):
        from gcp_policy_analyzer.loaders import IamBinding
        binding = IamBinding(role="roles/viewer", members=["user:bob@example.com"])
        result = score_iam_binding(binding)
        self.assertFalse(result.is_high_privilege)
        self.assertFalse(result.toxic_combination)

    def test_toxic_combinations_override(self):
        """Custom toxic_combinations parameter overrides module default."""
        from gcp_policy_analyzer.loaders import IamBinding
        binding = IamBinding(
            role="roles/owner",  # not in default TOXIC_COMBINATIONS
            members=["serviceAccount:sa@project.iam.gserviceaccount.com"],
        )
        # Default: not toxic
        result_default = score_iam_binding(binding)
        self.assertFalse(result_default.toxic_combination)

        # With custom set including roles/owner
        custom_toxic = frozenset({"roles/owner"})
        result_custom = score_iam_binding(binding, toxic_combinations=custom_toxic)
        self.assertTrue(result_custom.toxic_combination)


class TestClassifyChange(unittest.TestCase):
    def setUp(self):
        self.changes = load_audit_changes(FIXTURE)

    def _get(self, resource_suffix: str, action: str) -> Change:
        return next(
            c for c in self.changes
            if c.resource.endswith(resource_suffix) and c.action == action
        )

    def test_classify_world_open_update_broadened(self):
        # fixture change #1: sourceRanges widened to 0.0.0.0/0
        c = self._get("prod-allow-tcp-8080", "UPDATE")
        # There are two UPDATEs; get the one that widens to 0.0.0.0/0
        c = next(
            ch for ch in self.changes
            if ch.resource.endswith("prod-allow-tcp-8080")
            and ch.action == "UPDATE"
            and ch.after is not None
            and "0.0.0.0/0" in ch.after.get("sourceRanges", [])
        )
        self.assertEqual(classify_change(c), ChangeClass.BroadenedAccess)

    def test_classify_deny_delete_removed_protection(self):
        # fixture change #2: DELETE of deny rule
        c = self._get("prod-deny-all-egress", "DELETE")
        self.assertEqual(classify_change(c), ChangeClass.RemovedProtection)

    def test_classify_description_only_neutral(self):
        # fixture change #4: only description changed
        c = next(
            ch for ch in self.changes
            if ch.before == {"description": ""}
            and ch.after == {"description": "Updated description only"}
        )
        self.assertEqual(classify_change(c), ChangeClass.Neutral)

    def test_classify_empty_diff_other(self):
        """Empty before and after (both empty dicts) classifies as Other."""
        c = Change(
            resource="projects/test/global/firewalls/rule",
            resource_type="firewall_rule",
            action="UPDATE",
            before={},
            after={},
            timestamp=_ts("2025-01-01T00:00:00Z"),
            principal="user:test@example.com",
        )
        self.assertEqual(classify_change(c), ChangeClass.Other)
