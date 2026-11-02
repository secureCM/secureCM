"""Tests for prioritize.py and helpers.format_report."""
import json
import unittest
from datetime import datetime, timezone

from gcp_policy_analyzer.diff import Change
from gcp_policy_analyzer.prioritize import (
    BlastRadius,
    PrioritizedChange,
    compute_blast_radius,
    prioritize_changes,
)
from gcp_policy_analyzer.helpers import format_report


def _load_fixture():
    import os
    path = os.path.join(os.path.dirname(__file__), "..", "fixtures", "synthetic.json")
    with open(path) as f:
        import json
        return json.load(f)


def _world_open_change():
    """The BroadenedAccess firewall change from the fixture: 10.0.0.0/8 → 0.0.0.0/0, prod label."""
    return Change(
        resource="projects/example-prod-project/global/firewalls/prod-allow-tcp-8080",
        resource_type="firewall_rule",
        action="UPDATE",
        before={"sourceRanges": ["10.0.0.0/8"]},
        after={"sourceRanges": ["0.0.0.0/0"]},
        timestamp=datetime(2026, 10, 30, 16, 22, 41, tzinfo=timezone.utc),
        principal="terraform-deployer@example-prod-project.iam.gserviceaccount.com",
        risk_delta=5,
        labels={"env": "prod"},
    )


def _neutral_change():
    return Change(
        resource="projects/example-prod-project/global/firewalls/prod-allow-tcp-8080",
        resource_type="firewall_rule",
        action="UPDATE",
        before={"description": ""},
        after={"description": "Updated description only"},
        timestamp=datetime(2026, 10, 30, 11, 2, 10, tzinfo=timezone.utc),
        principal="alice@example.com",
        risk_delta=0,
        labels={},
    )


class TestBlastRadiusScoreFormula(unittest.TestCase):
    def test_blast_radius_score_formula(self):
        """14 resources on prod-network, external exposure, prod label → score 56."""
        ctx = _load_fixture()
        change = _world_open_change()
        br = compute_blast_radius(change, context=ctx)
        self.assertEqual(br.affected_resources, 14)
        self.assertTrue(br.external_exposure)
        self.assertTrue(br.production)
        self.assertEqual(br.score, 56)  # 14 * 2 * 2

    def test_blast_radius_no_context(self):
        """With no context, affected_resources defaults to 1."""
        change = _world_open_change()
        br = compute_blast_radius(change)
        self.assertEqual(br.affected_resources, 1)

    def test_blast_radius_no_matching_resources_floor_1(self):
        """When no resources match the change's network/project, affected_resources floors to 1."""
        ctx = _load_fixture()
        # IAM change with a project that has no matching resources
        change = Change(
            resource="projects/nonexistent-project",
            resource_type="iam_policy",
            action="UPDATE",
            before={"bindings": []},
            after={"bindings": [{"role": "roles/viewer", "members": ["user:alice@example.com"]}]},
            timestamp=datetime(2026, 10, 30, 16, 22, 41, tzinfo=timezone.utc),
            principal="terraform-deployer@example-prod-project.iam.gserviceaccount.com",
            risk_delta=1,
            labels={},
        )
        br = compute_blast_radius(change, context=ctx)
        # Even though no resources match, affected_resources must be at least 1
        self.assertEqual(br.affected_resources, 1)
        self.assertGreaterEqual(br.score, 1)


class TestPrioritizeOrdersAndRanks(unittest.TestCase):
    def test_prioritize_orders_and_ranks(self):
        """World-open rule ranks 1; Neutral/Other changes excluded."""
        ctx = _load_fixture()
        world_open = _world_open_change()
        neutral = _neutral_change()
        result = prioritize_changes([neutral, world_open], context=ctx)
        # Neutral excluded
        self.assertFalse(any(pc.change is neutral for pc in result))
        # world_open included and ranked 1
        self.assertTrue(any(pc.change is world_open for pc in result))
        top = result[0]
        self.assertEqual(top.rank, 1)
        self.assertIs(top.change, world_open)

    def test_prioritize_rank_sequence(self):
        """Ranks are sequential from 1."""
        ctx = _load_fixture()
        world_open = _world_open_change()
        # Add a second risky change with lower score
        second = Change(
            resource="projects/example-prod-project",
            resource_type="iam_policy",
            action="UPDATE",
            before={"bindings": []},
            after={"bindings": [{"role": "roles/owner", "members": ["serviceAccount:sa-demo@example-prod-project.iam.gserviceaccount.com"]}]},
            timestamp=datetime(2026, 10, 27, 9, 15, tzinfo=timezone.utc),
            principal="terraform-deployer@example-prod-project.iam.gserviceaccount.com",
            risk_delta=1,
            labels={},
        )
        result = prioritize_changes([second, world_open], context=ctx)
        ranks = [pc.rank for pc in result]
        self.assertEqual(ranks, list(range(1, len(ranks) + 1)))


class TestFormatReportIsRedacted(unittest.TestCase):
    def test_format_report_is_redacted(self):
        """format_report output must not contain original SA local-part (terraform-deployer)."""
        ctx = _load_fixture()
        world_open = _world_open_change()
        prioritized = prioritize_changes([world_open], context=ctx)
        report = format_report(prioritized)
        report_str = json.dumps(report)
        # Original email local-part must be gone; redact_sensitive replaces it with sa-{hash}
        self.assertNotIn("terraform-deployer@example-prod-project.iam.gserviceaccount.com", report_str)
        # Confirm SA email masking happened (sa- prefix present)
        self.assertIn("sa-", report_str)

    def test_format_report_structure(self):
        """format_report has required keys."""
        ctx = _load_fixture()
        world_open = _world_open_change()
        prioritized = prioritize_changes([world_open], context=ctx)
        report = format_report(prioritized)
        self.assertIn("summary", report)
        self.assertIn("prioritized", report)
        self.assertIn("stats", report)
        stats = report["stats"]
        for key in ("total_changes", "risky", "neutral", "principals"):
            self.assertIn(key, stats)

    def test_format_report_with_all_changes(self):
        """format_report with all_changes computes accurate stats including neutral count."""
        ctx = _load_fixture()
        world_open = _world_open_change()
        neutral = _neutral_change()
        all_changes = [world_open, neutral]
        prioritized = prioritize_changes(all_changes, context=ctx)
        report = format_report(prioritized, all_changes=all_changes)
        stats = report["stats"]
        # total_changes should include all (risky + neutral)
        self.assertEqual(stats["total_changes"], 2)
        # risky should only be the non-neutral changes
        self.assertEqual(stats["risky"], 1)
        # neutral count should reflect the excluded changes
        self.assertEqual(stats["neutral"], 1)
        # principals should come from all_changes
        self.assertEqual(len(stats["principals"]), 2)  # terraform-deployer and alice

    def test_format_report_legacy_behavior(self):
        """format_report without all_changes uses legacy behavior (neutral=0)."""
        ctx = _load_fixture()
        world_open = _world_open_change()
        prioritized = prioritize_changes([world_open], context=ctx)
        report = format_report(prioritized)  # No all_changes
        stats = report["stats"]
        self.assertEqual(stats["total_changes"], stats["risky"])
        self.assertEqual(stats["neutral"], 0)


if __name__ == "__main__":
    unittest.main()
